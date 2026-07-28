# Copyright 2025 Christ10-8
# Licensed under the Apache License, Version 2.0
# -*- coding: utf-8 -*-
"""
Ed25519 signing for SURX containers (new in 0.2.0).

What it signs:
- A deterministic digest (flat Merkle SHA-256) over ALL zip entries, sorted,
  EXCEPT mutable regions:
    * signatures/        (the signature does not sign itself)
    * profiles/audit/    (append-only: anchored via chain-heads, not the digest)
    * profiles/usage*    (KPIs that mutate on every read)
- The audit-log chain-heads AT SIGNING TIME. verify() checks the current chain
  is consistent and that the signed head is an ANCESTOR of the current chain:
  the audit log could only grow, never be edited.

What verify_container() guarantees:
- valid=True  -> no signed entry changed, the signature matches the given public
                 key, and the audit log only appended events.
- valid=False -> reports exactly WHICH entries changed/are missing/were added,
                 or where the audit chain broke.

The 0.1.5 "signature" was an unkeyed hash-chain: anyone with write access could
rewrite the whole chain. Ed25519 closes that: without the private key you cannot
produce a valid signature over altered content.
"""
from __future__ import annotations

import hashlib
import json
import os
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from zipfile import ZipFile, BadZipFile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from .crypto import _rewrite_zip_with_replacements

SIG_PATH = "signatures/ed25519.json"
AUDIT_PREFIX = "profiles/audit/"
EXCLUDE_PREFIXES: Tuple[str, ...] = ("signatures/", AUDIT_PREFIX)
EXCLUDE_EXACT: Tuple[str, ...] = ("profiles/usage.json",)
EXCLUDE_PREFIX_USAGE = "profiles/usage/"
GENESIS = "0" * 64

# --- Resource limits (0.4.0) -------------------------------------------------
# A verifier is an attacker-facing surface: it runs on untrusted input, in CI and
# in a hosted service. _entry_hashes() used to zf.read() whole entries into RAM,
# so a 260 KB container with a 1000x ratio made the verifier allocate 256 MB.
# We hash in a stream, cap the absolute size, and cap the ratio.
HASH_CHUNK = 1 << 20                     # 1 MiB
MAX_ENTRY_BYTES = int(os.environ.get("SURX_MAX_ENTRY_BYTES", 2 * 1024**3))   # 2 GiB
MAX_TOTAL_BYTES = int(os.environ.get("SURX_MAX_TOTAL_BYTES", 8 * 1024**3))  # 8 GiB
MAX_RATIO = float(os.environ.get("SURX_MAX_RATIO", 200))                    # x


class ContainerLimitError(Exception):
    """Declared or actual size exceeds a verifier resource limit."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_signed_entry(name: str) -> bool:
    if name.endswith("/"):
        return False
    if any(name.startswith(p) for p in EXCLUDE_PREFIXES):
        return False
    if name.startswith(EXCLUDE_PREFIX_USAGE) or name in EXCLUDE_EXACT:
        return False
    return True


# -------------------- keys --------------------

@dataclass
class KeyPair:
    private_hex: str
    public_hex: str


def generate_keypair() -> KeyPair:
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return KeyPair(private_hex=priv_raw.hex(), public_hex=pub_raw.hex())


def save_private_key(kp_or_hex, path: str, passphrase: Optional[str] = None) -> None:
    """Save the private key as PEM (PKCS8). With a passphrase it is encrypted at rest."""
    priv_hex = kp_or_hex.private_hex if isinstance(kp_or_hex, KeyPair) else str(kp_or_hex)
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    enc = (serialization.BestAvailableEncryption(passphrase.encode())
           if passphrase else serialization.NoEncryption())
    pem = priv.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, enc)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
        f.flush()
        os.fsync(f.fileno())


def load_private_key(path: str, passphrase: Optional[str] = None) -> str:
    with open(path, "rb") as f:
        priv = serialization.load_pem_private_key(
            f.read(), password=passphrase.encode() if passphrase else None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("The PEM key is not Ed25519.")
    raw = priv.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    return raw.hex()


def save_public_key(kp_or_hex, path: str) -> None:
    pub_hex = kp_or_hex.public_hex if isinstance(kp_or_hex, KeyPair) else str(kp_or_hex)
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(path, "wb") as f:
        f.write(pem)


def load_public_key(path: str) -> str:
    with open(path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("The PEM key is not Ed25519.")
    return pub.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw).hex()


# -------------------- container digest --------------------

def _validate_zip_structure(names: List[str]) -> List[str]:
    """(0.3.0) Rechaza estructuras de zip ambiguas o peligrosas.
    Entradas DUPLICADAS son un ataque clasico: distintos parsers leen distinta
    copia, asi que una firma podria validar contenido que otro lector no ve.
    Tambien: paths absolutos, '..' y backslashes (zip-slip)."""
    problems: List[str] = []
    from collections import Counter
    for name, c in Counter(names).items():
        if c > 1:
            problems.append(f"duplicate entry x{c}: {name}")
    for name in names:
        if name.startswith("/") or "\\" in name or ".." in name.split("/"):
            problems.append(f"unsafe name: {name}")
    return problems


def _validate_zip_envelope(zf: ZipFile) -> List[str]:
    """(0.4.0) The digest covers ENTRY CONTENT, not the raw file. That left three
    unsigned channels that changed sha256(file) while verify said "valid":

      * data PREPENDED before the first local header (polyglot / parser
        confusion: some readers see the prefix, zipfile skips it),
      * data APPENDED after the end-of-central-directory record,
      * the zip archive COMMENT (a free-form unsigned field).

    A container is a signed artifact, so it must be byte-exact: exactly one zip,
    starting at offset 0, ending at the EOCD, no comment. Anything else is
    ambiguity and we refuse it instead of blessing it.
    """
    problems: List[str] = []
    infos = zf.infolist()

    if zf.comment:
        problems.append(f"unsigned zip comment present ({len(zf.comment)} bytes)")

    if infos:
        first = min(i.header_offset for i in infos)
        if first != 0:
            problems.append(f"{first} bytes prepended before the first zip entry")

    # The EOCD must be the last record in the file.
    fp = getattr(zf, "fp", None)
    try:
        if fp is not None and fp.seekable():
            here = fp.tell()
            fp.seek(0, os.SEEK_END)
            total = fp.tell()
            want = total - 22 - len(zf.comment or b"")
            if want >= 0:
                fp.seek(want)
                if fp.read(4) != b"PK\x05\x06":
                    problems.append("trailing bytes after the end-of-central-directory record")
            fp.seek(here)
    except (OSError, ValueError):
        pass

    # Declared sizes: refuse the bomb before allocating anything for it.
    total_declared = 0
    for i in infos:
        if not _is_signed_entry(i.filename):
            continue
        total_declared += i.file_size
        if i.file_size > MAX_ENTRY_BYTES:
            problems.append(
                f"entry exceeds size limit: {i.filename} declares {i.file_size} bytes "
                f"(limit {MAX_ENTRY_BYTES}; raise SURX_MAX_ENTRY_BYTES to allow)")
        if i.compress_size > 0:
            ratio = i.file_size / i.compress_size
            if ratio > MAX_RATIO:
                problems.append(
                    f"compression ratio limit exceeded: {i.filename} is {ratio:.0f}x "
                    f"({i.compress_size} -> {i.file_size} bytes, limit {MAX_RATIO:.0f}x; "
                    f"raise SURX_MAX_RATIO to allow)")
    if total_declared > MAX_TOTAL_BYTES:
        problems.append(
            f"container exceeds total size limit: {total_declared} bytes "
            f"(limit {MAX_TOTAL_BYTES}; raise SURX_MAX_TOTAL_BYTES to allow)")
    return problems


def _sha256_stream(zf: ZipFile, name: str, info) -> str:
    """Hash one entry WITHOUT loading it whole into RAM, enforcing the caps as we
    read (the declared file_size in the header is attacker-controlled, so the
    real decompressed length is checked too)."""
    h = hashlib.sha256()
    read = 0
    limit = min(MAX_ENTRY_BYTES, max(int(info.compress_size * MAX_RATIO), HASH_CHUNK))
    with zf.open(name, "r") as fh:
        while True:
            chunk = fh.read(HASH_CHUNK)
            if not chunk:
                break
            read += len(chunk)
            if read > limit:
                raise ContainerLimitError(
                    f"compression ratio limit exceeded while reading {name}: "
                    f"decompressed past {limit} bytes from {info.compress_size} "
                    f"compressed (limit {MAX_RATIO:.0f}x)")
            h.update(chunk)
    return h.hexdigest()


def _entry_hashes(zf: ZipFile) -> Dict[str, str]:
    out: Dict[str, str] = {}
    total = 0
    for info in zf.infolist():
        name = info.filename
        if not _is_signed_entry(name):
            continue
        out[name] = _sha256_stream(zf, name, info)
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise ContainerLimitError(
                f"container exceeds total size limit ({MAX_TOTAL_BYTES} bytes)")
    return out


def _entries_root(entry_hashes: Dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(entry_hashes):
        h.update(hashlib.sha256(name.encode("utf-8")).digest())
        h.update(bytes.fromhex(entry_hashes[name]))
    return h.hexdigest()


# -------------------- audit chain: heads --------------------

def _audit_files(zf: ZipFile) -> List[str]:
    return sorted(n for n in zf.namelist()
                  if n.startswith(AUDIT_PREFIX) and n.endswith(".jsonl"))


def _chain_walk(raw: bytes) -> Tuple[List[str], bool, Optional[int]]:
    """Walk a hash-chained JSONL. Returns (line_hashes, consistent, first_bad_line)."""
    running_hashes: List[str] = []
    prev = GENESIS
    lines = [ln for ln in raw.split(b"\n") if ln.strip()]
    for i, ln in enumerate(lines, start=1):
        try:
            evt = json.loads(ln)
        except Exception:
            return running_hashes, False, i
        if "sha256" in evt and "prev_sha256" in evt:
            if evt["prev_sha256"] != prev:
                return running_hashes, False, i
            base = {k: v for k, v in evt.items() if k != "sha256"}
            payload = json.dumps(base, ensure_ascii=False,
                                 separators=(",", ":")).encode("utf-8")
            if hashlib.sha256(payload).hexdigest() != evt["sha256"]:
                return running_hashes, False, i
        # el eslabon fisico es sha256 de la LINEA cruda (asi encadena audit.py)
        prev = hashlib.sha256(ln).hexdigest()
        running_hashes.append(prev)
    return running_hashes, True, None


def _audit_heads(zf: ZipFile) -> Dict[str, str]:
    heads: Dict[str, str] = {}
    for name in _audit_files(zf):
        hashes, ok, _ = _chain_walk(zf.read(name))
        heads[name] = hashes[-1] if hashes else GENESIS
        if not ok:
            heads[name] = "!inconsistent"
    return heads


# -------------------- sign / verify --------------------

def sign_container(path: str, private_key_hex: str, *, signer: Optional[str] = None) -> Dict[str, Any]:
    """Sign the container and store signatures/ed25519.json inside. Returns the signed payload."""
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    with ZipFile(path, "r") as zf:
        problems = (_validate_zip_structure(zf.namelist())
                    + _validate_zip_envelope(zf))
        if problems:
            raise ValueError("Unsafe zip structure, refusing to sign: " + "; ".join(problems))
        eh = _entry_hashes(zf)
        heads = _audit_heads(zf)
        if any(v == "!inconsistent" for v in heads.values()):
            raise ValueError("The audit chain is already inconsistent: refusing to sign a corrupt state.")

    payload = {
        "v": 1,
        "alg": "Ed25519",
        "entries_root": _entries_root(eh),
        "entry_count": len(eh),
        "entries": eh,                     # permite diff exacto en verify
        "audit_heads": heads,
        "signer": signer or os.environ.get("SURX_USER") or "unknown",
        "signed_at": _now_iso(),
        "public_key": pub_hex,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
    sig = priv.sign(payload_bytes).hex()
    doc = {"payload": payload, "signature": sig}
    blob = json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")

    with ZipFile(path, "r") as zf:
        exists = SIG_PATH in zf.namelist()
    _rewrite_zip_with_replacements(
        path,
        replacements={SIG_PATH: blob} if exists else {},
        additions={} if exists else {SIG_PATH: blob},
    )
    return payload


def verify_container(path: str, public_key_hex: Optional[str] = None, *,
                     allow_unattested_appends: bool = False) -> Dict[str, Any]:
    """Verify signature + integrity. Without public_key_hex, uses the embedded one (self-attested).

    allow_unattested_appends: the audit log is EXCLUDED from the signed digest so
    it can grow after signing. That means events appended after the signature are
    chain-consistent but NOT authenticated — anyone with write access can forge
    them. Since 0.4.0 that makes the container invalid by default; pass True (or
    `surx verify --allow-appends`) to accept a container whose only difference
    from the signed state is appended audit events.
    """
    report: Dict[str, Any] = {
        "valid": False, "reason": None, "signer": None, "signed_at": None,
        "trusted_key": public_key_hex is not None,
        "modified": [], "missing": [], "added": [],
        "audit": {"consistent": None, "append_only": None,
                  "unattested_appends": 0, "detail": {}},
    }
    # A physically corrupt container (broken central directory, deflate stream
    # with a flipped byte, bad CRC, truncated) must NOT crash with a raw
    # traceback from zipfile/zlib: it is just another form of "invalid". So
    # we wrap it and return a clean report, like every other failure.
    try:
        with ZipFile(path, "r") as zf:
            names = zf.namelist()
            problems = _validate_zip_structure(names) + _validate_zip_envelope(zf)
            if problems:
                report["reason"] = "unsafe zip structure: " + "; ".join(problems)
                return report
            if SIG_PATH not in names:
                report["reason"] = "unsigned: missing signatures/ed25519.json"
                return report
            doc = json.loads(zf.read(SIG_PATH))
            # A malformed signature document is just another form of "invalid".
            # It must NOT surface as AttributeError/KeyError from deep inside:
            # the docstring of this module promises a clean report.
            if not isinstance(doc, dict) or not isinstance(doc.get("payload"), dict) \
                    or not isinstance(doc.get("signature"), str):
                report["reason"] = ("malformed signature document: expected "
                                    "{payload: object, signature: string} in " + SIG_PATH)
                return report
            payload = doc["payload"]
            sig_hex = doc["signature"]
            report["signer"] = payload.get("signer")
            report["signed_at"] = payload.get("signed_at")

            # 1) cryptographic signature over the payload
            pub_hex = public_key_hex or payload.get("public_key", "")
            try:
                pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
                payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                           separators=(",", ":")).encode("utf-8")
                pub.verify(bytes.fromhex(sig_hex), payload_bytes)
            except (InvalidSignature, ValueError):
                report["reason"] = ("invalid signature: payload does not match the "
                                    + ("provided key" if public_key_hex else "embedded key"))
                return report

            # 2) diff signed entries vs current state
            signed_entries: Dict[str, str] = payload.get("entries", {})
            current = _entry_hashes(zf)
            report["missing"] = sorted(set(signed_entries) - set(current))
            report["added"] = sorted(set(current) - set(signed_entries))
            report["modified"] = sorted(
                n for n in set(signed_entries) & set(current)
                if signed_entries[n] != current[n]
            )
            entries_ok = (not report["missing"] and not report["added"]
                          and not report["modified"]
                          and _entries_root(current) == payload.get("entries_root"))

            # 3) audit: consistent AND append-only relative to the signed head
            signed_heads: Dict[str, str] = payload.get("audit_heads", {})
            if not isinstance(signed_heads, dict):
                signed_heads = {}
            audit_ok = True
            unattested = 0
            for fname in sorted(set(_audit_files(zf)) | set(signed_heads)):
                det: Dict[str, Any] = {}
                if fname not in names:
                    det = {"status": "missing", "signed_head": signed_heads.get(fname)}
                    audit_ok = False
                else:
                    hashes, ok, bad = _chain_walk(zf.read(fname))
                    det["events"] = len(hashes)
                    if not ok:
                        det["status"] = f"chain_broken_at_line_{bad}"
                        audit_ok = False
                    else:
                        sh = signed_heads.get(fname)
                        if sh is None:
                            # An audit FILE that did not exist at signing time is
                            # 100% unauthenticated content. It used to be reported
                            # and then ignored, which is how "export by
                            # auditor@bigfour.com" could be injected into a
                            # container that still verified as valid.
                            #
                            # It is NOT hard-failed, though: a legitimate reader
                            # appending on a later date creates exactly this, so
                            # hard-failing would make any read of a signed
                            # container invalid with no way out. It counts as
                            # unattested and is governed by the same flag as any
                            # other post-signing event — default closed, explicit
                            # opt-in to accept.
                            det["status"] = "new_file_after_signing"
                            det["unattested"] = len(hashes)
                            unattested += len(hashes)
                        elif sh == GENESIS:
                            det["status"] = "append_only_ok"
                            det["unattested"] = len(hashes)
                            unattested += len(hashes)
                        elif sh in hashes:
                            det["status"] = "append_only_ok"
                            n_after = len(hashes) - (hashes.index(sh) + 1)
                            det["unattested"] = n_after
                            unattested += n_after
                        else:
                            det["status"] = "history_rewritten"
                            audit_ok = False
                report["audit"]["detail"][fname] = det
            report["audit"]["consistent"] = audit_ok
            report["audit"]["append_only"] = audit_ok
            report["audit"]["unattested_appends"] = unattested
            # The chain is an UNKEYED SHA-256: continuing it needs no key, so
            # post-signing events prove only "someone with write access added
            # this". They are not evidence. Fail closed unless asked otherwise.
            if unattested and not allow_unattested_appends:
                audit_ok = False
    except ContainerLimitError as exc:
        report["reason"] = f"refused: {exc}"
        return report
    except (BadZipFile, zlib.error, OSError, EOFError, json.JSONDecodeError,
            AttributeError, KeyError, TypeError, IndexError) as exc:
        report["reason"] = f"container unreadable: {type(exc).__name__}: {exc}"
        return report

    report["valid"] = bool(entries_ok and audit_ok)
    if not report["valid"] and report["reason"] is None:
        parts = []
        if report["modified"]:
            parts.append(f"{len(report['modified'])} modified entr" + ("y" if len(report['modified'])==1 else "ies"))
        if report["missing"]:
            parts.append(f"{len(report['missing'])} missing entr" + ("y" if len(report['missing'])==1 else "ies"))
        if report["added"]:
            parts.append(f"{len(report['added'])} unsigned addition" + ("" if len(report['added'])==1 else "s"))
        det = report["audit"]["detail"]
        n_new = sum(1 for d in det.values() if d.get("status") == "new_file_after_signing")
        if report["audit"]["unattested_appends"] and not allow_unattested_appends:
            msg = (f"{report['audit']['unattested_appends']} audit event(s) appended after "
                   "signing are NOT authenticated")
            if n_new:
                msg += f" ({n_new} in audit file(s) created after signing)"
            parts.append(msg + " (pass --allow-appends to accept)")
        if not audit_ok and not parts:
            parts.append("audit log altered")
        report["reason"] = "tampering detected: " + ", ".join(parts)
    elif report["valid"]:
        report["reason"] = "ok"
    return report
