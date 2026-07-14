# Copyright 2025 Christ10-8
# Licensed under the Apache License, Version 2.0
# -*- coding: utf-8 -*-
"""
Firma Ed25519 de contenedores SURX (nuevo en 0.2.0).

Que firma:
- Un digest deterministico (Merkle-plano SHA-256) sobre TODAS las entradas del
  zip, ordenadas, EXCEPTO regiones mutables:
    * signatures/        (la firma no se firma a si misma)
    * profiles/audit/    (append-only: se ancla via chain-heads, no via digest)
    * profiles/usage*    (KPIs que mutan en cada lectura)
- Los chain-heads del log de auditoria AL MOMENTO de firmar. verify() valida
  que la cadena actual sea consistente y que el head firmado sea un ANCESTRO
  de la cadena actual: la auditoria solo pudo crecer, nunca editarse.

Que garantiza verify_container():
- valid=True  -> ninguna entrada firmada cambio, la firma corresponde a la
                 clave publica dada, y la auditoria solo agrego eventos.
- valid=False -> reporta exactamente QUE entradas cambiaron/faltan/sobran,
                 o donde se rompio la cadena de auditoria.

La "firma" de 0.1.5 era un hash-chain sin clave: cualquiera con acceso de
escritura podia reescribir la cadena completa. Ed25519 cierra eso: sin la
clave privada no se puede producir una firma valida sobre contenido alterado.
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


# -------------------- claves --------------------

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
    """Guarda la clave privada en PEM (PKCS8). Con passphrase queda cifrada at-rest."""
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
        raise ValueError("La clave del PEM no es Ed25519.")
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
        raise ValueError("La clave del PEM no es Ed25519.")
    return pub.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw).hex()


# -------------------- digest del contenedor --------------------

def _validate_zip_structure(names: List[str]) -> List[str]:
    """(0.3.0) Rechaza estructuras de zip ambiguas o peligrosas.
    Entradas DUPLICADAS son un ataque clasico: distintos parsers leen distinta
    copia, asi que una firma podria validar contenido que otro lector no ve.
    Tambien: paths absolutos, '..' y backslashes (zip-slip)."""
    problems: List[str] = []
    from collections import Counter
    for name, c in Counter(names).items():
        if c > 1:
            problems.append(f"entrada duplicada x{c}: {name}")
    for name in names:
        if name.startswith("/") or "\\" in name or ".." in name.split("/"):
            problems.append(f"nombre inseguro: {name}")
    return problems


def _entry_hashes(zf: ZipFile) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name in zf.namelist():
        if _is_signed_entry(name):
            out[name] = hashlib.sha256(zf.read(name)).hexdigest()
    return out


def _entries_root(entry_hashes: Dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(entry_hashes):
        h.update(hashlib.sha256(name.encode("utf-8")).digest())
        h.update(bytes.fromhex(entry_hashes[name]))
    return h.hexdigest()


# -------------------- cadena de auditoria: heads --------------------

def _audit_files(zf: ZipFile) -> List[str]:
    return sorted(n for n in zf.namelist()
                  if n.startswith(AUDIT_PREFIX) and n.endswith(".jsonl"))


def _chain_walk(raw: bytes) -> Tuple[List[str], bool, Optional[int]]:
    """Recorre un JSONL encadenado. Devuelve (hashes_de_linea, consistente, primera_linea_mala)."""
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


# -------------------- firmar / verificar --------------------

def sign_container(path: str, private_key_hex: str, *, signer: Optional[str] = None) -> Dict[str, Any]:
    """Firma el contenedor y guarda signatures/ed25519.json adentro. Devuelve el payload firmado."""
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    with ZipFile(path, "r") as zf:
        problems = _validate_zip_structure(zf.namelist())
        if problems:
            raise ValueError("Estructura de zip insegura, no se firma: " + "; ".join(problems))
        eh = _entry_hashes(zf)
        heads = _audit_heads(zf)
        if any(v == "!inconsistent" for v in heads.values()):
            raise ValueError("La cadena de auditoria ya es inconsistente: no se firma un estado corrupto.")

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


def verify_container(path: str, public_key_hex: Optional[str] = None) -> Dict[str, Any]:
    """Verifica firma + integridad. Sin public_key_hex usa la embebida (self-attested)."""
    report: Dict[str, Any] = {
        "valid": False, "reason": None, "signer": None, "signed_at": None,
        "trusted_key": public_key_hex is not None,
        "modified": [], "missing": [], "added": [],
        "audit": {"consistent": None, "append_only": None, "detail": {}},
    }
    # Un contenedor corrupto a nivel fisico (directorio central roto, stream
    # deflate con un byte volteado, CRC malo, truncado) NO debe crashear con un
    # traceback de zipfile/zlib: es simplemente otra forma de "invalido". Lo
    # envolvemos y devolvemos un reporte limpio, igual que el resto de fallas.
    try:
        with ZipFile(path, "r") as zf:
            names = zf.namelist()
            problems = _validate_zip_structure(names)
            if problems:
                report["reason"] = "estructura de zip insegura: " + "; ".join(problems)
                return report
            if SIG_PATH not in names:
                report["reason"] = "unsigned: no existe signatures/ed25519.json"
                return report
            doc = json.loads(zf.read(SIG_PATH))
            payload = doc.get("payload", {})
            sig_hex = doc.get("signature", "")
            report["signer"] = payload.get("signer")
            report["signed_at"] = payload.get("signed_at")

            # 1) firma criptografica sobre el payload
            pub_hex = public_key_hex or payload.get("public_key", "")
            try:
                pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
                payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                           separators=(",", ":")).encode("utf-8")
                pub.verify(bytes.fromhex(sig_hex), payload_bytes)
            except (InvalidSignature, ValueError):
                report["reason"] = ("firma invalida: el payload no corresponde a la clave "
                                    + ("provista" if public_key_hex else "embebida"))
                return report

            # 2) diff de entradas firmadas vs estado actual
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

            # 3) auditoria: consistente Y append-only respecto del head firmado
            signed_heads: Dict[str, str] = payload.get("audit_heads", {})
            audit_ok = True
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
                            det["status"] = "new_file_after_signing"
                        elif sh == GENESIS or sh in hashes:
                            det["status"] = "append_only_ok"
                        else:
                            det["status"] = "history_rewritten"
                            audit_ok = False
                report["audit"]["detail"][fname] = det
            report["audit"]["consistent"] = audit_ok
            report["audit"]["append_only"] = audit_ok
    except (BadZipFile, zlib.error, OSError, EOFError, json.JSONDecodeError) as exc:
        report["reason"] = f"container unreadable: {type(exc).__name__}: {exc}"
        return report

    report["valid"] = bool(entries_ok and audit_ok)
    if not report["valid"] and report["reason"] is None:
        parts = []
        if report["modified"]:
            parts.append(f"{len(report['modified'])} entrada(s) modificada(s)")
        if report["missing"]:
            parts.append(f"{len(report['missing'])} faltante(s)")
        if report["added"]:
            parts.append(f"{len(report['added'])} agregada(s) sin firmar")
        if not audit_ok:
            parts.append("auditoria alterada")
        report["reason"] = "tampering detectado: " + ", ".join(parts)
    elif report["valid"]:
        report["reason"] = "ok"
    return report
