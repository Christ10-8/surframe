# Copyright 2025-2026 Christ10-8 — Apache-2.0
"""SURX Registry client (transparency log). Stdlib only: zero new deps.

seal_container_remote(): takes a container ALREADY signed locally and notarizes
it in the transparency log — the registry seal proves to third parties that THIS
state existed and was publicly anchored. The receipt is stored inside the
container (signatures/registry_seal.json, a region excluded from the local
digest, so the local signature stays valid).

check_seal(): four bindings, all of which must hold —
  0. container: the local Ed25519 signature over the content verifies
  1. local:     the CURRENT content matches the sealed entries_root
  2. issuer:    the seal is signed by a TRUSTED issuer key (pinned or supplied,
                NEVER the copy that travels inside the artifact)
  3. registry:  the registry confirms the seal and its link in the chain

SECURITY NOTE (0.4.0). Until 0.3.5 step 2 verified receipt["issuer_sig"] against
receipt["issuer_public_key"] — a key read from the artifact under audit. Anyone
could generate a keypair, tamper the content, recompute the root, sign their own
receipt and get valid=True offline. The same class of bug as CVE-2026-22703 in
Cosign: a bundle verified while the log entry did not bind the artifact's digest,
signature or key. A trust anchor is not optional; it is the whole mechanism.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from zipfile import ZipFile, BadZipFile

from .crypto import _rewrite_zip_with_replacements
from .signing import (
    SIG_PATH, _entry_hashes, _entries_root, verify_container,
    ContainerLimitError,
)

RECEIPT_PATH = "signatures/registry_seal.json"
DEFAULT_REGISTRY = os.environ.get("SURX_REGISTRY", "https://api.surframe.dev")

# --- Trust anchor -----------------------------------------------------------
# The public key of the surframe.dev production registry, pinned at build time.
# This is the root of trust for `surx check-seal`: it is what makes an offline
# check meaningful. Verifying a receipt against a key carried inside the same
# receipt proves nothing at all.
#
# Override for a self-hosted registry:
#   surx check-seal f.surx --issuer-key <64-hex>
#   SURX_ISSUER_KEY=<64-hex>
# Rotation: publish the new key, ship a release that lists BOTH, drop the old
# one only after the overlap window. Never silently accept an unknown key.
PINNED_ISSUER_KEYS: Tuple[str, ...] = (
    "543659d1c2c8ede01062b201c375330cc728372a8b0b208979b43fdf197875bc",
)


def trusted_issuer_keys(explicit: Optional[str] = None) -> List[str]:
    """Trust anchors, in precedence order: explicit argument, env, pinned."""
    if explicit:
        return [explicit.strip().lower()]
    env = os.environ.get("SURX_ISSUER_KEY", "").strip().lower()
    if env:
        return [k for k in (x.strip() for x in env.split(",")) if k]
    return list(PINNED_ISSUER_KEYS)


def _post(url: str, body: dict, headers: Dict[str, str]) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def seal_container_remote(path: str, api_key: str,
                          registry_url: str = "") -> Dict[str, Any]:
    """Notarize a signed container. Requires a prior sign_container()."""
    base = (registry_url or DEFAULT_REGISTRY).rstrip("/")
    with ZipFile(path, "r") as zf:
        if SIG_PATH not in zf.namelist():
            raise ValueError("The container is not signed. Run sign_container()/surx sign first.")
        sig_doc = json.loads(zf.read(SIG_PATH))
    if not isinstance(sig_doc, dict) or not isinstance(sig_doc.get("payload"), dict):
        raise ValueError(f"Malformed {SIG_PATH}: cannot read the signed payload.")
    p = sig_doc["payload"]
    receipt = _post(f"{base}/v1/seal",
                    {"entries_root": p["entries_root"],
                     "entry_count": p["entry_count"],
                     "subject": {"signer": p.get("signer", ""),
                                 "public_key": p.get("public_key", ""),
                                 "name": os.path.basename(path)},
                     # Proof of possession (0.4.0): the container signature is
                     # itself a signature by subject.public_key over a payload
                     # committing to this entries_root. Sending it lets the
                     # registry verify authorship instead of taking our word.
                     "signature_doc": sig_doc},
                    {"X-API-Key": api_key})
    blob = json.dumps(receipt, ensure_ascii=False, indent=2).encode()
    with ZipFile(path, "r") as zf:
        exists = RECEIPT_PATH in zf.namelist()
    _rewrite_zip_with_replacements(path,
                                   replacements={RECEIPT_PATH: blob} if exists else {},
                                   additions={} if exists else {RECEIPT_PATH: blob})
    return receipt


def get_usage(api_key: str, registry_url: str = "") -> Dict[str, Any]:
    """Read the monthly quota for an API key. Does not consume anything."""
    base = (registry_url or DEFAULT_REGISTRY).rstrip("/")
    req = urllib.request.Request(f"{base}/v1/usage", headers={"X-API-Key": api_key})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _bad(reason: str, **extra: Any) -> Dict[str, Any]:
    out = {"sealed": True, "valid": False, "reason": reason,
           "container_sig_ok": False, "local_match": False,
           "issuer_sig_ok": False, "issuer_trusted": False,
           "signer_bound": False, "registry": "unchecked"}
    out.update(extra)
    return out


def check_seal(path: str, registry_url: str = "", *,
               issuer_key: Optional[str] = None,
               pubkey: Optional[str] = None,
               allow_unattested_appends: bool = False) -> Dict[str, Any]:
    """Verify the seal. valid=True requires ALL of:

      * the container's own Ed25519 signature verifies (and its audit log is
        clean) — a seal over a container that fails verify_container() is not
        evidence of anything;
      * the current content reproduces the sealed entries_root;
      * the receipt is signed by a TRUSTED issuer key (see PINNED_ISSUER_KEYS);
      * the receipt's subject.public_key is the key that actually signed this
        container — otherwise the seal belongs to somebody else's artifact;
      * the registry does not contradict it (a reachable registry answering
        "not found" or "invalid" fails closed; only a genuine network failure
        degrades to "unreachable").

    pubkey: the container signer's key, for identity (as in `surx verify
    --pubkey`). Without it the content is verified but the signer is
    self-attested and `signer_trusted` is False.
    """
    # ---- 0. read the receipt ------------------------------------------------
    try:
        with ZipFile(path, "r") as zf:
            names = zf.namelist()
            if RECEIPT_PATH not in names:
                return {"sealed": False, "valid": False,
                        "reason": "no receipt: the container was not sealed in the registry"}
            receipt = json.loads(zf.read(RECEIPT_PATH))
            container_key = ""
            if SIG_PATH in names:
                sig_doc = json.loads(zf.read(SIG_PATH))
                if isinstance(sig_doc, dict) and isinstance(sig_doc.get("payload"), dict):
                    container_key = str(sig_doc["payload"].get("public_key", "")).lower()
            current_root = _entries_root(_entry_hashes(zf))
    except ContainerLimitError as exc:
        return _bad(f"refused: {exc}")
    except (BadZipFile, OSError, EOFError, json.JSONDecodeError) as exc:
        return _bad(f"container unreadable: {type(exc).__name__}: {exc}")

    if not isinstance(receipt, dict) or not isinstance(receipt.get("payload"), dict):
        return _bad("malformed receipt: expected {payload: object, issuer_sig: string, "
                    "seal_id: string} in " + RECEIPT_PATH)
    payload = receipt["payload"]
    seal_id = str(receipt.get("seal_id") or payload.get("seal_id") or "")
    issuer_sig = receipt.get("issuer_sig")
    if not isinstance(issuer_sig, str) or not seal_id:
        return _bad(f"malformed receipt: missing issuer_sig or seal_id in {RECEIPT_PATH}",
                    seal_id=seal_id)

    result: Dict[str, Any] = {
        "sealed": True, "valid": False, "reason": "", "seal_id": seal_id,
        "n": receipt.get("n") or payload.get("n"),
        "container_sig_ok": False, "local_match": False,
        "issuer_sig_ok": False, "issuer_trusted": False, "signer_bound": False,
        "signer_trusted": pubkey is not None, "registry": "unchecked",
        "verify_url": receipt.get("verify_url", ""),
    }
    fail: List[str] = []

    # ---- 1. the container itself must verify --------------------------------
    creport = verify_container(path, pubkey,
                               allow_unattested_appends=allow_unattested_appends)
    result["container_sig_ok"] = bool(creport.get("valid"))
    result["container_reason"] = creport.get("reason")
    result["signer"] = creport.get("signer")
    if not result["container_sig_ok"]:
        fail.append(f"the container does not verify ({creport.get('reason')})")

    # ---- 2. content vs sealed state ----------------------------------------
    sealed_root = str(payload.get("entries_root", ""))
    result["local_match"] = bool(sealed_root) and current_root == sealed_root
    if not result["local_match"]:
        fail.append("current content does NOT match the sealed state")

    # ---- 3. issuer signature against a TRUSTED anchor ----------------------
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    anchors = trusted_issuer_keys(issuer_key)
    claimed = str(payload.get("issuer_public_key", "")).lower()
    result["issuer_trusted"] = claimed in anchors
    if not result["issuer_trusted"]:
        fail.append("untrusted issuer key: the seal was issued by "
                    f"{(claimed or '(none)')[:16]}…, which is not a trust anchor "
                    "(use --issuer-key for a self-hosted registry)")
    else:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode()
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(claimed)) \
                .verify(bytes.fromhex(issuer_sig), canonical)
            result["issuer_sig_ok"] = True
        except (InvalidSignature, ValueError, TypeError):
            fail.append("invalid issuer signature over the seal payload")

    # ---- 4. the seal must be ABOUT this container's signer ------------------
    subject = payload.get("subject") if isinstance(payload.get("subject"), dict) else {}
    sealed_key = str(subject.get("public_key", "")).lower()
    result["signer_bound"] = bool(container_key) and sealed_key == container_key
    if not result["signer_bound"]:
        fail.append("the seal is not bound to this container's signing key "
                    f"(sealed {(sealed_key or '(none)')[:16]}… vs "
                    f"container {(container_key or '(none)')[:16]}…)")

    # ---- 5. the registry gets the last word --------------------------------
    base = (registry_url or DEFAULT_REGISTRY).rstrip("/")
    try:
        rep = _get(f"{base}/v1/verify/{seal_id}")
        result["registry"] = "valid" if rep.get("valid") else "INVALID"
        if result["registry"] == "INVALID":
            fail.append("the registry reports the seal as invalid")
    except urllib.error.HTTPError as exc:
        # HTTPError IS a subclass of URLError. Catching URLError first swallowed
        # every 404/500 and reported it as "unreachable", which kept valid=True.
        # A server that ANSWERED is authoritative: fail closed.
        result["registry"] = f"HTTP {exc.code}"
        fail.append(f"the registry answered HTTP {exc.code} for seal {seal_id} "
                    "(the seal is not in the log)")
    except (urllib.error.URLError, OSError, TimeoutError):
        result["registry"] = "unreachable"       # genuine offline: 1-4 still hold
    except (ValueError, json.JSONDecodeError):
        result["registry"] = "unparseable"
        fail.append("the registry returned a response that is not valid JSON")

    result["valid"] = not fail
    result["reason"] = "ok" if not fail else "; ".join(fail)
    return result
