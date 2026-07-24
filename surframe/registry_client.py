# Copyright 2025 Christ10-8 — Apache-2.0
"""SURX Registry client (new in 0.3.0). Stdlib only: zero new deps.

seal_container_remote(): takes a container ALREADY signed locally and notarizes
it in the transparency log — the registry seal proves to third parties that THIS
state existed and was publicly anchored. The receipt is stored inside the
container (signatures/registry_seal.json, a region excluded from the local
digest, so the local signature stays valid).

check_seal(): triple verificacion —
  1. local:   the CURRENT content matches the sealed entries_root
  2. offline: the issuer Ed25519 signature over the seal payload
  3. online:  the registry confirms the seal and its link in the chain
Funciona sin red (informa registry="unreachable" y valida 1+2 igual).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional
from zipfile import ZipFile

from .crypto import _rewrite_zip_with_replacements
from .signing import SIG_PATH, _entry_hashes, _entries_root

RECEIPT_PATH = "signatures/registry_seal.json"
DEFAULT_REGISTRY = os.environ.get("SURX_REGISTRY", "https://api.surframe.dev")


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
    p = sig_doc["payload"]
    receipt = _post(f"{base}/v1/seal",
                    {"entries_root": p["entries_root"],
                     "entry_count": p["entry_count"],
                     "subject": {"signer": p.get("signer", ""),
                                 "public_key": p.get("public_key", ""),
                                 "name": os.path.basename(path)}},
                    {"X-API-Key": api_key})
    blob = json.dumps(receipt, ensure_ascii=False, indent=2).encode()
    with ZipFile(path, "r") as zf:
        exists = RECEIPT_PATH in zf.namelist()
    _rewrite_zip_with_replacements(path,
                                   replacements={RECEIPT_PATH: blob} if exists else {},
                                   additions={} if exists else {RECEIPT_PATH: blob})
    return receipt


def check_seal(path: str, registry_url: str = "") -> Dict[str, Any]:
    """Verify the seal: current content vs sealed, issuer signature, and registry."""
    with ZipFile(path, "r") as zf:
        if RECEIPT_PATH not in zf.namelist():
            return {"sealed": False, "valid": False,
                    "reason": "no receipt: the container was not sealed in the registry"}
        receipt = json.loads(zf.read(RECEIPT_PATH))
        current_root = _entries_root(_entry_hashes(zf))

    payload = receipt["payload"]
    local_match = current_root == payload["entries_root"]

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode()
    try:
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(receipt["issuer_public_key"])
        ).verify(bytes.fromhex(receipt["issuer_sig"]), canonical)
        issuer_ok = True
    except (InvalidSignature, ValueError, KeyError):
        issuer_ok = False

    base = (registry_url or DEFAULT_REGISTRY).rstrip("/")
    registry_state: Any = "unreachable"
    try:
        rep = _get(f"{base}/v1/verify/{receipt['seal_id']}")
        registry_state = "valid" if rep.get("valid") else "INVALID"
    except (urllib.error.URLError, OSError, ValueError):
        pass

    valid = local_match and issuer_ok and registry_state != "INVALID"
    reason = "ok" if valid else "; ".join(
        ([] if local_match else ["current content does NOT match the sealed state"])
        + ([] if issuer_ok else ["invalid issuer signature"])
        + ([] if registry_state != "INVALID" else ["the registry reports the seal as invalid"]))
    return {"sealed": True, "valid": valid, "reason": reason,
            "seal_id": receipt["seal_id"], "n": receipt.get("n"),
            "local_match": local_match, "issuer_sig_ok": issuer_ok,
            "registry": registry_state,
            "verify_url": receipt.get("verify_url", "")}
