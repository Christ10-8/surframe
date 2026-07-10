# Copyright 2025 Christ10-8 — Apache-2.0
"""Cliente del SURX Registry (nuevo en 0.3.0). Solo stdlib: cero deps nuevas.

seal_container_remote(): toma un contenedor YA firmado localmente y lo notariza
en el transparency log — el sello del registro prueba ante terceros que ESTE
estado existio y quedo anclado publicamente. El recibo se guarda dentro del
contenedor (signatures/registry_seal.json, zona excluida del digest local, asi
que la firma local sigue valida).

check_seal(): triple verificacion —
  1. local:   el contenido ACTUAL coincide con el entries_root sellado
  2. offline: la firma Ed25519 del emisor sobre el payload del sello
  3. online:  el registro confirma el sello y su eslabon en la cadena
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
DEFAULT_REGISTRY = os.environ.get("SURX_REGISTRY", "http://localhost:8000")


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
    """Notariza un contenedor firmado. Requiere sign_container() previo."""
    base = (registry_url or DEFAULT_REGISTRY).rstrip("/")
    with ZipFile(path, "r") as zf:
        if SIG_PATH not in zf.namelist():
            raise ValueError("El contenedor no esta firmado. Corre sign_container()/surx sign primero.")
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
    """Verifica el sello: contenido actual vs sellado, firma del emisor, y registro."""
    with ZipFile(path, "r") as zf:
        if RECEIPT_PATH not in zf.namelist():
            return {"sealed": False, "valid": False,
                    "reason": "sin recibo: el contenedor no fue sellado en el registro"}
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
        ([] if local_match else ["el contenido actual NO coincide con el estado sellado"])
        + ([] if issuer_ok else ["firma del emisor invalida"])
        + ([] if registry_state != "INVALID" else ["el registro reporta el sello como invalido"]))
    return {"sealed": True, "valid": valid, "reason": reason,
            "seal_id": receipt["seal_id"], "n": receipt.get("n"),
            "local_match": local_match, "issuer_sig_ok": issuer_ok,
            "registry": registry_state,
            "verify_url": receipt.get("verify_url", "")}
