# Copyright 2025 Christ10-8 — Apache-2.0
"""SURX Registry client (transparency log). New in 0.3.0.

seal_with_registry(): pide un sello notarizado sobre el estado actual del
container and stores the receipt inside (signatures/registry_seal.json, a region
excluida del digest firmado, asi el sello no invalida la firma local).

verify_registry_seal(): does NOT trust the receipt — recomputes the entries_root
locally, fetches the seal from the registry, and verifies the issuer Ed25519 signature
sobre el payload completo. Solo stdlib (urllib): cero dependencias nuevas.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, Optional
from zipfile import ZipFile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import _rewrite_zip_with_replacements
from .signing import SIG_PATH, _entries_root, _entry_hashes

RECEIPT_PATH = "signatures/registry_seal.json"
DEFAULT_REGISTRY = "https://surx-registry.fly.dev"


def _http_json(url: str, payload: Optional[dict] = None,
               api_key: Optional[str] = None, timeout: float = 15.0) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def seal_with_registry(path: str, api_key: str, *,
                       registry_url: str = DEFAULT_REGISTRY) -> Dict[str, Any]:
    """Seal the container in the registry and store the receipt inside."""
    with ZipFile(path, "r") as zf:
        eh = _entry_hashes(zf)
        root = _entries_root(eh)
        client_pubkey, client_signer, name = "", "", ""
        if SIG_PATH in zf.namelist():
            p = json.loads(zf.read(SIG_PATH)).get("payload", {})
            client_pubkey = p.get("public_key", "")
            client_signer = p.get("signer", "")
        if "manifest.json" in zf.namelist():
            name = json.loads(zf.read("manifest.json")).get("name", "")
        receipt_exists = RECEIPT_PATH in zf.namelist()

    resp = _http_json(f"{registry_url}/api/v1/seals", api_key=api_key, payload={
        "entries_root": root, "entry_count": len(eh), "container_name": name,
        "client_pubkey": client_pubkey, "client_signer": client_signer,
    })
    receipt = {"registry_url": registry_url, "seal": resp["seal"],
               "signature": resp["signature"], "chain_hash": resp["chain_hash"],
               "verify_url": resp.get("verify_url", "")}
    blob = json.dumps(receipt, ensure_ascii=False, indent=2).encode()
    _rewrite_zip_with_replacements(
        path,
        replacements={RECEIPT_PATH: blob} if receipt_exists else {},
        additions={} if receipt_exists else {RECEIPT_PATH: blob},
    )
    return receipt


def verify_registry_seal(path: str, *, registry_url: Optional[str] = None,
                         registry_pubkey_hex: Optional[str] = None) -> Dict[str, Any]:
    """Verify the seal against the registry. valid=True if:
    (1) the local entries_root matches the sealed one,
    (2) the issuer Ed25519 signature validates the full payload,
    (3) the issuer key matches the one published by the registry
        (or with registry_pubkey_hex if pinned)."""
    report: Dict[str, Any] = {"valid": False, "reason": None, "seal_id": None,
                              "position": None, "verify_url": None}
    with ZipFile(path, "r") as zf:
        if RECEIPT_PATH not in zf.namelist():
            report["reason"] = "no receipt: the container was not sealed in a registry"
            return report
        receipt = json.loads(zf.read(RECEIPT_PATH))
        local_root = _entries_root(_entry_hashes(zf))

    seal = receipt["seal"]
    url = registry_url or receipt["registry_url"]
    report.update(seal_id=seal["seal_id"], position=seal["position"],
                  verify_url=receipt.get("verify_url"))

    if seal["container"]["entries_root"] != local_root:
        report["reason"] = ("current content is NOT the sealed one: local entries_root "
                            f"{local_root[:12]}… != sealed {seal['container']['entries_root'][:12]}…")
        return report

    # Fetch the seal from the registry (do not trust only the local receipt)
    remote = _http_json(f"{url}/api/v1/seals/{seal['seal_id']}")
    pub_hex = registry_pubkey_hex or _http_json(f"{url}/api/v1/pubkey")["registry_pubkey"]
    if remote["seal"].get("registry_pubkey") != pub_hex:
        report["reason"] = "the issuer key in the seal does not match the registry's"
        return report
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(remote["signature"]), _canonical(remote["seal"]))
    except (InvalidSignature, ValueError):
        report["reason"] = "invalid registry signature"
        return report
    if remote["seal"]["container"]["entries_root"] != local_root:
        report["reason"] = "el sello remoto no corresponde a este contenido"
        return report

    report["valid"] = True
    report["reason"] = "ok: contenido identico al notarizado en el log publico"
    report["sealed_at"] = seal["sealed_at"]
    report["tsa"] = remote["seal"].get("tsa")
    return report
