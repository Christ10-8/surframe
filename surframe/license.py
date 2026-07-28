"""
SURFRAME PRO — local feature gate.

HONEST SCOPE (0.4.0). This is NOT a security boundary and never was. Until 0.3.5
it accepted any JSON: `SURFRAME_LICENSE_JSON='{"features":["ucodec"]}'` unlocked
PRO. That is harmless in itself — the revenue lives in server-side quotas on the
registry, not here — but a gate that looks like enforcement and is not is worse
than no gate: it misleads whoever reads the code, and it was flagged as a finding
in an external audit for exactly that reason.

So now it says what it is. A license is a signed statement or it is nothing:
- With SURFRAME_LICENSE_PUBKEY set, the license must carry a valid Ed25519
  signature over its canonical payload. Unsigned or badly signed -> unlicensed.
- With no pubkey configured, this is an honour-system local flag. It reports
  reason="unverified" and enforces nothing, which is the truth.

Never raises on import. SURFRAME_DISABLE_PRO=1 forces everything off.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Optional, Set


@dataclass
class LicenseStatus:
    ok: bool
    reason: str = "unlicensed"
    features: Set[str] = field(default_factory=set)
    verified: bool = False


def _machine_id() -> str:
    base = os.getenv("COMPUTERNAME") or os.getenv("HOSTNAME") or "unknown"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _check_signature(data: dict, pubkey_hex: str) -> bool:
    """Ed25519 over the canonical payload, signature carried in `sig`."""
    sig_hex = data.get("sig")
    if not isinstance(sig_hex, str):
        return False
    payload = {k: v for k, v in data.items() if k != "sig"}
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(sig_hex), _canonical(payload))
        return True
    except Exception:
        return False


def load_license() -> LicenseStatus:
    if os.getenv("SURFRAME_DISABLE_PRO") == "1":
        return LicenseStatus(False, "disabled_by_env", set())

    lic_json = os.getenv("SURFRAME_LICENSE_JSON")
    lic_path = os.getenv("SURFRAME_LICENSE_PATH")
    data = None
    try:
        if lic_json:
            data = json.loads(lic_json)
        elif lic_path and os.path.exists(lic_path):
            with open(lic_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
    except (ValueError, OSError):
        return LicenseStatus(False, "invalid", set())
    if not isinstance(data, dict) or not data:
        return LicenseStatus(False, "missing", set())

    features = set(data.get("features", []) if isinstance(data.get("features"), list) else [])
    pubkey = (os.getenv("SURFRAME_LICENSE_PUBKEY") or "").strip().lower()
    if pubkey:
        if not _check_signature(data, pubkey):
            return LicenseStatus(False, "bad_signature", set())
        return LicenseStatus(True, "ok", features, verified=True)
    # No trust anchor configured: local flag only. Say so instead of pretending.
    return LicenseStatus(True, "unverified", features, verified=False)


def is_pro_enabled(feature: Optional[str] = None) -> bool:
    st = load_license()
    if not st.ok:
        return False
    return True if feature is None else (feature in st.features)


__all__ = ["is_pro_enabled", "load_license", "LicenseStatus", "_machine_id"]
