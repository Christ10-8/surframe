"""
SURFRAME PRO - License (safe stub for CI/MVP)
- Never raises on import.
- If there is no license: PRO disabled (is_pro_enabled -> False).
- Opt-in via env: SURFRAME_LICENSE_JSON or SURFRAME_LICENSE_PATH.
- Full bypass (for CI/docs): SURFRAME_DISABLE_PRO=1 -> always False.
"""
from __future__ import annotations
import json, os, hashlib
from dataclasses import dataclass
from typing import Optional, Set

@dataclass
class LicenseStatus:
    ok: bool
    reason: str = "unlicensed"
    features: Set[str] = None

def _machine_id() -> str:
    base = os.getenv("COMPUTERNAME") or os.getenv("HOSTNAME") or "unknown"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

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
    except Exception:
        return LicenseStatus(False, "invalid", set())
    if not data:
        return LicenseStatus(False, "missing", set())
    features = set(data.get("features", []))
    # MVP: we do not validate the signature; only format/presence
    return LicenseStatus(True, "ok", features)

def is_pro_enabled(feature: Optional[str] = None) -> bool:
    st = load_license()
    if not st.ok:
        return False
    return True if feature is None else (feature in st.features)

__all__ = ["is_pro_enabled", "load_license", "LicenseStatus"]
