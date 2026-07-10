"""
SURFRAME PRO – Licencia (stub seguro para CI/MVP)
- Nunca lanza excepción al importar.
- Si no hay licencia: PRO deshabilitado (is_pro_enabled -> False).
- Opt-in por env: SURFRAME_LICENSE_JSON o SURFRAME_LICENSE_PATH.
- Bypass total (por CI/docs): SURFRAME_DISABLE_PRO=1 → siempre False.
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
    # MVP: no validamos firma; solo formato-presencia
    return LicenseStatus(True, "ok", features)

def is_pro_enabled(feature: Optional[str] = None) -> bool:
    st = load_license()
    if not st.ok:
        return False
    return True if feature is None else (feature in st.features)

__all__ = ["is_pro_enabled", "load_license", "LicenseStatus"]
