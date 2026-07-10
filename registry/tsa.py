# Copyright 2025 Christ10-8 — Apache-2.0
"""RFC 3161 opcional con degradacion elegante. Leccion aplicada: verify() re-valida
el token contra el imprint real; jamas confia en un campo editable."""
from __future__ import annotations
import base64, hashlib, os

TSA_URL_ENV = "REGISTRY_TSA_URL"   # ej: https://freetsa.org/tsr ; vacio = desactivado

def timestamp(data: bytes) -> str | None:
    url = os.environ.get(TSA_URL_ENV, "").strip()
    if not url:
        return None
    try:
        import rfc3161ng
        rt = rfc3161ng.RemoteTimestamper(url, hashname="sha256")
        token = rt.timestamp(data=data)
        return base64.b64encode(token).decode()
    except Exception:
        return None   # el sello sale igual; el token es refuerzo, no requisito

def verify_token(token_b64: str, data: bytes) -> bool:
    try:
        import rfc3161ng
        token = base64.b64decode(token_b64)
        return bool(rfc3161ng.check_timestamp(token, data=data, hashname="sha256"))
    except Exception:
        return False
