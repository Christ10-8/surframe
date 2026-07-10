# -*- coding: utf-8 -*-
"""
SURFRAME PRO — Security stubs
- Fingerprint y anti-tamper mínimos (no bloquean).
"""
from __future__ import annotations
import hashlib, sys
from .license import get_machine_id

def fingerprint_runtime() -> str:
    base = f"{sys.version}|{get_machine_id()}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def anti_tamper_check() -> bool:
    # Stub: siempre OK (dejar hooks para futuro)
    return True
