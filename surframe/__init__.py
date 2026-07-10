# Copyright 2025 Christ10-8
# Licensed under the Apache License, Version 2.0
"""SURFRAME: contenedor SURX firmado, cifrado por columna y auditable.

0.2.0: exports explicitos (el __init__ anterior tenia tres bloques PATCH que
se pisaban el __all__ entre si), firma Ed25519 real (surframe.signing),
verificador de auditoria, y cifrado multi-llamada sin perdida de datos.
"""
from __future__ import annotations

__version__ = "0.3.0"

# ---- Core: contenedor SURX ----
from .io import (
    write, read, inspect, plan, plan_plus, validate, optimize,
    snapshot, list_snapshots, get_snapshot, resolve_as_of, log,
    reindex, advise, update_usage_kpis, encrypt,
)

# ---- Cifrado por columna ----
from .crypto import (
    encrypt_columns_in_surx, decrypt_columns_in_surx,
    WrongPassphrase, CorruptCiphertext,
)

# ---- Auditoria ----
from .audit import append_audit_event, verify_audit_chain, read_audit_events

# ---- Firma Ed25519 (nuevo en 0.2.0) ----
from .signing import (
    generate_keypair, sign_container, verify_container,
    save_private_key, load_private_key, save_public_key, load_public_key,
    KeyPair,
)

# ---- Registry (transparency log, nuevo en 0.3.0) ----
from .registry import seal_with_registry, verify_registry_seal

# ---- Registro (transparency log, nuevo en 0.3.0) ----
from .registry_client import seal_container_remote, check_seal

# ---- ANN / busqueda vectorial ----
from .ann import ann_build, ann_query


def vsearch(container, *, col="embedding", query_vec=None, k=5,
            metric="cosine", where=None, id_col="id", columns=None):
    """Alias de busqueda vectorial (compat con tests): mapea query_vec -> q."""
    return ann_query(container, col=col, q=query_vec, k=int(k),
                     metric=metric, where=where, id_col=id_col, columns=columns)


# ---- Gating PRO (no fatal) ----
try:
    from .license import is_pro_enabled
except Exception:  # pragma: no cover
    def is_pro_enabled(*args, **kwargs):
        return False


def _pro(feature: str, modpath: str, fname: str):
    def _wrapper(*args, **kwargs):
        if not is_pro_enabled(feature):
            raise RuntimeError(f"SURFRAME PRO requerido: feature '{feature}' no habilitada.")
        import importlib
        mod = importlib.import_module(modpath, package=__name__)
        return getattr(mod, fname)(*args, **kwargs)
    _wrapper.__name__ = fname
    return _wrapper


learn_ucodec = _pro("ucodec", ".ucodec.learn", "learn_ucodec")
reencode_ucodec = _pro("ucodec", ".ucodec.reencode", "reencode_ucodec")
zorder_optimize = _pro("zopt", ".ucodec.layout", "zorder_optimize")
tier_plan = _pro("tier", ".ucodec.tier", "tier_plan")


__all__ = [
    "__version__",
    # core
    "write", "read", "inspect", "plan", "plan_plus", "validate", "optimize",
    "snapshot", "list_snapshots", "get_snapshot", "resolve_as_of", "log",
    "reindex", "advise", "update_usage_kpis", "encrypt",
    # crypto
    "encrypt_columns_in_surx", "decrypt_columns_in_surx",
    "WrongPassphrase", "CorruptCiphertext",
    # audit
    "append_audit_event", "verify_audit_chain", "read_audit_events",
    # signing
    "generate_keypair", "sign_container", "verify_container",
    "save_private_key", "load_private_key", "save_public_key", "load_public_key",
    "KeyPair",
    # registry
    "seal_with_registry", "verify_registry_seal",
    "seal_container_remote", "check_seal",
    # ann
    "ann_build", "ann_query", "vsearch",
    # pro
    "is_pro_enabled", "learn_ucodec", "reencode_ucodec", "zorder_optimize", "tier_plan",
]
