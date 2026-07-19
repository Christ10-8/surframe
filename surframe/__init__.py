# Copyright 2025 Christ10-8
# Licensed under the Apache License, Version 2.0
"""SURFRAME: signed, column-encrypted, auditable SURX container.

0.2.0: explicit exports (the previous __init__ had three PATCH blocks that
clobbered each other's __all__), real Ed25519 signing (surframe.signing),
an audit verifier, and multi-call encryption without data loss.
"""
from __future__ import annotations

__version__ = "0.3.2"

# ---- Core: SURX container ----
from .io import (
    write, read, inspect, plan, plan_plus, validate, optimize,
    snapshot, list_snapshots, get_snapshot, resolve_as_of, log,
    reindex, advise, update_usage_kpis, encrypt,
)

# ---- Column encryption ----
from .crypto import (
    encrypt_columns_in_surx, decrypt_columns_in_surx,
    WrongPassphrase, CorruptCiphertext,
)

# ---- Audit ----
from .audit import append_audit_event, verify_audit_chain, read_audit_events

# ---- Ed25519 signing (new in 0.2.0) ----
from .signing import (
    generate_keypair, sign_container, verify_container,
    save_private_key, load_private_key, save_public_key, load_public_key,
    KeyPair,
)

# ---- Registry (transparency log, nuevo en 0.3.0) ----
from .registry import seal_with_registry, verify_registry_seal

# ---- Registry (transparency log, new in 0.3.0) ----
from .registry_client import seal_container_remote, check_seal

# ---- ANN / vector search ----
from .ann import ann_build, ann_query


def vsearch(container, *, col="embedding", query_vec=None, k=5,
            metric="cosine", where=None, id_col="id", columns=None):
    """Vector-search alias (test compat): maps query_vec -> q."""
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
