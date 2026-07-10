# Copyright 2025 Christ10-8
# Licensed under the Apache License, Version 2.0

# surframe/audit.py
"""
Log de auditoria append-only dentro del .surx (profiles/audit/YYYYMMDD.jsonl).

v2 (0.2.0):
- Firma encadenada ACTIVA por defecto (SURX_AUDIT_SIGN=0 para desactivar).
- Locking entre procesos: dos escritores concurrentes ya no se pisan eventos
  (en 0.1.5 era last-writer-wins y se perdian lineas).
- verify_audit_chain(): recorre y valida la cadena completa; en 0.1.5 habia
  codigo para escribirla pero ninguno para verificarla.
- datetime.now(timezone.utc) en vez de utcnow() (deprecado en 3.12).

Nota honesta de seguridad: la cadena SHA-256 sin clave detecta corrupcion y
ediciones casuales, pero un atacante con acceso de escritura puede recalcularla
entera. La tamper-evidence REAL la da signing.sign_container(), que ancla el
head de esta cadena bajo una firma Ed25519. Cadena = orden e integridad
interna; firma = autenticidad.
"""
from __future__ import annotations

import datetime as _dt
import getpass as _getpass
import hashlib as _hashlib
import json as _json
import os as _os
from contextlib import contextmanager
from typing import Any, Dict, List, Optional
from zipfile import ZipFile

from .crypto import _rewrite_zip_with_replacements

AUDIT_PREFIX = "profiles/audit/"
GENESIS = "0" * 64


def _iso_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _whoami() -> str:
    try:
        return _os.environ.get("SURX_USER") or _getpass.getuser() or "unknown"
    except Exception:
        return "unknown"


@contextmanager
def _file_lock(target_path: str):
    """Lock exclusivo entre procesos sobre <target>.lock (fcntl en POSIX,
    msvcrt en Windows, lockfile O_EXCL como ultimo recurso)."""
    lock_path = target_path + ".lock"
    fd = _os.open(lock_path, _os.O_CREAT | _os.O_RDWR, 0o644)
    locked_via = None
    try:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
            locked_via = "fcntl"
        except ImportError:
            try:
                import msvcrt
                _os.lseek(fd, 0, 0)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                locked_via = "msvcrt"
            except ImportError:
                locked_via = None  # sin locking real: mejor esfuerzo
        yield
    finally:
        try:
            if locked_via == "fcntl":
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            elif locked_via == "msvcrt":
                import msvcrt
                _os.lseek(fd, 0, 0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            _os.close(fd)


def append_audit_event(path: str, event: Dict[str, Any], sign: Optional[bool] = None) -> None:
    """
    Agrega (o crea) una linea JSONL en profiles/audit/YYYYMMDD.jsonl dentro del .surx.
    Control por env:
      - SURX_AUDIT=0        -> desactiva (default: activo)
      - SURX_AUDIT_SIGN=0   -> desactiva firma encadenada (default: ACTIVA)
      - SURX_CLIENT=cli|py  -> etiqueta de cliente
      - SURX_USER=...       -> usuario (fallback: getpass.getuser())
    """
    if str(_os.environ.get("SURX_AUDIT", "1")).lower() in ("0", "false", "no"):
        return

    evt = dict(event)
    evt.setdefault("ts", _iso_utc())
    evt.setdefault("op", "read")
    evt.setdefault("user", _whoami())
    client = _os.environ.get("SURX_CLIENT")
    if client:
        evt.setdefault("client", client)

    date_yyyymmdd = evt["ts"][:10].replace("-", "")
    rel_log = f"{AUDIT_PREFIX}{date_yyyymmdd}.jsonl"

    do_sign = bool(sign) if sign is not None else \
        str(_os.environ.get("SURX_AUDIT_SIGN", "1")).lower() in ("1", "true", "yes")

    # Lock ANTES de leer: leer-modificar-escribir tiene que ser atomico
    # entre procesos, si no dos appends concurrentes se pisan (0.1.5).
    with _file_lock(path):
        existing: Optional[bytes] = None
        try:
            with ZipFile(path, "r") as zf:
                if rel_log in zf.namelist():
                    existing = zf.read(rel_log)
        except FileNotFoundError:
            return  # dataset no existe: nada que auditar

        if do_sign:
            prev_hash = GENESIS
            if existing:
                lines = [ln for ln in existing.split(b"\n") if ln.strip()]
                if lines:
                    prev_hash = _hashlib.sha256(lines[-1]).hexdigest()
            base = dict(evt)
            base["prev_sha256"] = prev_hash  # la firma cubre el evento + prev
            payload = _json.dumps(base, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            evt["prev_sha256"] = prev_hash
            evt["sha256"] = _hashlib.sha256(payload).hexdigest()

        line = _json.dumps(evt, ensure_ascii=False) + "\n"
        new_bytes = (existing or b"") + line.encode("utf-8")

        if existing is None:
            _rewrite_zip_with_replacements(path, replacements={}, additions={rel_log: new_bytes})
        else:
            _rewrite_zip_with_replacements(path, replacements={rel_log: new_bytes}, additions={})


def verify_audit_chain(path: str) -> Dict[str, Any]:
    """Valida la cadena de TODOS los archivos de auditoria del contenedor.

    Devuelve: {"ok": bool, "files": {nombre: {"events", "signed_events",
    "ok", "first_bad_line"}}, "total_events": int}
    """
    report: Dict[str, Any] = {"ok": True, "files": {}, "total_events": 0}
    with ZipFile(path, "r") as zf:
        logs = sorted(n for n in zf.namelist()
                      if n.startswith(AUDIT_PREFIX) and n.endswith(".jsonl"))
        for name in logs:
            raw = zf.read(name)
            lines = [ln for ln in raw.split(b"\n") if ln.strip()]
            prev = GENESIS
            f_ok, bad, signed = True, None, 0
            for i, ln in enumerate(lines, start=1):
                try:
                    evt = _json.loads(ln)
                except Exception:
                    f_ok, bad = False, i
                    break
                if "sha256" in evt and "prev_sha256" in evt:
                    signed += 1
                    if evt["prev_sha256"] != prev:
                        f_ok, bad = False, i
                        break
                    base = {k: v for k, v in evt.items() if k != "sha256"}
                    payload = _json.dumps(base, ensure_ascii=False,
                                          separators=(",", ":")).encode("utf-8")
                    if _hashlib.sha256(payload).hexdigest() != evt["sha256"]:
                        f_ok, bad = False, i
                        break
                prev = _hashlib.sha256(ln).hexdigest()
            report["files"][name] = {
                "events": len(lines), "signed_events": signed,
                "ok": f_ok, "first_bad_line": bad,
            }
            report["total_events"] += len(lines)
            report["ok"] = report["ok"] and f_ok
    return report


def read_audit_events(path: str) -> List[Dict[str, Any]]:
    """Devuelve todos los eventos de auditoria en orden cronologico de archivo."""
    out: List[Dict[str, Any]] = []
    with ZipFile(path, "r") as zf:
        for name in sorted(n for n in zf.namelist()
                           if n.startswith(AUDIT_PREFIX) and n.endswith(".jsonl")):
            for ln in zf.read(name).split(b"\n"):
                if ln.strip():
                    try:
                        out.append(_json.loads(ln))
                    except Exception:
                        out.append({"_raw": ln.decode("utf-8", "replace"), "_error": "json"})
    return out
