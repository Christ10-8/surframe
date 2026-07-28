# Copyright 2026 Christ10-8 — Apache-2.0
"""Suite de regresion adversarial para SURFRAME.

Cada test assertea el comportamiento CORRECTO, por lo tanto FALLA mientras el
bug este vivo y pasa cuando se arregla. No son tests de "no crashea": son
tests de "el atacante no gana".

Correr:  pytest -q test_attacks.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from zipfile import ZipFile

import pytest

from surframe.signing import (
    generate_keypair, sign_container, verify_container,
    _entry_hashes, _entries_root, SIG_PATH,
)
from surframe.crypto import _rewrite_zip_with_replacements
from surframe import registry_client as rc

RECEIPT = "signatures/registry_seal.json"


# ---------------------------------------------------------------- helpers

def build(tmpdir, signer="data-team@release-v3"):
    """Container firmado, valido, real."""
    path = os.path.join(tmpdir, "t.surx")
    with ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"name": "clients", "rows": 3}))
        zf.writestr("data/part-0.bin", b"\x01\x02\x03" * 100)
        zf.writestr("profiles/audit/20260726.jsonl", "")
    kp = generate_keypair()
    sign_container(path, kp.private_hex, signer=signer)
    return path, kp


def forge_receipt(path, *, seal_id="sf-00000042-deadbeef", signer="data-team@openai",
                  subject_pubkey=None):
    """Forja un recibo del registro con MI keypair de emisor, sobre el estado
    ACTUAL (ya adulterado) del container. Sin tocar la red."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    with ZipFile(path, "r") as zf:
        root = _entries_root(_entry_hashes(zf))
        n_entries = len(_entry_hashes(zf))
        real_pub = ""
        if SIG_PATH in zf.namelist():
            real_pub = json.loads(zf.read(SIG_PATH)).get("payload", {}).get("public_key", "")
        exists = RECEIPT in zf.namelist()

    evil = Ed25519PrivateKey.generate()
    evil_pub = evil.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    payload = {
        "v": 1, "seal_id": seal_id, "n": 42, "ts": "2026-07-26T00:00:00Z",
        "entries_root": root, "entry_count": n_entries,
        "subject": {"signer": signer,
                    "public_key": subject_pubkey if subject_pubkey is not None else real_pub,
                    "name": "t.surx"},
        "tier": "business", "prev_hash": "0" * 64,
        "issuer_public_key": evil_pub,
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode()
    receipt = {
        "seal_id": seal_id, "n": 42, "payload": payload,
        "issuer_sig": evil.sign(canonical).hex(),
        "chain_hash": "f" * 64,
        "issuer_public_key": evil_pub,
        "rfc3161": False,
        "verify_url": "https://api.surframe.dev/s/" + seal_id,
    }
    blob = json.dumps(receipt, ensure_ascii=False, indent=2).encode()
    _rewrite_zip_with_replacements(
        path,
        replacements={RECEIPT: blob} if exists else {},
        additions={} if exists else {RECEIPT: blob},
    )
    return receipt, evil_pub


def tamper_chunk(path, name="data/part-0.bin", data=b"POISONED" * 40):
    _rewrite_zip_with_replacements(path, replacements={name: data}, additions={})


# ---------------------------------------------------------------- ataques

def test_01_check_seal_rejects_foreign_issuer_key(tmp_path):
    """#1 CRITICO: check_seal no debe confiar en la clave del emisor que viaja
    DENTRO del artefacto. Sin ancla de confianza, cualquiera forja los 3 tildes."""
    path, kp = build(str(tmp_path))
    tamper_chunk(path)
    forge_receipt(path)
    r = rc.check_seal(path, registry_url="http://127.0.0.1:9")  # red muerta a proposito
    assert r["valid"] is False, f"recibo forjado aceptado offline: {r}"
    assert "issuer" in (r.get("reason") or "").lower()


def test_02_check_seal_fails_closed_on_404(tmp_path):
    """#1b: HTTPError es subclase de URLError. Un registro que responde
    'seal_id not found' no puede terminar reportado como 'unreachable'."""
    import http.server, threading, urllib.error

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"found": False, "valid": False,
                               "reason": "seal_id not found"}).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        path, kp = build(str(tmp_path))
        tamper_chunk(path)
        forge_receipt(path)
        r = rc.check_seal(path, registry_url=f"http://127.0.0.1:{port}")
        assert r["registry"] != "unreachable", \
            f"un 404 explicito quedo enmascarado como unreachable: {r}"
        assert r["valid"] is False, r
    finally:
        srv.shutdown()


def test_03_check_seal_binds_receipt_to_container_signer(tmp_path):
    """#1c: el recibo debe estar ATADO a la firma local. Si subject.public_key
    no es la clave que firmo el container, el sello no prueba nada de este
    artefacto. Y check_seal no puede dar valid si verify_container falla."""
    path, kp = build(str(tmp_path))
    forge_receipt(path, subject_pubkey="ab" * 32)  # clave que no firmo nada
    r = rc.check_seal(path, registry_url="http://127.0.0.1:9")
    assert r["valid"] is False, f"sello aceptado con signer ajeno: {r}"


def test_04_audit_new_file_after_signing_is_invalid(tmp_path):
    """#3 ALTO: inyectar profiles/audit/<nuevo>.jsonl con eventos inventados
    hoy sale 'new_file_after_signing' y NO toca audit_ok -> valid True."""
    path, kp = build(str(tmp_path))
    fake = ("{\"ts\":\"2026-08-20T10:00:00Z\",\"event\":\"export\","
            "\"actor\":\"auditor@bigfour.com\"}\n"
            "{\"ts\":\"2026-08-20T10:05:00Z\",\"event\":\"review_passed\","
            "\"actor\":\"legal@corp.com\"}\n")
    _rewrite_zip_with_replacements(
        path, replacements={}, additions={"profiles/audit/20260820.jsonl": fake.encode()})
    r = verify_container(path)
    assert r["valid"] is False, f"evidencia de auditoria fabricada aceptada: {r}"
    assert r["audit"]["unattested_appends"] == 2, str(r["audit"])


def test_05_audit_appended_events_are_authenticated(tmp_path):
    """#3b ALTO: la cadena de auditoria es SHA-256 SIN clave. Continuarla con un
    evento forjado mantiene al head firmado como ancestro -> append_only_ok.
    O se autentican los appends, o el THREAT_MODEL lo dice explicito."""
    path, kp = build(str(tmp_path))
    with ZipFile(path, "r") as zf:
        cur = zf.read("profiles/audit/20260726.jsonl").decode()
    prev = hashlib.sha256(cur.strip().encode()).hexdigest() if cur.strip() else "0" * 64
    evt = {"ts": "2026-08-20T11:00:00Z", "event": "review_passed",
           "actor": "legal@corp.com", "prev_sha256": prev}
    base = json.dumps(evt, ensure_ascii=False, separators=(",", ":"))
    evt["sha256"] = hashlib.sha256(base.encode()).hexdigest()
    line = json.dumps(evt, ensure_ascii=False, separators=(",", ":"))
    _rewrite_zip_with_replacements(
        path, replacements={"profiles/audit/20260726.jsonl": (cur + line + "\n").encode()},
        additions={})
    r = verify_container(path)
    assert r["valid"] is False, (
        "evento de auditoria forjado post-firma aceptado como append_only_ok: "
        f"{r['audit']}")


def test_06_prefixed_bytes_are_rejected(tmp_path):
    """#5 MEDIO: 'not a single byte changed' es falso. Prefijar basura al zip
    cambia el sha256 del archivo y valid sigue True. Habilita polyglots."""
    path, kp = build(str(tmp_path))
    before = hashlib.sha256(open(path, "rb").read()).hexdigest()
    raw = open(path, "rb").read()
    open(path, "wb").write(b"\x90" * 1700 + raw)
    after = hashlib.sha256(open(path, "rb").read()).hexdigest()
    assert before != after
    r = verify_container(path)
    assert r["valid"] is False, f"zip con 1700 bytes prefijados sigue valido: {r}"


def test_07_zip_comment_is_rejected(tmp_path):
    """#5b: el comment del zip no esta firmado; es un canal de datos libre."""
    path, kp = build(str(tmp_path))
    with ZipFile(path, "a") as zf:
        zf.comment = b"payload arbitrario no firmado"
    r = verify_container(path)
    assert r["valid"] is False, f"comment de zip no firmado aceptado: {r}"


def test_08_malformed_signature_doc_reports_not_crashes(tmp_path):
    """#6 MEDIO: el docstring de signing.py promete que un container corrupto
    NO revienta con traceback crudo. Hoy tira AttributeError/KeyError."""
    for bad in (b"[]", b'{"payload":"x"}', b'{"nope":1}'):
        path, kp = build(str(tmp_path / hashlib.sha256(bad).hexdigest()[:8]) if False else str(tmp_path))
        _rewrite_zip_with_replacements(path, replacements={SIG_PATH: bad}, additions={})
        r = verify_container(path)  # no debe levantar
        assert r["valid"] is False
        assert r["reason"], f"sin reason para {bad!r}"
    # y en check_seal
    path, kp = build(str(tmp_path))
    _rewrite_zip_with_replacements(path, replacements={},
                                   additions={RECEIPT: b'{"nope":1}'})
    r = rc.check_seal(path, registry_url="http://127.0.0.1:9")
    assert r["valid"] is False and r.get("reason")


def test_09_decompression_bomb_is_capped(tmp_path):
    """#7 MEDIO: _entry_hashes hace zf.read(name) completo a RAM. Un container
    chico con ratio alto hace que el verificador aloje cientos de MB."""
    path = str(tmp_path / "bomb.surx")
    with ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("manifest.json", "{}")
        zf.writestr("data/bomb.bin", b"\x00" * (256 * 1024 * 1024))
    size = os.path.getsize(path)
    with ZipFile(path, "r") as zf:
        info = zf.getinfo("data/bomb.bin")
        ratio = info.file_size / max(info.compress_size, 1)
    assert ratio > 100
    r = verify_container(path)
    assert r["valid"] is False, "bomba de descompresion procesada sin tope"
    assert "ratio" in (r["reason"] or "").lower() or "bomb" in (r["reason"] or "").lower(), \
        f"reason no menciona el tope: {r['reason']}"


def test_10_security_module_imports(tmp_path):
    """Menor: security.py importa get_machine_id de license.py, donde la funcion
    se llama _machine_id -> ImportError garantizado."""
    import importlib
    m = importlib.import_module("surframe.security")
    assert m.anti_tamper_check() is True
    assert isinstance(m.fingerprint_runtime(), str)
