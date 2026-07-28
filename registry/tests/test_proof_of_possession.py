# Copyright 2026 Christ10-8 — Apache-2.0
"""#4: el registro debe validar TITULARIDAD de clave, no solo aceptar texto libre.

Corre el registry de verdad en un TestClient con una base temporal.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from zipfile import ZipFile

# Repo root on sys.path: Python puts THIS file's directory on sys.path, not the
# project root, so `import registry` would fail when run as a plain script.
# Same trick as test_registry.py — no PYTHONPATH needed.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

os.environ["REGISTRY_KEY_PASSPHRASE"] = "test-pass-pop"
_tmp = tempfile.mkdtemp()
os.environ["REGISTRY_DB"] = os.path.join(_tmp, "reg.sqlite")
os.environ["REGISTRY_KEY_PATH"] = os.path.join(_tmp, "issuer_key.pem")
os.environ["REGISTRY_TSA_URL"] = ""

from registry.signer import bootstrap  # noqa: E402
bootstrap(os.environ["REGISTRY_KEY_PATH"], os.environ["REGISTRY_KEY_PASSPHRASE"])

from fastapi.testclient import TestClient  # noqa: E402
from registry.app import app  # noqa: E402
from surframe.signing import generate_keypair, sign_container, SIG_PATH  # noqa: E402

c = TestClient(app)
FAIL = []


def check(name, cond, detail=""):
    print(("  [PASS] " if cond else "  [FAIL] ") + name + (f" - {detail}" if detail else ""))
    if not cond:
        FAIL.append(name)


def container(tmp, signer):
    path = os.path.join(tmp, "t.surx")
    with ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", '{"name":"clients"}')
        zf.writestr("data/part-0.bin", b"\x01\x02\x03" * 50)
    kp = generate_keypair()
    sign_container(path, kp.private_hex, signer=signer)
    with ZipFile(path, "r") as zf:
        doc = json.loads(zf.read(SIG_PATH))
    return path, kp, doc


key = c.post("/v1/keys/free").json()["api_key"]
H = {"X-API-Key": key}

print("\n== #4: el signer declarado sin prueba NO queda como verificado ==")
tmp = tempfile.mkdtemp()
path, kp, doc = container(tmp, "data-team@release-v3")
p = doc["payload"]

r = c.post("/v1/seal", headers=H, json={
    "entries_root": p["entries_root"], "entry_count": p["entry_count"],
    "subject": {"signer": "data-team@openai", "public_key": "ab" * 32, "name": "t.surx"}})
check("cliente viejo (sin signature_doc) sigue funcionando", r.status_code == 200, r.text)
sid_unverified = r.json()["seal_id"]
check("subject.verified es False sin prueba",
      r.json()["payload"]["subject"]["verified"] is False, json.dumps(r.json()["payload"]["subject"]))

v = c.get(f"/v1/verify/{sid_unverified}").json()
check("verify reporta signer_verified False", v["signer_verified"] is False, json.dumps(v)[:200])
page = c.get(f"/s/{sid_unverified}").text
check("la pagina publica NO dice VERIFIED", "VERIFIED" not in page)
check("la pagina publica dice que el signer es declarado",
      "NOT verified" in page and "not who produced it" in page)
badge = c.get(f"/badge/{sid_unverified}.svg").text
check("el badge dice 'sealed', no 'verified'", ">sealed<" in badge, badge[-90:])

print("\n== #4: la prueba de posesion valida marca verified ==")
r = c.post("/v1/seal", headers=H, json={
    "entries_root": p["entries_root"], "entry_count": p["entry_count"],
    "subject": {"signer": p["signer"], "public_key": p["public_key"], "name": "t.surx"},
    "signature_doc": doc})
check("sello con prueba valida aceptado", r.status_code == 200, r.text)
sid_ok = r.json()["seal_id"]
check("subject.verified es True", r.json()["payload"]["subject"]["verified"] is True)
check("la pagina publica dice VERIFIED", "VERIFIED" in c.get(f"/s/{sid_ok}").text)
check("el badge dice 'verified'", ">verified<" in c.get(f"/badge/{sid_ok}.svg").text)

print("\n== #4: robar autoria ya no funciona ==")
r = c.post("/v1/seal", headers=H, json={
    "entries_root": p["entries_root"], "entry_count": p["entry_count"],
    # afirmo la clave ajena y adjunto el doc de firma real de ese tercero
    "subject": {"signer": "data-team@openai", "public_key": "cd" * 32, "name": "t.surx"},
    "signature_doc": doc})
check("prueba que no matchea el public_key declarado -> 400", r.status_code == 400, r.text[:160])

evil = dict(doc)
evil["signature"] = "00" * 64
r = c.post("/v1/seal", headers=H, json={
    "entries_root": p["entries_root"], "entry_count": p["entry_count"],
    "subject": {"signer": p["signer"], "public_key": p["public_key"], "name": "t.surx"},
    "signature_doc": evil})
check("firma invalida -> 400", r.status_code == 400, r.text[:160])

# root distinto al firmado: replay de un doc de firma sobre otro contenido
r = c.post("/v1/seal", headers=H, json={
    "entries_root": "9" * 64, "entry_count": p["entry_count"],
    "subject": {"signer": p["signer"], "public_key": p["public_key"], "name": "t.surx"},
    "signature_doc": doc})
check("doc de firma que no cubre ESTE root -> 400", r.status_code == 400, r.text[:160])

print("\n== auditoria del log completo valida firmas, no solo eslabones ==")
a = c.get("/v1/log/audit").json()
check("audit ok", a["ok"] is True, json.dumps(a))
check("audit reporta first_bad_signature_n", "first_bad_signature_n" in a)

print("\n" + "=" * 60)
print(f"PROOF OF POSSESSION: {14 - len(FAIL)} PASS / {len(FAIL)} FAIL")
if FAIL:
    print("FALLARON:", FAIL)
raise SystemExit(1 if FAIL else 0)
