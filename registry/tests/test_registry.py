# -*- coding: utf-8 -*-
"""Bateria del SURX Registry: cada leccion de la auditoria del notary, atacada."""
import concurrent.futures as cf
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

WORK = tempfile.mkdtemp()
os.environ["REGISTRY_KEY_PATH"] = f"{WORK}/issuer.pem"
os.environ["REGISTRY_KEY_PASSPHRASE"] = "test-pass"
os.environ["REGISTRY_DEV_FAKE_LS"] = "LS-PRO-123:pro,LS-BIZ-456:business"
os.environ["REGISTRY_TSA_URL"] = ""   # sin red en tests

from registry import db, core
from registry.signer import bootstrap, IssuerSigner

PASS, FAIL = [], []
def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))

def root(i):
    return hashlib.sha256(f"dataset-{i}".encode()).hexdigest()

print("== R0: clave del emisor - cifrada at-rest, sin passphrase no arranca ==")
try:
    IssuerSigner()
    check("falla sin clave generada", False)
except RuntimeError:
    check("falla sin clave generada", True)
pub = bootstrap(os.environ["REGISTRY_KEY_PATH"], "test-pass")
mode = oct(os.stat(os.environ["REGISTRY_KEY_PATH"]).st_mode & 0o777)
check("PEM con permisos 0600", mode == "0o600", mode)
raw = open(os.environ["REGISTRY_KEY_PATH"], "rb").read()
check("PEM cifrado (ENCRYPTED PRIVATE KEY)", b"ENCRYPTED" in raw)
saved = os.environ.pop("REGISTRY_KEY_PASSPHRASE")
try:
    IssuerSigner()
    check("se niega a arrancar sin passphrase", False)
except RuntimeError:
    check("se niega a arrancar sin passphrase", True)
os.environ["REGISTRY_KEY_PASSPHRASE"] = saved

db.reset_for_tests(f"{WORK}/reg.db")
from fastapi.testclient import TestClient
from registry.app import app
client = TestClient(app)

print("\n== R1: flujo basico - key gratis, sellar, verificar ==")
r = client.post("/v1/keys/free")
key = r.json()["api_key"]
check("key gratis emitida", r.status_code == 200 and key.startswith("surx_"))
r = client.post("/v1/keys/free")
check("rate limit por IP (1/hora)", r.status_code == 429)
r = client.post("/v1/seal", headers={"X-API-Key": key},
                json={"entries_root": root(1), "entry_count": 8,
                      "subject": {"signer": "data-team", "public_key": "ab"*32, "name": "trainset-v3"}})
receipt = r.json()
check("sello emitido", r.status_code == 200 and receipt["n"] == 1)
sid = receipt["seal_id"]
rep = client.get(f"/v1/verify/{sid}").json()
check("verify: firma emisor + eslabon OK", rep["valid"] and rep["issuer_sig_ok"] and rep["chain_link_ok"])
check("busqueda por root", client.get(f"/v1/seals/by-root/{root(1)}").json()["seals"][0]["seal_id"] == sid)

print("\n== R2: forja de metadata (leccion #1: la firma cubre TODO el payload) ==")
conn = db.connect()
row = conn.execute("SELECT * FROM seals WHERE seal_id=?", (sid,)).fetchone()
p = json.loads(row["payload_json"]); p["subject"]["signer"] = "atacante-corp"
conn.execute("UPDATE seals SET payload_json=? WHERE seal_id=?", (json.dumps(p), sid)); conn.commit()
rep = client.get(f"/v1/verify/{sid}").json()
check("cambiar el firmante rompe la firma del emisor", not rep["valid"] and not rep["issuer_sig_ok"])
conn.execute("UPDATE seals SET payload_json=? WHERE seal_id=?",
             (row["payload_json"], sid)); conn.commit()
check("restaurado vuelve a valido", client.get(f"/v1/verify/{sid}").json()["valid"])

print("\n== R3: tamper del log + auditoria publica de cadena completa ==")
for i in range(2, 6):
    client.post("/v1/seal", headers={"X-API-Key": key},
                json={"entries_root": root(i), "entry_count": i, "subject": {}})
check("auditoria completa OK (5 sellos)",
      client.get("/v1/log/audit").json() == {"ok": True, "size": 5,
          "head": client.get("/v1/log/audit").json()["head"], "first_bad_n": None})
row3 = conn.execute("SELECT * FROM seals WHERE n=3").fetchone()
p3 = json.loads(row3["payload_json"]); p3["entries_root"] = root(999)
conn.execute("UPDATE seals SET payload_json=? WHERE n=3", (json.dumps(p3),)); conn.commit()
aud = client.get("/v1/log/audit").json()
check("auditoria detecta el eslabon exacto", not aud["ok"] and aud["first_bad_n"] == 3, str(aud))
conn.execute("UPDATE seals SET payload_json=? WHERE n=3", (row3["payload_json"],)); conn.commit()

print("\n== R4: race condition en append (leccion #3) - 20 sellos concurrentes ==")
k_biz = client.post("/v1/keys/activate", json={"license_key": "LS-BIZ-456"}).json()["api_key"]
def do_seal(i):
    return client.post("/v1/seal", headers={"X-API-Key": k_biz},
                       json={"entries_root": root(100 + i), "entry_count": 1, "subject": {}}).json()["n"]
with cf.ThreadPoolExecutor(8) as ex:
    ns = sorted(ex.map(do_seal, range(20)))
check("20 posiciones unicas y consecutivas", ns == list(range(6, 26)), str(ns[:5]) + "...")
check("cadena integra tras concurrencia", client.get("/v1/log/audit").json()["ok"])

print("\n== R5: metering por tier ==")
row = conn.execute("SELECT used, tier FROM api_keys WHERE label LIKE 'ip:%'").fetchone()
check("free consumio 5", row["used"] == 5 and row["tier"] == "free")
conn.execute("UPDATE api_keys SET used=10 WHERE label LIKE 'ip:%'"); conn.commit()
r = client.post("/v1/seal", headers={"X-API-Key": key},
                json={"entries_root": root(7), "entry_count": 1, "subject": {}})
check("cupo agotado -> 402", r.status_code == 402)
r = client.post("/v1/seal", headers={"X-API-Key": "surx_falsa"},
                json={"entries_root": root(7), "entry_count": 1, "subject": {}})
check("key invalida -> 401", r.status_code == 401)

print("\n== R6: activacion Lemon Squeezy (dev) ==")
r = client.post("/v1/keys/activate", json={"license_key": "LS-PRO-123"})
check("license pro -> tier pro", r.status_code == 200 and r.json()["tier"] == "pro"
      and r.json()["quota"] == 500)
check("license invalida -> 403",
      client.post("/v1/keys/activate", json={"license_key": "NOPE"}).status_code == 403)

print("\n== R7: checkpoint firmado (anti-rollback del registro) ==")
cp = client.get("/v1/checkpoint").json()
from registry.signer import verify_issuer
check("checkpoint verifica con clave del emisor",
      verify_issuer(cp["checkpoint"]["issuer_public_key"], cp["checkpoint"], cp["issuer_sig"])
      and cp["checkpoint"]["size"] == 25)
forged = dict(cp["checkpoint"]); forged["size"] = 3
check("checkpoint forjado NO verifica",
      not verify_issuer(forged["issuer_public_key"], forged, cp["issuer_sig"]))

print("\n== R8: pagina publica /s/{id} ==")
h = client.get(f"/s/{sid}")
check("HTML 200 con VERIFIED", h.status_code == 200 and "VERIFIED" in h.text
      and "data-team" in h.text)
check("seal inexistente -> 404 NOT FOUND",
      client.get("/s/sf-nope").status_code == 404)

print("\n== R9: badge SVG (marketing embebido en el producto) ==")
b = client.get(f"/badge/{sid}.svg")
check("badge verified verde", b.status_code == 200 and "verified" in b.text
      and "#1B7F5C" in b.text and b.headers["content-type"].startswith("image/svg"))
b = client.get("/badge/sf-nope.svg")
check("badge not found gris", "not found" in b.text and "#5B6770" in b.text)

print("\n== R10: log publico paginado ==")
l1 = client.get("/v1/log?after=0&limit=10").json()["entries"]
l2 = client.get("/v1/log?after=20&limit=100").json()["entries"]
check("paginacion correcta", [e["n"] for e in l1] == list(range(1, 11))
      and [e["n"] for e in l2] == list(range(21, 26)))
check("expone root y chain", all(len(e["entries_root"]) == 64 for e in l1))

print("\n" + "=" * 60)
print(f"REGISTRY: {len(PASS)} PASS / {len(FAIL)} FAIL")
if FAIL:
    print("FALLARON:", FAIL); sys.exit(1)
