# -*- coding: utf-8 -*-
"""Bateria export ai-act: evidence pack correcto + rechazo de manipulados."""
import json, os, shutil, sys, tempfile, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import surframe
from surframe import generate_keypair, sign_container
from surframe.export_aiact import build_evidence_pack

os.environ["SURX_AUDIT"] = "1"
WORK = os.path.join(tempfile.gettempdir(), "sf_export_tests")  # portable Linux/Windows
shutil.rmtree(WORK, ignore_errors=True)
os.makedirs(WORK)
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def mkcontainer(path, signer="data-team"):
    df = pd.DataFrame({"prompt": ["x"] * 100, "label": [1, 0] * 50})
    surframe.write(df, path)
    kp = generate_keypair()
    sign_container(path, kp.private_hex, signer=signer)
    return kp


print("\n== export ai-act: pack valido ==")
c1 = os.path.join(WORK, "ok.surx")
mkcontainer(c1)
ev = build_evidence_pack(c1, output_dir=WORK, include_container=True,
                         declarations={"purpose": "test", "license": "CC-BY-4.0"})
pack = ev["_pack_path"]
check("pack generado", os.path.isdir(pack))
for f in ["EVIDENCE.json", "REPORT.md", "VERIFY.md", "ai_act_mapping.md", "checksums.txt"]:
    check(f"contiene {f}", os.path.exists(os.path.join(pack, f)))
check("contenedor embebido", os.path.exists(os.path.join(pack, "ok.surx")))
check("firma copiada", os.path.exists(os.path.join(pack, "signature.ed25519.json")))

evj = json.load(open(os.path.join(pack, "EVIDENCE.json"), encoding="utf-8"))
check("verificacion valida", evj["verification"]["valid"] is True)
check("signer registrado", evj["signature"]["signer"] == "data-team")
check("sha256 presente", len(evj["container"]["sha256"]) == 64)
check("declaraciones", evj["declarations"].get("license") == "CC-BY-4.0")
check("disclaimer sin 'compliant'", "compliant" not in
      open(os.path.join(pack, "REPORT.md"), encoding="utf-8").read().lower())

import hashlib
ok_sums = True
for line in open(os.path.join(pack, "checksums.txt"), encoding="utf-8"):
    digest, rel = line.strip().split(maxsplit=1)
    h = hashlib.sha256(open(os.path.join(pack, rel), "rb").read()).hexdigest()
    ok_sums = ok_sums and (h == digest)
check("checksums verificables", ok_sums)

print("\n== export ai-act: rechazo de tampering ==")
c2 = os.path.join(WORK, "bad.surx")
mkcontainer(c2)
names = zipfile.ZipFile(c2).namelist()
chunk = [n for n in names if n.startswith("chunks/")][0]
tmp = c2 + ".tmp"
with zipfile.ZipFile(c2, "r") as zin, zipfile.ZipFile(tmp, "w") as zout:
    for n in names:
        data = zin.read(n)
        zout.writestr(n, data + b"X" if n == chunk else data)
os.replace(tmp, c2)
try:
    build_evidence_pack(c2, output_dir=WORK)
    check("rechaza contenedor manipulado", False)
except RuntimeError as e:
    check("rechaza contenedor manipulado", "FAILED" in str(e), str(e)[:70])
check("no genera pack sobre manipulado",
      len([d for d in os.listdir(WORK) if d.startswith("evidence_pack_bad")]) == 0)

print("\n== export ai-act: rechazo de zip corrupto ==")
c3 = os.path.join(WORK, "corrupt.surx")
mkcontainer(c3)
data = open(c3, "rb").read()
i = data.find(b"part-000000") + 40
open(c3, "wb").write(data[:i] + bytes([data[i] ^ 0xFF]) + data[i + 1:])
try:
    build_evidence_pack(c3, output_dir=WORK)
    check("rechaza zip corrupto sin traceback", False)
except RuntimeError as e:
    # Rechazo limpio: nunca un traceback de zlib/zipfile crudo. Segun tenga o no
    # el fix de signing.py, el motivo llega como "could not even be read"
    # (verify_container tiraba excepcion) o "container unreadable" (0.3.1: ahora
    # verify_container la envuelve y devuelve reporte). Ambos son rechazo correcto.
    check("rechaza zip corrupto sin traceback",
          ("could not even be read" in str(e)) or ("container unreadable" in str(e)),
          str(e)[:70])
except Exception as e:  # si escapa cualquier otra cosa (traceback crudo), es FAIL
    check("rechaza zip corrupto sin traceback", False, f"traceback crudo: {type(e).__name__}")
check("no genera pack sobre corrupto",
      len([d for d in os.listdir(WORK) if d.startswith("evidence_pack_corrupt")]) == 0)

print("\n== export ai-act: sin firma ==")
c4 = os.path.join(WORK, "unsigned.surx")
surframe.write(pd.DataFrame({"a": [1, 2, 3]}), c4)
try:
    build_evidence_pack(c4, output_dir=WORK)
    check("rechaza contenedor sin firmar", False)
except RuntimeError as e:
    check("rechaza contenedor sin firmar", "unsigned" in str(e))

print("\n" + "=" * 60)
print(f"RESULTADO: {len(PASS)} PASS / {len(FAIL)} FAIL")
sys.exit(0 if not FAIL else 1)
