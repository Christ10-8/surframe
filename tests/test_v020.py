# -*- coding: utf-8 -*-
"""Bateria v0.2.0: demuestra cada fix con un ataque/escenario real."""
import io, json, hashlib, os, shutil, sys, tempfile, zipfile
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import pandas as pd
import surframe
from surframe import (encrypt_columns_in_surx, decrypt_columns_in_surx,
                      WrongPassphrase, CorruptCiphertext,
                      generate_keypair, sign_container, verify_container,
                      append_audit_event, verify_audit_chain)

os.environ["SURX_AUDIT"] = "1"
os.environ["SURX_AUDIT_SIGN"] = "1"
WORK = os.path.join(tempfile.gettempdir(), "sf_tests")  # portable Linux/Windows
shutil.rmtree(WORK, ignore_errors=True)
os.makedirs(WORK)
PASS, FAIL = [], []

def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))

def mkdf(n=100):
    return pd.DataFrame({"id": range(n), "country": ["AR"]*(n//2) + ["UY"]*(n//2),
                         "dni": [f"D{i:05d}" for i in range(n)],
                         "salario": [1000.0+i for i in range(n)],
                         "nota": [f"n{i}" for i in range(n)]})

def fresh(name):
    p = f"{WORK}/{name}.surx"
    surframe.write(mkdf(), p)
    return p

def zip_patch(path, inner, data):
    tmp = path + ".t"
    with zipfile.ZipFile(path) as zin, zipfile.ZipFile(tmp, "w") as zout:
        for n in zin.namelist():
            zout.writestr(n, data if n == inner else zin.read(n))
    os.replace(tmp, path)

print("\n== T1: cifrado multi-llamada (bug de perdida de datos en 0.1.5) ==")
p = fresh("t1")
encrypt_columns_in_surx(p, ["dni"], "clave123")
encrypt_columns_in_surx(p, ["salario"], "clave123")   # en 0.1.5 esto rompia 'dni'
df = surframe.read(p, columns=["id", "dni", "salario"], passphrase="clave123")
check("dni recuperable tras 2da llamada", df["dni"].iloc[7] == "D00007")
check("salario recuperable", float(df["salario"].iloc[7]) == 1007.0)
meta = json.loads(zipfile.ZipFile(p).read("config/crypto.json"))
check("meta fusionado (2 columnas)", sorted(meta["columns"]) == ["dni", "salario"])
check("Scrypt N=2^17", meta["scrypt"]["n"] == 2**17, f"n={meta['scrypt']['n']}")
encrypt_columns_in_surx(p, ["dni"], "clave123")  # re-cifrar lo ya cifrado
check("re-cifrado idempotente (no-op)", True)

print("\n== T2: passphrase equivocada en 2da llamada -> aborta ANTES de tocar nada ==")
p = fresh("t2")
encrypt_columns_in_surx(p, ["dni"], "clave123")
try:
    encrypt_columns_in_surx(p, ["salario"], "OTRA_clave")
    check("rechaza passphrase distinta", False)
except WrongPassphrase:
    check("rechaza passphrase distinta", True)
df = surframe.read(p, columns=["dni"], passphrase="clave123")
check("datos originales intactos", df["dni"].iloc[0] == "D00000")
try:
    surframe.read(p, columns=["dni"], passphrase="mala")
    check("error preciso con passphrase mala", False)
except WrongPassphrase:
    check("error preciso con passphrase mala", True)

print("\n== T3: firma Ed25519 -> tamper de un chunk detectado con nombre exacto ==")
p = fresh("t3")
kp = generate_keypair()
sign_container(p, kp.private_hex, signer="christian")
rep = verify_container(p, kp.public_hex)
check("verify OK post-firma", rep["valid"], rep["reason"])
chunk = [n for n in zipfile.ZipFile(p).namelist() if n.endswith(".parquet")][0]
raw = bytearray(zipfile.ZipFile(p).read(chunk)); raw[100] ^= 0xFF
zip_patch(p, chunk, bytes(raw))
rep = verify_container(p, kp.public_hex)
check("tamper detectado", not rep["valid"])
check("entrada exacta reportada", chunk in rep["modified"], str(rep["modified"]))
kp2 = generate_keypair()
rep = verify_container(p, kp2.public_hex)
check("clave publica ajena -> firma invalida", not rep["valid"] and "firma invalida" in rep["reason"])

print("\n== T4: cadena de auditoria - verificador nuevo ==")
p = fresh("t4")
for i in range(5):
    append_audit_event(p, {"op": "read", "n": i})
rep = verify_audit_chain(p)
check("cadena valida (5 eventos)", rep["ok"] and rep["total_events"] >= 5)
fname = [f for f in rep["files"]][0]
raw = zipfile.ZipFile(p).read(fname)
lines = raw.decode().strip().split("\n")
evt = json.loads(lines[2]); evt["n"] = 999    # editar evento del medio
lines[2] = json.dumps(evt, ensure_ascii=False)
zip_patch(p, fname, ("\n".join(lines) + "\n").encode())
rep = verify_audit_chain(p)
bad = rep["files"][fname]
check("edicion de evento detectada", not rep["ok"])
check("linea exacta reportada", bad["first_bad_line"] in (3, 4), f"linea {bad['first_bad_line']}")

print("\n== T5: ataque real - reescribir la cadena COMPLETA (vence al hash-chain sin clave) ==")
p = fresh("t5")
for i in range(4):
    append_audit_event(p, {"op": "write", "n": i})
kp = generate_keypair()
sign_container(p, kp.private_hex, signer="christian")
append_audit_event(p, {"op": "read", "n": 99})  # crecimiento legitimo post-firma
rep = verify_container(p, kp.public_hex)
check("append post-firma sigue valido (append-only)", rep["valid"], rep["reason"])
# atacante: borra el evento n=1 y RE-CALCULA toda la cadena (chain queda perfecta)
fname = [n for n in zipfile.ZipFile(p).namelist() if n.startswith("profiles/audit/")][0]
evts = [json.loads(l) for l in zipfile.ZipFile(p).read(fname).decode().strip().split("\n")]
evts = [e for e in evts if e.get("n") != 1]
prev = "0"*64; out = []
for e in evts:
    base = {k: v for k, v in e.items() if k not in ("sha256",)}
    base["prev_sha256"] = prev
    payload = json.dumps(base, ensure_ascii=False, separators=(",", ":")).encode()
    e["prev_sha256"] = prev; e["sha256"] = hashlib.sha256(payload).hexdigest()
    line = json.dumps(e, ensure_ascii=False)
    prev = hashlib.sha256(line.encode()).hexdigest()
    out.append(line)
zip_patch(p, fname, ("\n".join(out) + "\n").encode())
check("cadena recalculada pasa el check interno (limite del chain sin clave)",
      verify_audit_chain(p)["ok"])
rep = verify_container(p, kp.public_hex)
det = rep["audit"]["detail"][fname]
check("Ed25519 SI detecta la reescritura", not rep["valid"] and det["status"] == "history_rewritten",
      det["status"])

print("\n== T6: splice de side-car entre contenedores (AD v2) ==")
pa_, pb = fresh("t6a"), fresh("t6b")
encrypt_columns_in_surx(pa_, ["dni"], "clave123")
encrypt_columns_in_surx(pb, ["dni"], "clave123")   # misma passphrase, otro contenedor
sc = [n for n in zipfile.ZipFile(pa_).namelist() if n.startswith("enc/")][0]
blob_a = zipfile.ZipFile(pa_).read(sc)
# trasplante: side-car de A dentro de B (mantengo el meta de B; solo cambio el blob)
zip_patch(pb, sc, blob_a)
try:
    surframe.read(pb, columns=["dni"], passphrase="clave123")
    check("side-car trasplantado rechazado", False)
except (CorruptCiphertext, ValueError):
    check("side-car trasplantado rechazado", True)

print("\n== T7: compat hacia atras - contenedor cifrado por 0.1.5 (meta v1) ==")
# Genera un side-car formato v1 real (AD legacy 'part|col', N=2^14, meta sin 'check')
def make_legacy_v1(path, col, pw):
    import io as _io, re as _re
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AG
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as _Sc
    import pyarrow as _pa, pyarrow.parquet as _pq
    salt = os.urandom(16)
    key = _Sc(salt=salt, length=32, n=2**14, r=8, p=1).derive(pw.encode())
    aes = _AG(key)
    zin = zipfile.ZipFile(path); data = {n: zin.read(n) for n in zin.namelist()}; zin.close()
    parts = {}
    for name in list(data):
        if name.startswith("chunks/") and name.endswith(".parquet"):
            pid = _re.search(r"part-(\d+)", name).group(1)
            df = _pq.read_table(_io.BytesIO(data[name])).to_pandas()
            if col not in df.columns:
                continue
            cbuf = _io.BytesIO(); _pq.write_table(_pa.Table.from_pandas(pd.DataFrame({col: df[col]}), preserve_index=False), cbuf)
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, cbuf.getvalue(), associated_data=f"part:{pid}|col:{col}".encode())
            data[f"enc/part-{pid}/{col}.bin"] = nonce + ct
            parts.setdefault(pid, []).append(col)
            obuf = _io.BytesIO(); _pq.write_table(_pa.Table.from_pandas(df.drop(columns=[col]), preserve_index=False), obuf)
            data[name] = obuf.getvalue()
    data["config/crypto.json"] = json.dumps({  # meta v1: sin version/aad_v/check
        "algo": "AESGCM", "kdf": "scrypt",
        "scrypt": {"n": 2**14, "r": 8, "p": 1, "salt": salt.hex()},
        "nonce_size": 12, "columns": [col], "parts": parts,
    }).encode()
    with zipfile.ZipFile(path, "w") as z:
        [z.writestr(n, d) for n, d in data.items()]

p = fresh("t7")
make_legacy_v1(p, "dni", "legacy_pw")
df = surframe.read(p, columns=["dni"], passphrase="legacy_pw")
check("lee side-cars v1 (AD legacy, N=2^14)", df["dni"].iloc[3] == "D00003")
encrypt_columns_in_surx(p, ["salario"], "legacy_pw")           # extiende contenedor v1
df = surframe.read(p, columns=["dni", "salario"], passphrase="legacy_pw")
check("extiende v1 sin romper lo viejo", df["dni"].iloc[3] == "D00003"
      and float(df["salario"].iloc[3]) == 1003.0)
meta = json.loads(zipfile.ZipFile(p).read("config/crypto.json"))
check("upgrade a v2 con verificador, AD sigue v1", meta["version"] == 2
      and meta["aad_v"] == 1 and "check" in meta)
try:
    encrypt_columns_in_surx(p, ["nota"], "otra")
    check("v1 extendido tambien rechaza passphrase mala", False)
except WrongPassphrase:
    check("v1 extendido tambien rechaza passphrase mala", True)

print("\n== T8: decrypt_columns_in_surx (nuevo) ==")
p = fresh("t8")
encrypt_columns_in_surx(p, ["dni", "salario"], "clave123")
decrypt_columns_in_surx(p, ["dni"], "clave123")
with zipfile.ZipFile(p) as zf:
    _names = zf.namelist()
check("side-car de dni eliminado", not any("dni.bin" in n for n in _names))
df = surframe.read(p, columns=["dni"])          # sin passphrase: ya es plano
check("dni vuelve a texto plano", df["dni"].iloc[5] == "D00005")
df = surframe.read(p, columns=["salario"], passphrase="clave123")
check("salario sigue cifrado y legible", float(df["salario"].iloc[5]) == 1005.0)

print("\n== T9: concurrencia - 2 procesos x 10 appends de auditoria ==")
p = fresh("t9")
append_audit_event(p, {"op": "init"})
# El helper se ejecuta como subproceso: inyectamos REPO_ROOT y el path del
# contenedor con repr() para que sean literales Python validos en cualquier SO
# (en Windows los backslashes reventaban como secuencias de escape).
code = (
    "import sys, os\n"
    f"sys.path.insert(0, {REPO_ROOT!r})\n"
    'os.environ["SURX_AUDIT_SIGN"] = "1"\n'
    "from surframe import append_audit_event\n"
    "for i in range(10):\n"
    f"    append_audit_event({p!r}, {{'op': 'w', 'proc': sys.argv[1], 'i': i}})\n"
)
open(f"{WORK}/w.py", "w").write(code)
import subprocess
procs = [subprocess.Popen([sys.executable, f"{WORK}/w.py", str(k)]) for k in (1, 2)]
[pr.wait() for pr in procs]
rep = verify_audit_chain(p)
check("21 eventos presentes (0 perdidos)", rep["total_events"] == 21,
      f"total={rep['total_events']}")
check("cadena valida tras escritura concurrente", rep["ok"])

print("\n== T10: sin columna 'country' (fix del requisito MVP) ==")
p = f"{WORK}/t10.surx"
df10 = pd.DataFrame({"user_id": range(60), "api_key": [f"sk-{i:04d}" for i in range(60)],
                     "latency_ms": [10.0 + i for i in range(60)]})
surframe.write(df10, p)                                  # en 0.1.5: ValueError
with zipfile.ZipFile(p) as zf:                           # cerrar antes de encrypt:
    _names = zf.namelist()                              # en Windows, os.replace falla
    _manifest = json.loads(zf.read("manifest.json"))    # si el .surx sigue abierto
check("escribe sin particion", any(n.startswith("chunks/") for n in _names))
check("manifest sin particiones", _manifest["partitions"] == [])
encrypt_columns_in_surx(p, ["api_key"], "pw")
kp = generate_keypair(); sign_container(p, kp.private_hex)
check("sign+verify sin particion", verify_container(p, kp.public_hex)["valid"])
out = surframe.read(p, columns=["user_id", "api_key"], passphrase="pw")
check("lee cifrado sin particion", out["api_key"].iloc[9] == "sk-0009" and len(out) == 60)

print("\n== T11: partition_by con columna arbitraria + pruning ==")
p = f"{WORK}/t11.surx"
df11 = pd.DataFrame({"model": ["gpt", "claude", "llama"] * 20,
                     "score": [0.5 + i * 0.001 for i in range(60)]})
surframe.write(df11, p, partition_by=["model"])
with zipfile.ZipFile(p) as zf:
    _names = zf.namelist()
check("chunks por model=", any("model=claude" in n for n in _names))
check("bloom con nombre dinamico", "indexes/model.bloom.json" in _names)
pl = surframe.plan(p, where="model == 'claude'")
check("pruning por columna custom (1 de 3 chunks)",
      pl["candidates_count"] == 1 and "model=claude" in pl["candidate_paths"][0],
      f"count={pl['candidates_count']}")
check("plan reporta la columna real", "model" in pl["candidates_by_col"])
out = surframe.read(p, where="model == 'claude'")
check("read filtrado correcto", len(out) == 20 and set(out["model"]) == {"claude"})
out_all = surframe.read(p)
check("read completo 3 particiones", len(out_all) == 60)

print("\n== T12: zips ambiguos/peligrosos rechazados (ataque de doble entrada) ==")
p = fresh("t12")
kp = generate_keypair()
sign_container(p, kp.private_hex)
raw = open(p, "rb").read()
import zipfile as _z, io as _io
buf = _io.BytesIO(raw)
with _z.ZipFile(buf, "a") as z:   # duplicar manifest con contenido distinto
    z.writestr("manifest.json", b'{"evil": true}')
open(p, "wb").write(buf.getvalue())
rep = verify_container(p, kp.public_hex)
check("verify rechaza entrada duplicada", not rep["valid"]
      and "duplicada" in (rep["reason"] or ""), rep["reason"])
try:
    sign_container(p, kp.private_hex)
    check("sign se niega sobre zip ambiguo", False)
except ValueError:
    check("sign se niega sobre zip ambiguo", True)

print("\n== T13: contenedor corrupto a nivel deflate no crashea verify_container ==")
# Regresion 0.3.1: un byte volteado DENTRO del stream comprimido de una entrada
# firmada dejaba el directorio central intacto (ZipFile abre) pero zf.read()
# tiraba zlib.error/BadZipFile crudo. verify_container ahora lo envuelve.
p = fresh("t13")
kp = generate_keypair()
sign_container(p, kp.private_hex, signer="t13")
with zipfile.ZipFile(p) as _zf:
    _tgt = next(zi for zi in _zf.infolist()
                if zi.filename.endswith(".parquet")
                and zi.compress_type == zipfile.ZIP_DEFLATED
                and zi.compress_size > 60)
_raw = bytearray(open(p, "rb").read())
_lh = _tgt.header_offset
_nl = int.from_bytes(_raw[_lh + 26:_lh + 28], "little")
_el = int.from_bytes(_raw[_lh + 28:_lh + 30], "little")
_body = _lh + 30 + _nl + _el
_raw[_body + _tgt.compress_size // 2] ^= 0xFF   # flip en medio del deflate
open(p, "wb").write(_raw)
_crashed = False
try:
    rep = verify_container(p, kp.public_hex)
except Exception as _e:   # noqa: BLE001 — cualquier excepcion cruda = regresion
    _crashed = True
    rep = {"valid": None, "reason": f"CRASH {type(_e).__name__}: {_e}"}
check("verify no tira traceback sobre deflate corrupto", not _crashed, rep["reason"])
check("verify devuelve reporte limpio invalido",
      (not _crashed) and rep["valid"] is False and "unreadable" in (rep["reason"] or ""),
      rep["reason"])

print("\n" + "="*60)
print(f"RESULTADO: {len(PASS)} PASS / {len(FAIL)} FAIL")
if FAIL:
    print("FALLARON:", FAIL); sys.exit(1)
print("Todos los fixes demostrados.")
