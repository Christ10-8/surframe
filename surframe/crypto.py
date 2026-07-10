# Copyright 2025 Christ10-8
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -*- coding: utf-8 -*-
"""
Cifrado por columna (AES-GCM) con side-cars para SURFRAME.

v2 (0.2.0):
- Multi-llamada segura: encrypt_columns_in_surx() reutiliza salt/clave existentes
  y FUSIONA el meta en vez de pisarlo (bug de perdida de datos en 0.1.5).
- Verificador de passphrase ("check"): detecta passphrase equivocada ANTES de
  cifrar nada, y distingue "passphrase incorrecta" de "datos corruptos".
- AD v2 ata la identidad del contenedor (container_id) ademas de part|col:
  un side-car no se puede trasplantar entre contenedores.
- Scrypt N=2**17 (OWASP) para contenedores nuevos; los viejos se leen con los
  parametros guardados en su config/crypto.json.
- Reescritura atomica con fsync (archivo tmp + directorio).
- decrypt_columns_in_surx(): revierte columnas a texto plano.
"""
from __future__ import annotations

import io
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional
from zipfile import ZipFile, ZIP_DEFLATED

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

CRYPTO_CONFIG_PATH = "config/crypto.json"
ENC_DIR = "enc"
NONCE_SIZE = 12   # bytes
SALT_SIZE = 16    # bytes
SCRYPT_N_DEFAULT = 2**17  # OWASP 2024+ para cifrado at-rest (antes 2**14)
_CHECK_PLAINTEXT = b"surframe-passphrase-check-v2"


class WrongPassphrase(ValueError):
    """La passphrase no coincide con la usada para cifrar este contenedor."""


class CorruptCiphertext(ValueError):
    """Passphrase verificada pero el side-car no autentica: datos alterados."""


@dataclass
class CryptoMeta:
    algo: str
    kdf: str
    scrypt_n: int
    scrypt_r: int
    scrypt_p: int
    salt_hex: str
    columns: List[str]
    parts: Dict[str, List[str]]        # part_id -> [cols]
    version: int = 2
    aad_v: int = 2                      # 1 = "part|col" (legacy), 2 = "sf|part|col"
    container_id: str = ""              # ata side-cars a ESTE contenedor (aad_v=2)
    check_nonce_hex: str = ""           # verificador de passphrase
    check_ct_hex: str = ""

    def to_dict(self) -> dict:
        d = {
            "version": self.version,
            "algo": self.algo,
            "kdf": self.kdf,
            "scrypt": {
                "n": self.scrypt_n,
                "r": self.scrypt_r,
                "p": self.scrypt_p,
                "salt": self.salt_hex,
            },
            "nonce_size": NONCE_SIZE,
            "aad_v": self.aad_v,
            "columns": self.columns,
            "parts": self.parts,
        }
        if self.container_id:
            d["container_id"] = self.container_id
        if self.check_nonce_hex and self.check_ct_hex:
            d["check"] = {"nonce": self.check_nonce_hex, "ct": self.check_ct_hex}
        return d


# -------------------- helpers --------------------

def _derive_key(passphrase: bytes, salt: bytes, *, n: int = SCRYPT_N_DEFAULT, r: int = 8, p: int = 1) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(passphrase)


def _get_chunk_id_from_path(p: str) -> str:
    m = re.search(r"part-(\d+)\.parquet$", p)
    return m.group(1) if m else p


def _list_chunk_paths(zf: ZipFile) -> List[str]:
    return [n for n in zf.namelist() if n.startswith("chunks/") and n.endswith(".parquet")]


def _read_parquet_from_zip(zf: ZipFile, name: str) -> pd.DataFrame:
    with zf.open(name, "r") as f:
        buf = io.BytesIO(f.read())
    return pq.read_table(buf).to_pandas()


def _write_parquet_to_bytes(df: pd.DataFrame) -> bytes:
    table = pa.Table.from_pandas(df, preserve_index=False)
    out = io.BytesIO()
    pq.write_table(table, out)
    return out.getvalue()


def _fsync_dir(dirpath: str) -> None:
    try:
        dfd = os.open(dirpath, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass  # algunos FS (Windows/red) no soportan fsync de directorio


def _rewrite_zip_with_replacements(
    src_path: str,
    *,
    replacements: Dict[str, bytes],
    additions: Dict[str, bytes],
    deletions: Optional[Iterable[str]] = None,
) -> None:
    """Reescribe el .surx de forma atomica y DURABLE:
    tmp en la misma carpeta + fsync(tmp) + os.replace + fsync(dir).
    Sin el fsync, un corte de energia tras el rename puede dejar un zip vacio/corrupto.
    """
    dst_dir = os.path.dirname(os.path.abspath(src_path)) or "."
    del_set = set(deletions or ())
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".surx.tmp", dir=dst_dir)
    try:
        with os.fdopen(tmp_fd, "wb") as tmp_f:
            with ZipFile(src_path, "r") as zsrc, ZipFile(tmp_f, "w", compression=ZIP_DEFLATED) as zdst:
                skip_names = set(replacements.keys()) | set(additions.keys()) | del_set
                for name in zsrc.namelist():
                    if name in skip_names:
                        continue
                    zdst.writestr(name, zsrc.read(name))
                for name, data in {**replacements, **additions}.items():
                    zdst.writestr(name, data)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        os.replace(tmp_path, src_path)
        _fsync_dir(dst_dir)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def _make_ad(meta: CryptoMeta, part_id: str, col: str) -> bytes:
    if meta.aad_v >= 2 and meta.container_id:
        return f"sf:{meta.container_id}|part:{part_id}|col:{col}".encode()
    return f"part:{part_id}|col:{col}".encode()  # legacy v1


def _check_ad(meta: CryptoMeta) -> bytes:
    return f"sf-check:{meta.container_id}".encode()


def _verify_passphrase(meta: CryptoMeta, key: bytes) -> None:
    """Valida la passphrase contra el campo 'check'. WrongPassphrase si no coincide."""
    if not (meta.check_nonce_hex and meta.check_ct_hex):
        return  # meta v1: no hay verificador (se valida al primer decrypt)
    aes = AESGCM(key)
    try:
        aes.decrypt(bytes.fromhex(meta.check_nonce_hex),
                    bytes.fromhex(meta.check_ct_hex),
                    associated_data=_check_ad(meta))
    except InvalidTag:
        raise WrongPassphrase(
            "Passphrase incorrecta: no coincide con la usada al cifrar este contenedor."
        )


# -------------------- API principal --------------------

def encrypt_columns_in_surx(path: str, cols: Iterable[str], passphrase: str) -> None:
    """Cifra columnas y las mueve a side-cars AES-GCM.

    Seguro para llamadas multiples: si el contenedor ya tiene columnas cifradas,
    reutiliza la MISMA clave (verificando la passphrase primero) y fusiona el meta.
    En 0.1.5 la segunda llamada regeneraba el salt y pisaba config/crypto.json,
    dejando indescifrables las columnas de la primera llamada.
    """
    cols = list(dict.fromkeys([c.strip() for c in cols if c and c.strip()]))
    if not cols:
        raise ValueError("No se especificaron columnas a cifrar")

    with ZipFile(path, "r") as zf:
        meta = load_crypto_meta(zf)

        if meta is not None:
            # ---- contenedor ya cifrado: reusar clave, verificar passphrase ----
            salt = bytes.fromhex(meta.salt_hex)
            key = _derive_key(passphrase.encode("utf-8"), salt,
                              n=meta.scrypt_n, r=meta.scrypt_r, p=meta.scrypt_p)
            if meta.check_nonce_hex:
                _verify_passphrase(meta, key)
            else:
                # meta v1 sin verificador: probar contra un side-car existente
                _probe_legacy_passphrase(zf, meta, key)
                # upgrade in-place del meta (mantiene aad_v=1 por compat con side-cars viejos)
                meta.version = 2
                if not meta.container_id:
                    meta.container_id = uuid.uuid4().hex
                nonce = os.urandom(NONCE_SIZE)
                ct = AESGCM(key).encrypt(nonce, _CHECK_PLAINTEXT, associated_data=_check_ad(meta))
                meta.check_nonce_hex, meta.check_ct_hex = nonce.hex(), ct.hex()
            already = [c for c in cols if c in meta.columns]
            cols = [c for c in cols if c not in meta.columns]
            if already and not cols:
                return  # todo ya estaba cifrado: no-op idempotente
        else:
            # ---- primer cifrado: meta v2 nuevo ----
            salt = os.urandom(SALT_SIZE)
            key = _derive_key(passphrase.encode("utf-8"), salt)
            meta = CryptoMeta(
                algo="AESGCM", kdf="scrypt",
                scrypt_n=SCRYPT_N_DEFAULT, scrypt_r=8, scrypt_p=1,
                salt_hex=salt.hex(), columns=[], parts={},
                version=2, aad_v=2, container_id=uuid.uuid4().hex,
            )
            nonce = os.urandom(NONCE_SIZE)
            ct = AESGCM(key).encrypt(nonce, _CHECK_PLAINTEXT, associated_data=_check_ad(meta))
            meta.check_nonce_hex, meta.check_ct_hex = nonce.hex(), ct.hex()

        aes = AESGCM(key)
        chunk_paths = _list_chunk_paths(zf)
        additions: Dict[str, bytes] = {}
        replacements: Dict[str, bytes] = {}
        new_parts: Dict[str, List[str]] = {}

        for cp in chunk_paths:
            part_id = _get_chunk_id_from_path(cp)
            df = _read_parquet_from_zip(zf, cp)
            present_cols = [c for c in cols if c in df.columns]
            if not present_cols:
                continue
            for col in present_cols:
                col_df = pd.DataFrame({col: df[col]})
                plain = _write_parquet_to_bytes(col_df)
                nonce = os.urandom(NONCE_SIZE)
                ct = aes.encrypt(nonce, plain, associated_data=_make_ad(meta, part_id, col))
                additions[f"{ENC_DIR}/part-{part_id}/{col}.bin"] = nonce + ct
                new_parts.setdefault(part_id, []).append(col)
            df_drop = df.drop(columns=present_cols)
            replacements[cp] = _write_parquet_to_bytes(df_drop)

        encrypted_now = sorted({c for cl in new_parts.values() for c in cl})
        if not encrypted_now:
            raise ValueError("Ninguna de las columnas especificadas estaba en texto plano para cifrar.")

        # ---- FUSION (no pisar): union de columnas y parts ----
        meta.columns = sorted(set(meta.columns) | set(encrypted_now))
        for pid, cl in new_parts.items():
            merged = set(meta.parts.get(pid, [])) | set(cl)
            meta.parts[pid] = sorted(merged)

        replacements_or_add = additions
        payload = json.dumps(meta.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")
        if CRYPTO_CONFIG_PATH in zf.namelist():
            replacements[CRYPTO_CONFIG_PATH] = payload
        else:
            replacements_or_add[CRYPTO_CONFIG_PATH] = payload

    _rewrite_zip_with_replacements(path, replacements=replacements, additions=additions)


def _probe_legacy_passphrase(zf: ZipFile, meta: CryptoMeta, key: bytes) -> None:
    """Meta v1 sin 'check': valida la passphrase intentando descifrar un side-car real."""
    aes = AESGCM(key)
    for pid, cl in meta.parts.items():
        for col in cl:
            name = f"{ENC_DIR}/part-{pid}/{col}.bin"
            if name in zf.namelist():
                blob = zf.read(name)
                try:
                    aes.decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:],
                                associated_data=_make_ad(meta, pid, col))
                    return
                except InvalidTag:
                    raise WrongPassphrase(
                        "Passphrase incorrecta: no coincide con la usada al cifrar este contenedor."
                    )
    # no hay side-cars que probar: continuar (contenedor cifrado vacio)


def decrypt_columns_in_surx(path: str, cols: Iterable[str], passphrase: str) -> None:
    """Revierte columnas cifradas a texto plano dentro de los chunks y elimina side-cars."""
    cols = list(dict.fromkeys([c.strip() for c in cols if c and c.strip()]))
    with ZipFile(path, "r") as zf:
        meta = load_crypto_meta(zf)
        if meta is None:
            raise ValueError("El contenedor no tiene columnas cifradas.")
        target = [c for c in cols if c in meta.columns] if cols else list(meta.columns)
        if not target:
            raise ValueError("Ninguna de las columnas indicadas esta cifrada.")

        salt = bytes.fromhex(meta.salt_hex)
        key = _derive_key(passphrase.encode("utf-8"), salt,
                          n=meta.scrypt_n, r=meta.scrypt_r, p=meta.scrypt_p)
        _verify_passphrase(meta, key)
        aes = AESGCM(key)

        replacements: Dict[str, bytes] = {}
        deletions: List[str] = []
        for cp in _list_chunk_paths(zf):
            pid = _get_chunk_id_from_path(cp)
            here = [c for c in target if f"{ENC_DIR}/part-{pid}/{c}.bin" in zf.namelist()]
            if not here:
                continue
            df = _read_parquet_from_zip(zf, cp)
            for col in here:
                name = f"{ENC_DIR}/part-{pid}/{col}.bin"
                blob = zf.read(name)
                try:
                    plain = aes.decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:],
                                        associated_data=_make_ad(meta, pid, col))
                except InvalidTag:
                    raise CorruptCiphertext(f"Side-car alterado o trasplantado: {name}")
                col_df = pq.read_table(io.BytesIO(plain)).to_pandas()
                df[col] = col_df[col].values
                deletions.append(name)
            replacements[cp] = _write_parquet_to_bytes(df)

        meta.columns = sorted(set(meta.columns) - set(target))
        meta.parts = {pid: [c for c in cl if c not in target]
                      for pid, cl in meta.parts.items()}
        meta.parts = {pid: cl for pid, cl in meta.parts.items() if cl}
        replacements[CRYPTO_CONFIG_PATH] = json.dumps(
            meta.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")

    _rewrite_zip_with_replacements(path, replacements=replacements, additions={}, deletions=deletions)


def load_crypto_meta(zf: ZipFile) -> CryptoMeta | None:
    if CRYPTO_CONFIG_PATH not in zf.namelist():
        return None
    data = json.loads(zf.read(CRYPTO_CONFIG_PATH))
    s = data.get("scrypt", {})
    chk = data.get("check", {}) or {}
    return CryptoMeta(
        algo=data.get("algo", "AESGCM"),
        kdf=data.get("kdf", "scrypt"),
        scrypt_n=int(s.get("n", 2**14)),
        scrypt_r=int(s.get("r", 8)),
        scrypt_p=int(s.get("p", 1)),
        salt_hex=str(s.get("salt")),
        columns=list(data.get("columns", [])),
        parts={k: list(v) for k, v in (data.get("parts", {}) or {}).items()},
        version=int(data.get("version", 1)),
        aad_v=int(data.get("aad_v", 1)),
        container_id=str(data.get("container_id", "") or ""),
        check_nonce_hex=str(chk.get("nonce", "") or ""),
        check_ct_hex=str(chk.get("ct", "") or ""),
    )


def rehydrate_chunk_columns(
    zf: ZipFile,
    df_chunk: pd.DataFrame,
    chunk_path: str,
    *,
    passphrase: str,
    want_cols: Iterable[str] | None,
) -> pd.DataFrame:
    meta = load_crypto_meta(zf)
    if not meta:
        return df_chunk

    salt = bytes.fromhex(meta.salt_hex)
    key = _derive_key(passphrase.encode("utf-8"), salt,
                      n=meta.scrypt_n, r=meta.scrypt_r, p=meta.scrypt_p)
    _verify_passphrase(meta, key)  # con meta v2: error preciso ANTES de tocar side-cars
    aes = AESGCM(key)

    part_id = _get_chunk_id_from_path(chunk_path)
    want = set(want_cols or meta.columns)
    cols_here = {c for c in want if f"enc/part-{part_id}/{c}.bin" in zf.namelist()}
    if not cols_here:
        return df_chunk

    out = df_chunk.copy()
    for col in cols_here:
        enc_name = f"enc/part-{part_id}/{col}.bin"
        blob = zf.read(enc_name)
        nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
        try:
            plain = aes.decrypt(nonce, ct, associated_data=_make_ad(meta, part_id, col))
        except InvalidTag:
            if meta.check_nonce_hex:
                raise CorruptCiphertext(
                    f"Passphrase correcta pero '{enc_name}' no autentica: "
                    "datos alterados o side-car de otro contenedor.")
            raise ValueError("Passphrase incorrecta o datos cifrados corruptos")
        col_df = pq.read_table(io.BytesIO(plain)).to_pandas()
        if col not in col_df.columns or len(col_df) != len(out):
            raise ValueError(f"Side-car invalido para {col}")
        out[col] = col_df[col].values
    return out
