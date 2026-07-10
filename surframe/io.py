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


from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import hashlib
import io
import json
import os
import posixpath
import re
import time
import getpass
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

from .crypto import load_crypto_meta, rehydrate_chunk_columns, encrypt_columns_in_surx
from .audit import append_audit_event

import numpy as _np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from .indexes.bloom import Bloom
from .indexes.hll import HLL

# === Nivel 4: Optimize (compact + order) y Planner PLUS =====================
from datetime import timezone as _tz
import io as _io
import json as _json
import re as _re
import zipfile as _zip
import math as _math
import pandas as _pd
import pyarrow as _pa
import pyarrow.parquet as _pq
import hashlib as _hashlib  # para _bloom_maybe

# -------------------- helpers generales --------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _posix_join(*parts: str) -> str:
    return posixpath.join(*parts)

def _basename_wo_ext(path: str) -> str:
    return Path(path).stem

def _ensure_ts_utc_series(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s, utc=True)

def _iso(ts: pd.Timestamp) -> str:
    return pd.to_datetime(ts, utc=True).isoformat()

def _infer_or_load_manifest_schema(schema: Optional[Dict[str, Any]], df: pd.DataFrame) -> Dict[str, Any]:
    if schema:
        return schema
    def arrow_type_of(pd_dtype: Any) -> str:
        if pd.api.types.is_datetime64_any_dtype(pd_dtype):
            return "timestamp[us, UTC]"
        if pd.api.types.is_integer_dtype(pd_dtype):
            return "int64"
        if pd.api.types.is_float_dtype(pd_dtype):
            return "float64"
        return "utf8"
    sch = []
    for c in df.columns:
        sch.append({"name": c, "arrow_type": arrow_type_of(df[c].dtype)})
    return {
        "version": 1,
        "name": "dataset",
        "schema": sch,
        "primary_key": None,
        "partitions": [{"by": "country"}] if "country" in df.columns else [],
        "indexes": {},
    }

def _zip_write_json(zf: ZipFile, path: str, obj: Any) -> None:
    zf.writestr(path, json.dumps(obj, ensure_ascii=False, indent=2))

def _zip_list(zf: ZipFile, prefix: str) -> List[str]:
    return [n for n in zf.namelist() if n.startswith(prefix)]

def _read_json_from_zip(zf: ZipFile, path: str) -> Any:
    with zf.open(path) as f:
        return json.loads(f.read().decode("utf-8"))

def _fsync_file_and_dir(file_path: str) -> None:
    """(0.2.0) Durabilidad: fsync del archivo y su directorio antes/despues del rename."""
    try:
        fd = os.open(file_path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
    try:
        dfd = os.open(os.path.dirname(os.path.abspath(file_path)) or ".", os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass

def _zip_replace_file(zip_path: str, inner_path: str, data: bytes) -> None:
    tmp_path = zip_path + ".tmp"
    with ZipFile(zip_path, "r") as zfin, ZipFile(tmp_path, "w", compression=ZIP_DEFLATED) as zfout:
        for info in zfin.infolist():
            if info.filename == inner_path:
                continue
            with zfin.open(info.filename) as src:
                zfout.writestr(info.filename, src.read())
        zfout.writestr(inner_path, data)
    _fsync_file_and_dir(tmp_path)
    os.replace(tmp_path, zip_path)
    _fsync_file_and_dir(zip_path)

def _zip_write_json_replace(zip_path: str, inner_path: str, obj: Any) -> None:
    _zip_replace_file(zip_path, inner_path, json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8"))

def _read_last_json_from_zip(zf: ZipFile, path: str) -> Any:
    matches = [i for i in zf.infolist() if i.filename == path]
    if not matches:
        raise FileNotFoundError(path)
    with zf.open(matches[-1]) as f:
        return json.loads(f.read().decode("utf-8"))

def _compute_manifest_hash(zf: ZipFile) -> str:
    data = json.dumps(_read_json_from_zip(zf, "manifest.json"), ensure_ascii=False).encode("utf-8")
    h = hashlib.sha256(data).hexdigest()
    return f"sha256:{h}"


# -------------------- Escritura (.surx) --------------------

@dataclass
class _ChunkInfo:
    chunk_id: str
    path_in_zip: str
    country: str
    ts_min_iso: Optional[str]
    ts_max_iso: Optional[str]
    nrows: int
    file_size: int  # bytes comprimidos

def _build_bloom_for_values(values: Iterable[str], fp_rate: float = 0.01) -> Bloom:
    vals = {str(v) for v in values if v is not None}
    bloom = Bloom.with_fp_rate(n=max(1, len(vals)), fp_rate=fp_rate)
    for v in vals:
        bloom.add(v)
    return bloom

def _serialize_bloom(b: Bloom) -> Dict[str, Any]:
    return {"m": b.m, "k": b.k, "bits_hex": b.bits.hex()}

def _deserialize_bloom(d: Dict[str, Any]) -> Bloom:
    return Bloom(m=d["m"], k=d["k"], bits=bytearray.fromhex(d["bits_hex"]))

def _build_indexes_entries(chunk_infos: List[_ChunkInfo], blooms: Dict[str, Bloom], bloom_col: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    minmax_entries: List[Dict[str, Any]] = []
    for c in chunk_infos:
        if c.ts_min_iso is None or c.ts_max_iso is None:
            continue
        minmax_entries.append({"chunk_id": c.chunk_id, "path": c.path_in_zip, "min": c.ts_min_iso, "max": c.ts_max_iso})
    minmax_index = {"version": 1, "column": "ts", "index": "minmax", "entries": minmax_entries}

    bloom_entries: List[Dict[str, Any]] = []
    for cid, b in blooms.items():
        ch = next(ci for ci in chunk_infos if ci.chunk_id == cid)
        bloom_entries.append({"chunk_id": cid, "path": ch.path_in_zip, "bloom": _serialize_bloom(b)})
    bloom_index = {"version": 1, "column": bloom_col or "country", "index": "bloom", "entries": bloom_entries}
    return minmax_index, bloom_index


def write(
    source: Union[str, pd.DataFrame],
    out_path: str,
    schema: Optional[Dict[str, Any]] = None,
    partition_by: Optional[List[str]] = None,
    indexes: Optional[Dict[str, Dict[str, Any]]] = None,
    fmt: str = "surx",
    auto_snapshot: bool = True,
) -> None:
    """Convierte CSV/Parquet/DataFrame a contenedor .surx con índices básicos."""
    if isinstance(source, str):
        if source.lower().endswith(".csv"):
            df = pd.read_csv(source)
        elif source.lower().endswith(".parquet"):
            df = pd.read_parquet(source)
        else:
            raise ValueError("Fuente no soportada. Use CSV/Parquet/DataFrame.")
    else:
        df = source.copy()

    # (0.2.0) Particionado generico: partition_by[0] > 'country' si existe > sin particion.
    part_col: Optional[str] = None
    if partition_by:
        part_col = partition_by[0]
        if part_col not in df.columns:
            raise ValueError(f"Columna de particion '{part_col}' no existe en los datos.")
    elif "country" in df.columns:
        part_col = "country"
    # 'ts' es opcional: si existe, construimos minmax; si no, seguimos sin error.
    has_ts = "ts" in df.columns
    if has_ts:
        df["ts"] = _ensure_ts_utc_series(df["ts"])

    manifest = _infer_or_load_manifest_schema(schema, df)
    manifest["name"] = _basename_wo_ext(out_path)

    # Índices por defecto sólo si indexes es None
    if indexes is None:
        idx_default: Dict[str, List[str]] = ({part_col: ["bloom"]} if part_col else {})
        if has_ts:
            idx_default["ts"] = ["minmax"]
        manifest["indexes"] = manifest.get("indexes") or idx_default
    else:
        manifest["indexes"] = manifest.get("indexes") or indexes

    manifest["partitions"] = [{"by": part_col}] if part_col else []
    manifest["created_at"] = _now_iso()

    chunk_infos: List[_ChunkInfo] = []
    blooms: Dict[str, Bloom] = {}

    with ZipFile(out_path, mode="w", compression=ZIP_DEFLATED) as zf:
        part_counter = 0
        groups = df.groupby(part_col, sort=True) if part_col else [(None, df)]
        for pval, g in groups:
            g_sorted = g.sort_values("ts") if has_ts else g
            table = pa.Table.from_pandas(g_sorted, preserve_index=False)
            buf = io.BytesIO()
            pq.write_table(table, buf, compression="zstd")
            data = buf.getvalue()

            chunk_id = f"{part_counter:06d}"
            rel_dir = _posix_join("chunks", f"{part_col}={pval}") if part_col else "chunks"
            rel_name = f"part-{chunk_id}.parquet"
            rel_path = _posix_join(rel_dir, rel_name)
            zf.writestr(rel_path, data)

            if has_ts:
                ts_min = g_sorted["ts"].min()
                ts_max = g_sorted["ts"].max()
                ts_min_iso = _iso(ts_min)
                ts_max_iso = _iso(ts_max)
            else:
                ts_min_iso = None
                ts_max_iso = None

            ci = _ChunkInfo(
                chunk_id=chunk_id,
                path_in_zip=rel_path,
                country=str(pval) if part_col else "",
                ts_min_iso=ts_min_iso,
                ts_max_iso=ts_max_iso,
                nrows=len(g_sorted),
                file_size=len(data),
            )
            chunk_infos.append(ci)

            if part_col:
                blooms[chunk_id] = _build_bloom_for_values([pval], fp_rate=(indexes or {}).get(part_col, {}).get("bloom", {}).get("fp_rate", 0.01))
            part_counter += 1

        minmax_idx, bloom_idx = _build_indexes_entries(chunk_infos, blooms, bloom_col=part_col)
        # Escribimos bloom siempre; minmax sólo si hay 'ts'
        if has_ts and minmax_idx.get("entries"):
            _zip_write_json(zf, _posix_join("indexes", "ts.minmax.json"), minmax_idx)
        if part_col and bloom_idx.get("entries"):
            _zip_write_json(zf, _posix_join("indexes", f"{part_col}.bloom.json"), bloom_idx)

        _zip_write_json(zf, "manifest.json", manifest)
        _zip_write_json(zf, _posix_join("profiles", "quality.json"), {"version": 1, "rows": int(df.shape[0])})

    # Journal: write
    _journal_append(out_path, "write", {"rows": int(df.shape[0]), "chunks": len(chunk_infos)})
    # Snapshot inicial opcional
    if auto_snapshot:
        snapshot(out_path, note="auto after write")


# -------------------- Cifrado de columnas (wrapper público) --------------------

def encrypt(path: str, columns: Iterable[str], passphrase: str) -> None:
    """Cifra columnas (side-cars AES-GCM) y reescribe los chunks sin esas columnas."""
    encrypt_columns_in_surx(path, columns, passphrase)


# -------------------- Lectura con pruning --------------------

# parser where: acepta = y ==
_COND_RE = re.compile(
    r"""^\s*
        (?P<col>[A-Za-z_][A-Za-z0-9_]*)
        \s*(?P<op>==|=|>=|<=|>|<)\s*
        (?P<val>.+?)\s*$""",
    re.VERBOSE,
)

def _split_and(where: str) -> List[str]:
    parts = re.split(r"\s+and\s+", where, flags=re.IGNORECASE)
    return [p.strip() for p in parts if p.strip()]

@dataclass
class _Cond:
    col: str
    op: str
    val: Any

def _parse_value(col: str, raw: str) -> Any:
    s = raw.strip()
    if s.startswith(("'", '"')) and s.endswith(("'", '"')):
        s = s[1:-1]
    if col == "ts":
        return pd.to_datetime(s, utc=True)
    try:
        return float(s) if "." in s or s.isdigit() else s
    except Exception:
        return s

def _parse_where(where: Optional[str]) -> List[_Cond]:
    if not where:
        return []
    conds: List[_Cond] = []
    for seg in _split_and(where):
        m = _COND_RE.match(seg)
        if not m:
            raise ValueError(f"Condición inválida: {seg}")
        col, op, val = m.group("col"), m.group("op"), m.group("val")
        if op == "=":
            op = "=="
        conds.append(_Cond(col=col, op=op, val=_parse_value(col, val)))
    return conds

def _load_index_minmax(zf: ZipFile, allowed_paths: Optional[set[str]] = None) -> Dict[str, Tuple[pd.Timestamp, pd.Timestamp, str]]:
    idx_path = "indexes/ts.minmax.json"
    if allowed_paths is not None and idx_path not in allowed_paths:
        return {}
    if idx_path not in zf.namelist():
        return {}
    raw = _read_json_from_zip(zf, idx_path)
    out: Dict[str, Tuple[pd.Timestamp, pd.Timestamp, str]] = {}
    for e in raw.get("entries", []):
        out[e["chunk_id"]] = (pd.to_datetime(e["min"], utc=True), pd.to_datetime(e["max"], utc=True), e["path"])
    return out

def _load_index_bloom(zf: ZipFile, allowed_paths: Optional[set[str]] = None) -> Tuple[Optional[str], Dict[str, Tuple[Bloom, str]]]:
    """(0.2.0) Columna de particion dinamica: busca indexes/<col>.bloom.json y devuelve (col, entradas)."""
    cands = sorted(n for n in zf.namelist() if n.startswith("indexes/") and n.endswith(".bloom.json"))
    if not cands:
        return None, {}
    idx_path = cands[0]
    if allowed_paths is not None and idx_path not in allowed_paths:
        return None, {}
    raw = _read_json_from_zip(zf, idx_path)
    col = raw.get("column") or "country"
    out: Dict[str, Tuple[Bloom, str]] = {}
    for e in raw.get("entries", []):
        out[e["chunk_id"]] = (_deserialize_bloom(e["bloom"]), e["path"])
    return col, out

def _load_index_minmax_for_col(zf: ZipFile, col: str, allowed_paths: Optional[set[str]] = None) -> Dict[str, Tuple[Any, Any, str]]:
    idx_path = f"indexes/{col}.minmax.json"
    if allowed_paths is not None and idx_path not in allowed_paths:
        return {}
    if idx_path not in zf.namelist():
        return {}
    raw = _read_json_from_zip(zf, idx_path)
    out: Dict[str, Tuple[Any, Any, str]] = {}
    for e in raw.get("entries", []):
        mn, mx = e["min"], e["max"]
        if col == "ts":
            mn = pd.to_datetime(mn, utc=True); mx = pd.to_datetime(mx, utc=True)
        out[e["chunk_id"]] = (mn, mx, e["path"])
    return out

def _cand_from_minmax(conds: List[_Cond], idx_minmax: Dict[str, Tuple[pd.Timestamp, pd.Timestamp, str]]) -> Optional[set[str]]:
    cands: Optional[set[str]] = None
    ts_conds = [c for c in conds if c.col == "ts"]
    if not ts_conds:
        return cands
    res: set[str] = set()
    for cid, (mn, mx, _path) in idx_minmax.items():
        keep = True
        for c in ts_conds:
            v: pd.Timestamp = c.val  # type: ignore
            if c.op == "==":
                if not (mn <= v <= mx): keep = False; break
            elif c.op == ">=":
                if not (mx >= v): keep = False; break
            elif c.op == "<=":
                if not (mn <= v): keep = False; break
            elif c.op == ">":
                if not (mx > v): keep = False; break
            elif c.op == "<":
                if not (mn < v): keep = False; break
        if keep:
            res.add(cid)
    return res

def _cand_from_bloom(conds: List[_Cond], bloom_col: Optional[str], idx_bloom: Dict[str, Tuple[Bloom, str]]) -> Optional[set[str]]:
    if not bloom_col:
        return None
    eq = [c for c in conds if c.col == bloom_col and c.op == "=="]
    if not eq:
        return None
    value = str(eq[-1].val)
    return {cid for cid, (b, _path) in idx_bloom.items() if (value in b)}

def _cand_from_minmax_for_col(conds: List[_Cond], idx: Dict[str, Tuple[Any, Any, str]]) -> Optional[set[str]]:
    if not conds or not idx:
        return None
    res: set[str] = set()
    for cid, (mn, mx, _path) in idx.items():
        keep = True
        for c in conds:
            v = c.val
            try:
                if isinstance(mn, (int, float)) and not isinstance(v, (int, float)):
                    v = float(v)
            except Exception:
                pass
            if c.op == "==":
                if not (mn <= v <= mx): keep = False; break
            elif c.op == ">=":
                if not (mx >= v): keep = False; break
            elif c.op == "<=":
                if not (mn <= v): keep = False; break
            elif c.op == ">":
                if not (mx > v): keep = False; break
            elif c.op == "<":
                if not (mn < v): keep = False; break
        if keep:
            res.add(cid)
    return res

def _intersect_opt(a: Optional[set[str]], b: Optional[set[str]]) -> Optional[set[str]]:
    if a is None:
        return b
    if b is None:
        return a
    return a & b

def _rows_filter(df: pd.DataFrame, conds: List[_Cond]) -> pd.DataFrame:
    if not conds:
        return df
    mask = pd.Series(True, index=df.index)
    for c in conds:
        if c.col not in df.columns:
            continue
        if c.col == "ts":
            colv = pd.to_datetime(df[c.col], utc=True)
            v = c.val
        else:
            colv = df[c.col]
            v = c.val
        if c.op == "==":
            mask &= (colv == v)
        elif c.op == ">=":
            mask &= (colv >= v)
        elif c.op == "<=":
            mask &= (colv <= v)
        elif c.op == ">":
            mask &= (colv > v)
        elif c.op == "<":
            mask &= (colv < v)
        else:
            raise ValueError(f"Operador no soportado: {c.op}")
    return df.loc[mask]


# -------- Snapshots & Journal utilities --------

def _list_snapshot_files(zf: ZipFile) -> List[str]:
    return sorted([n for n in zf.namelist() if n.startswith("snapshots/") and n.endswith(".json")])

def _pick_snapshot_as_of(zf: ZipFile, as_of_iso: str) -> Optional[Dict[str, Any]]:
    try:
        as_of = pd.to_datetime(as_of_iso, utc=True)
    except Exception:
        raise ValueError(f"as_of inválido: {as_of_iso}")
    best = None
    for p in _list_snapshot_files(zf):
        s = _read_json_from_zip(zf, p)
        ts = pd.to_datetime(s.get("ts"), utc=True)
        if ts <= as_of and (best is None or pd.to_datetime(best["ts"], utc=True) < ts):
            best = s
    return best

def _journal_next_id(zf: ZipFile) -> int:
    files = [n for n in zf.namelist() if n.startswith("journal/") and n.endswith(".json")]
    if not files:
        return 1
    ids = []
    for n in files:
        m = re.search(r"journal/(\d+)\.json$", n)
        if m:
            ids.append(int(m.group(1)))
    return (max(ids) + 1) if ids else 1

def _journal_append(zip_path: str, op: str, details: Dict[str, Any]) -> None:
    try:
        with ZipFile(zip_path, "r") as zfr:
            next_id = _journal_next_id(zfr)
        event = {
            "id": next_id,
            "ts": _now_iso(),
            "op": op,
            "details": details or {},
        }
        with ZipFile(zip_path, "a", compression=ZIP_DEFLATED) as zfa:
            path = _posix_join("journal", f"{next_id:06d}.json")
            _zip_write_json(zfa, path, event)
    except Exception:
        pass


# ------------- read (con soporte as_of y columnas cifradas) ----------------

def read(
    path: str,
    columns: Optional[Iterable[str]] = None,
    where: Optional[str] = None,
    as_of: Optional[str] = None,
    passphrase: Optional[str] = None,
    head: Optional[int] = None,
    explain: bool = False,
) -> pd.DataFrame:
    """
    Lee .surx aplicando pruning por índices y proyección de columnas.
    Si se pasa as_of, usa el snapshot más reciente <= as_of para resolver chunks/índices.
    Si el contenedor tiene columnas cifradas y se solicitan en `columns`, debe proveerse `passphrase`.
    """
    conds = _parse_where(where)
    cols_req = list(columns) if columns is not None else None
    cols_needed = set(cols_req or [])
    cols_needed.update({c.col for c in conds})
    cols_needed = list(cols_needed) if cols_needed else None

    t0 = time.perf_counter()
    bytes_read = 0
    chunks_scanned = 0
    parts: List[pd.DataFrame] = []

    with ZipFile(path, mode="r") as zf:
        snap = _pick_snapshot_as_of(zf, as_of) if as_of else None
        allowed_idx_paths = set(snap["indexes"]) if snap else None
        allowed_chunk_paths = [e["path"] for e in (snap.get("chunks") if snap else [])] if snap else None

        # --- nombres en el zip (para detectar side-cars de cifrado robustamente) ---
        znames = set(zf.namelist())

        # --- cifrado: validar si se pidieron columnas cifradas sin passphrase ---
        meta = load_crypto_meta(zf)

        # Detectar por meta y también por existencia de side-cars
        enc_requested: set[str] = set()
        if cols_req is not None:
            for c in cols_req:
                suffix = f"/{c}.bin"
                if any(n.startswith("enc/") and n.endswith(suffix) for n in znames):
                    enc_requested.add(c)

        if ((meta and cols_req is not None and (set(cols_req) & set(meta.columns))) or enc_requested) and not passphrase:
            raise ValueError("Se solicitaron columnas cifradas pero no se proporcionó passphrase")

        idx_minmax = _load_index_minmax(zf, allowed_paths=allowed_idx_paths)
        bloom_col, idx_bloom = _load_index_bloom(zf, allowed_paths=allowed_idx_paths)
        cand_ts = _cand_from_minmax(conds, idx_minmax)
        cand_ct = _cand_from_bloom(conds, bloom_col, idx_bloom)

        price_conds = [c for c in conds if c.col == "price"]
        cand_price = None
        idx_price: Dict[str, Tuple[Any, Any, str]] = {}
        if price_conds:
            idx_price = _load_index_minmax_for_col(zf, "price", allowed_paths=allowed_idx_paths)
            if idx_price:
                for c in price_conds:
                    try:
                        c.val = float(c.val)
                    except Exception:
                        pass
                cand_price = _cand_from_minmax_for_col(price_conds, idx_price)

        cand = _intersect_opt(cand_ts, cand_ct)
        cand = _intersect_opt(cand, cand_price)

        id_to_path: Dict[str, str] = {}
        for cid, (_mn, _mx, p) in idx_minmax.items():
            id_to_path[cid] = p
        for cid, (_b, p) in idx_bloom.items():
            id_to_path[cid] = p
        for cid, (_mn, _mx, p) in idx_price.items():
            id_to_path[cid] = p

        chunk_paths: List[Tuple[str, str]] = []
        if cand is None:
            if allowed_chunk_paths is not None:
                for name in allowed_chunk_paths:
                    m = re.search(r"part-(\d+)\.parquet$", name)
                    cid = m.group(1) if m else name
                    chunk_paths.append((cid, name))
            else:
                for name in _zip_list(zf, "chunks/"):
                    if name.endswith(".parquet"):
                        m = re.search(r"part-(\d+)\.parquet$", name)
                        cid = m.group(1) if m else name
                        chunk_paths.append((cid, name))
        else:
            for cid in sorted(cand):
                pth = id_to_path.get(cid)
                if pth is None:
                    # Si el snapshot no tiene ese chunk, lo descartamos
                    continue
                if allowed_chunk_paths is not None and pth not in allowed_chunk_paths:
                    continue
                chunk_paths.append((cid, pth))

        for cid, pth in chunk_paths:
            info = zf.getinfo(pth)

            # --- Detectar columnas cifradas en este part (robusto aunque meta.parts esté vacío) ---
            m = re.search(r"part-(\d+)\.parquet$", pth)
            part_id = m.group(1) if m else pth

            enc_cols_part: set[str] = set()
            if cols_needed is not None:
                if meta and meta.parts.get(part_id):
                    enc_cols_part |= set(meta.parts.get(part_id, [])) & set(cols_needed)
                for c in cols_needed:
                    if f"enc/part-{part_id}/{c}.bin" in znames:
                        enc_cols_part.add(c)

            # No pedir a Parquet las columnas cifradas
            cols_on_disk = None
            if cols_needed is not None:
                tmp = [c for c in cols_needed if c not in enc_cols_part]
                cols_on_disk = tmp or None

            with zf.open(pth, "r") as f:
                df_chunk = pd.read_parquet(f, columns=cols_on_disk)

            # Rehidratar lo cifrado si hay passphrase (usa side-cars; no depende de meta.parts)
            if passphrase:
                df_chunk = rehydrate_chunk_columns(
                    zf, df_chunk, pth, passphrase=passphrase, want_cols=cols_needed
                )

            chunks_scanned += 1
            bytes_read += info.compress_size

            if conds:
                df_chunk = _rows_filter(df_chunk, conds)

            # Completar columnas faltantes sólo si NO están cifradas. Si son cifradas: rehidratar o error claro.
            if cols_req is not None:
                missing = [c for c in cols_req if c not in df_chunk.columns]
                if missing:
                    miss_nonenc = [c for c in missing if f"enc/part-{part_id}/{c}.bin" not in znames]
                    if miss_nonenc:
                        with zf.open(pth, "r") as f:
                            add_cols = pd.read_parquet(f, columns=miss_nonenc)
                        df_chunk = pd.concat([df_chunk.reset_index(drop=True), add_cols.reset_index(drop=True)], axis=1)

                    still_missing = [c for c in cols_req if c not in df_chunk.columns]
                    if still_missing:
                        if passphrase:
                            df_chunk = rehydrate_chunk_columns(
                                zf, df_chunk, pth, passphrase=passphrase, want_cols=still_missing
                            )
                        else:
                            raise ValueError("Se solicitaron columnas cifradas pero no se proporcionó passphrase")
                df_chunk = df_chunk[cols_req]
            parts.append(df_chunk)

    out = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=cols_req or [])

    if head is not None:
        out = out.head(head)

    # Guardar métrica de uso (archivo por timestamp único)
    try:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        usage_rec = {"ts": ts, "where": where, "columns": cols_req, "bytes_read": int(bytes_read), "chunks_scanned": int(chunks_scanned), "as_of": as_of}
        usage_dir = _posix_join("profiles", "usage")
        with ZipFile(path, mode="a", compression=ZIP_DEFLATED) as zfa:
            existing = set(zfa.namelist())
            base_name = f"{ts}.json"
            usage_path = _posix_join(usage_dir, base_name)
            if usage_path in existing:
                i = 1
                while True:
                    alt = _posix_join(usage_dir, f"{ts}-{i}.json")
                    if alt not in existing:
                        usage_path = alt
                        break
                    i += 1
            _zip_write_json(zfa, usage_path, usage_rec)
    except Exception:
        pass

    try:
        _update_usage_agg(path)
    except Exception:
        pass

    # ---- Auditoría de acceso (3.3) ----
    try:
        duration_ms = int((time.perf_counter() - t0) * 1000)
        cols_log = list(cols_req) if cols_req else None
        user = os.environ.get("SURX_USER") or getpass.getuser()
        client = os.environ.get("SURX_CLIENT") or "py"
        evt = {
            "op": "read",
            "where": where,
            "cols": cols_log,
            "user": user,
            "client": client,
            "bytes_read": int(bytes_read),
            "chunks_scanned": int(chunks_scanned),
            "duration_ms": duration_ms,
        }
        if as_of:
            evt["as_of"] = as_of
        append_audit_event(path, evt)  # firma opcional vía SURX_AUDIT_SIGN
    except Exception:
        # Nunca romper la lectura por fallas de auditoría
        pass

    return out


# -------------------- Inspect --------------------

def inspect(path: str) -> Dict[str, Any]:
    with ZipFile(path, mode="r") as zf:
        manifest = _read_json_from_zip(zf, "manifest.json")
        chunk_files = [n for n in zf.namelist() if n.startswith("chunks/") and n.endswith(".parquet")]
        total_bytes = sum(zf.getinfo(n).compress_size for n in chunk_files)
        idx_files = [n for n in zf.namelist() if n.startswith("indexes/")]
        idx_present = sorted(posixpath.basename(n) for n in idx_files)

        usage_files = [n for n in zf.namelist() if n.startswith("profiles/usage/") and n.endswith(".json")]
        last_usage: Optional[Dict[str, Any]] = None
        if usage_files:
            usage_files.sort()
            last = usage_files[-1]
            last_usage = _read_json_from_zip(zf, last)

        rows = None
        quality = None
        if "profiles/quality.json" in zf.namelist():
            try:
                quality = _read_last_json_from_zip(zf, "profiles/quality.json")
                rows = int(quality.get("rows"))
            except Exception:
                pass

        usage_agg = None
        if "profiles/usage.json" in zf.namelist():
            try:
                usage_agg = _read_last_json_from_zip(zf, "profiles/usage.json")
            except Exception:
                pass

        # snapshots/journal resumen
        snaps = _list_snapshot_files(zf)
        last_snap = None
        if snaps:
            s = _read_json_from_zip(zf, snaps[-1])
            last_snap = s.get("ts")

        journal_count = len([n for n in zf.namelist() if n.startswith("journal/") and n.endswith(".json")])

        info = {
            "name": manifest.get("name"),
            "created_at": manifest.get("created_at"),
            "partitions": manifest.get("partitions", []),
            "indexes": idx_present,
            "n_chunks": len(chunk_files),
            "bytes_total": int(total_bytes),
            "rows": rows,
            "quality": quality,
            "last_usage": last_usage,
            "usage_agg": usage_agg,
            "snapshots": {"count": len(snaps), "last_ts": last_snap},
            "journal": {"count": journal_count},
        }
        return info


# -------------------- Validate (HLL + KLL-lite + enum estricto) --------------------

def _series_kind(col: str, s: pd.Series) -> str:
    if col == "ts" or pd.api.types.is_datetime64_any_dtype(s):
        return "datetime"
    if pd.api.types.is_numeric_dtype(s):
        return "number"
    return "string"

def _to_comparable(kind: str, val: Any):
    if val is None:
        return None
    if kind == "datetime":
        return pd.to_datetime(val, utc=True)
    if kind == "number":
        try:
            return float(val)
        except Exception:
            return None
    return str(val)

def _merge_min(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if a <= b else b

def _merge_max(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if a >= b else b

# ---- KLL-lite ----
class _KLLSketch:
    def __init__(self, k: int = 200, seed: int = 0x9E3779B97F4A7C15):
        self.k = max(8, int(k))
        self.levels: list[list[float]] = [[]]
        self.state = seed & ((1 << 64) - 1)
        self.n = 0

    def _randbit(self) -> int:
        self.state = (6364136223846793005 * self.state + 1) & ((1 << 64) - 1)
        return (self.state >> 63) & 1

    def _compact_level(self, lvl: int) -> None:
        buf = self.levels[lvl]
        if len(buf) <= self.k:
            return
        buf.sort()
        start = self._randbit()
        survivors = buf[start::2]
        buf.clear()
        if len(self.levels) <= lvl + 1:
            self.levels.append([])
        self.levels[lvl + 1].extend(survivors)
        if len(self.levels[lvl + 1]) > self.k:
            self._compact_level(lvl + 1)

    def add(self, x: float) -> None:
        self.levels[0].append(float(x))
        self.n += 1
        if len(self.levels[0]) > self.k:
            self._compact_level(0)

    def _weights(self) -> list[tuple[float, int]]:
        out: list[tuple[float, int]] = []
        for lvl, buf in enumerate(self.levels):
            w = 1 << lvl
            for v in buf:
                out.append((v, w))
        return out

    def quantile(self, q: float) -> Optional[float]:
        if self.n == 0:
            return None
        pts = self._weights()
        if not pts:
            return None
        pts.sort(key=lambda t: t[0])
        total_w = sum(w for _, w in pts)
        target = q * (total_w - 1)
        acc = 0
        for v, w in pts:
            acc += w
            if acc - 1 >= target:
                return float(v)
        return float(pts[-1][0])


def _kind_from_arrow_type(arrow_type: str) -> str:
    at = (arrow_type or "").lower()
    if "timestamp" in at:
        return "datetime"
    if any(t in at for t in ["int", "float", "double", "decimal"]):
        return "number"
    return "string"

def _normalize_scalar_for_kind(kind: str, v: Any) -> Any:
    if v is None:
        return None
    if kind == "datetime":
        return pd.to_datetime(v, utc=True)
    if kind == "number":
        try:
            return float(v)
        except Exception:
            return None
    return str(v)

def validate(path: str) -> None:
    """Valida constraints del manifest y genera profiles/quality.json con HLL + KLL-lite."""
    violations: List[str] = []
    with ZipFile(path, mode="r") as zf:
        manifest = _read_json_from_zip(zf, "manifest.json")
        schema = manifest.get("schema", [])
        chunk_files = [n for n in zf.namelist() if n.startswith("chunks/") and n.endswith(".parquet")]
        if not chunk_files:
            raise ValueError("No hay chunks en el contenedor.")

        enum_allowed: Dict[str, set] = {}
        kind_by_col: Dict[str, str] = {}
        for col_def in schema:
            col = col_def.get("name")
            at = col_def.get("arrow_type") or ""
            kind = _kind_from_arrow_type(at)
            kind_by_col[col] = kind
            cons = col_def.get("constraints") or {}
            if "enum" in cons and isinstance(cons["enum"], (list, tuple, set)):
                enum_allowed[col] = {_normalize_scalar_for_kind(kind, v) for v in cons["enum"]}

        cols = [c["name"] for c in schema] if schema else None
        totals: Dict[str, Dict[str, Any]] = {}
        for col in (cols or []):
            kind = kind_by_col.get(col, "string")
            totals[col] = {
                "nulls": 0,
                "min": None,
                "max": None,
                "distinct_hll": HLL.create(p=12),
                "kind": kind,
                "kll": _KLLSketch(k=200) if kind == "number" else None,
            }
        total_rows = 0
        enum_viol: Dict[str, set] = {c: set() for c in enum_allowed.keys()}

        for pth in chunk_files:
            with zf.open(pth, "r") as f:
                df = pd.read_parquet(f)
            total_rows += len(df)
            for col in (cols or df.columns.tolist()):
                if col not in df.columns:
                    continue
                s = df[col]
                kind = totals.get(col, {}).get("kind") or _series_kind(col, s)
                if col not in totals:
                    totals[col] = {
                        "nulls": 0, "min": None, "max": None,
                        "distinct_hll": HLL.create(p=12),
                        "kind": kind,
                        "kll": _KLLSketch(k=200) if kind == "number" else None,
                    }

                nulls = int(s.isna().sum())
                totals[col]["nulls"] += nulls

                if kind == "datetime":
                    sv = pd.to_datetime(s, utc=True).dropna()
                elif kind == "number":
                    sv = pd.to_numeric(s, errors="coerce").dropna()
                else:
                    sv = s.astype("string").dropna()

                if not sv.empty:
                    vmin = sv.min(); vmax = sv.max()
                    totals[col]["min"] = _merge_min(totals[col]["min"], vmin)
                    totals[col]["max"] = _merge_max(totals[col]["max"], vmax)

                for v in sv:
                    totals[col]["distinct_hll"].add(str(v))

                if kind == "number" and totals[col]["kll"] is not None and len(sv) > 0:
                    sketch: _KLLSketch = totals[col]["kll"]
                    for v in sv.values.tolist():
                        if pd.notna(v):
                            sketch.add(float(v))

                if col in enum_allowed and not sv.empty:
                    allowed = enum_allowed[col]
                    if kind == "datetime":
                        observed = {pd.to_datetime(v, utc=True) for v in sv.unique().tolist() if v is not None}
                    elif kind == "number":
                        observed = {float(v) for v in sv.unique().tolist() if pd.notna(v)}
                    else:
                        observed = {str(v) for v in sv.unique().tolist() if v is not None}
                    diff = observed - allowed
                    if diff:
                        for x in list(diff)[:10]:
                            enum_viol[col].add(x)

        quality_cols: Dict[str, Any] = {}
        for col, acc in totals.items():
            kind = acc["kind"] or "string"
            mn = acc["min"]; mx = acc["max"]
            if kind == "datetime":
                mn = None if mn is None else pd.to_datetime(mn, utc=True).isoformat()
                mx = None if mx is None else pd.to_datetime(mx, utc=True).isoformat()

            distinct_est = float(acc["distinct_hll"].estimate())
            p50 = p95 = p99 = None
            if kind == "number" and acc["kll"] is not None and acc["kll"].n > 0:
                sketch: _KLLSketch = acc["kll"]
                p50 = sketch.quantile(0.50)
                p95 = sketch.quantile(0.95)
                p99 = sketch.quantile(0.99)

            quality_cols[col] = {
                "dtype": kind,
                "nulls": int(acc["nulls"]),
                "null_pct": (acc["nulls"] / total_rows) if total_rows else 0.0,
                "min": mn, "max": mx,
                "distinct_est": distinct_est,
                "p50": p50, "p95": p95, "p99": p99,
            }

    _zip_write_json_replace(path, _posix_join("profiles", "quality.json"), {"version": 1, "rows": int(total_rows), "columns": quality_cols})

    # Validaciones
    for col_def in schema:
        col = col_def.get("name")
        cons = (col_def.get("constraints") or {})
        qc = quality_cols.get(col)
        if qc is None:
            continue
        kind = qc["dtype"]
        obs_min = _to_comparable(kind, qc["min"])
        obs_max = _to_comparable(kind, qc["max"])

        if cons.get("not_null") and qc["nulls"] > 0:
            violations.append(f"{col}: not_null violado (nulos={qc['nulls']})")

        if "enum" in cons:
            bad = enum_viol.get(col, set())
            if bad:
                muestras = ", ".join([str(x) for x in list(bad)[:10]])
                violations.append(f"{col}: valores fuera de enum {cons['enum']} → ejemplos: {muestras}")

        if "min" in cons:
            cmin = _to_comparable(kind, cons["min"])
            if obs_min is not None and cmin is not None and obs_min < cmin:
                violations.append(f"{col}: min observado {obs_min} < constraint {cmin}")
        if "max" in cons:
            cmax = _to_comparable(kind, cons["max"])
            if obs_max is not None and cmax is not None and obs_max > cmax:
                violations.append(f"{col}: max observado {obs_max} > constraint {cmax}")

        if "valid_range" in cons and isinstance(cons["valid_range"], (list, tuple)) and len(cons["valid_range"]) == 2:
            lo = _to_comparable(kind, cons["valid_range"][0])
            hi = _to_comparable(kind, cons["valid_range"][1])
            if obs_min is not None and lo is not None and obs_min < lo:
                violations.append(f"{col}: min observado {obs_min} < rango mínimo {lo}")
            if obs_max is not None and hi is not None and obs_max > hi:
                violations.append(f"{col}: max observado {obs_max} > rango máximo {hi}")

    if violations:
        msg = "VALIDATION FAILED:\n- " + "\n- ".join(violations)
        raise ValueError(msg)

    # Journal: validate
    _journal_append(path, "validate", {})


# (0.2.0) Se elimino un optimize() duplicado que quedaba tapado por el
# optimize() completo definido mas abajo; la doble definicion era codigo muerto.


# -------------------- Plan (explicación de pruning) --------------------

def _idx_summary_minmax(idx_minmax: Dict[str, Tuple[pd.Timestamp, pd.Timestamp, str]]) -> Dict[str, Any]:
    if not idx_minmax:
        return {"n_chunks_indexed": 0, "global_min": None, "global_max": None}
    mins = [mn for (mn, _, _) in idx_minmax.values()]
    maxs = [mx for (_, mx, _) in idx_minmax.values()]
    return {
        "n_chunks_indexed": len(idx_minmax),
        "global_min": pd.to_datetime(min(mins), utc=True).isoformat(),
        "global_max": pd.to_datetime(max(maxs), utc=True).isoformat(),
    }

def _idx_summary_bloom(idx_bloom: Dict[str, Tuple[Bloom, str]]) -> Dict[str, Any]:
    return {
        "n_chunks_indexed": len(idx_bloom),
        "m_bits": {cid: b.m for cid, (b, _) in idx_bloom.items()},
        "k_hashes": {cid: b.k for cid, (b, _) in idx_bloom.items()},
    }

def _get_chunk_id_from_path(p: str) -> str:
    m = re.search(r"part-(\d+)\.parquet$", p)
    return m.group(1) if m else p

def _list_chunk_paths(zf: ZipFile) -> List[str]:
    return [n for n in zf.namelist() if n.startswith("chunks/") and n.endswith(".parquet")]

def plan(path: str, where: Optional[str] = None, as_of: Optional[str] = None) -> Dict[str, Any]:
    """Devuelve plan de pruning; respeta snapshot si se pasa as_of."""
    with ZipFile(path, mode="r") as zf:
        conds = _parse_where(where)
        snap = _pick_snapshot_as_of(zf, as_of) if as_of else None
        all_chunks = ( [e["path"] for e in snap.get("chunks")] if snap else _list_chunk_paths(zf) )
        total_chunks = len(all_chunks)

        allowed_idx_paths = set(snap["indexes"]) if snap else None

        idx_minmax = _load_index_minmax(zf, allowed_paths=allowed_idx_paths)
        bloom_col, idx_bloom = _load_index_bloom(zf, allowed_paths=allowed_idx_paths)
        idx_price = _load_index_minmax_for_col(zf, "price", allowed_paths=allowed_idx_paths)

        cand_ts = _cand_from_minmax(conds, idx_minmax)
        cand_ct = _cand_from_bloom(conds, bloom_col, idx_bloom)
        price_conds = [c for c in conds if c.col == "price"]
        cand_pr = _cand_from_minmax_for_col(price_conds, idx_price) if price_conds else None

        cand = _intersect_opt(cand_ts, cand_ct)
        cand = _intersect_opt(cand, cand_pr)

        id_to_path: Dict[str, str] = {}
        for cid, (_mn, _mx, p) in idx_minmax.items():
            id_to_path[cid] = p
        for cid, (_b, p) in idx_bloom.items():
            id_to_path[cid] = p
        for cid, (_mn, _mx, p) in idx_price.items():
            id_to_path[cid] = p

        if cand is None:
            cand_ids = []
            for name in all_chunks:
                m = re.search(r"part-(\d+)\.parquet$", name)
                cid = m.group(1) if m else name
                cand_ids.append(cid)
        else:
            cand_ids = sorted(cand)

        cand_paths = [id_to_path.get(cid, next((n for n in all_chunks if cid in n), None)) for cid in cand_ids]

        plan_info = {
            "where": where,
            "as_of": as_of,
            "total_chunks": total_chunks,
            "candidates_count": len(cand_ids),
            "pruning_ratio": (len(cand_ids) / total_chunks) if total_chunks else 1.0,
            "candidates_by_col": {
                "ts": None if cand_ts is None else sorted(list(cand_ts)),
                (bloom_col or "country"): None if cand_ct is None else sorted(list(cand_ct)),
                "price": None if cand_pr is None else sorted(list(cand_pr)),
            },
            "candidates_final": cand_ids,
            "candidate_paths": cand_paths,
            "indexes": {
                "minmax": {**_idx_summary_minmax(idx_minmax), "price_indexed": bool(idx_price)},
                "bloom": _idx_summary_bloom(idx_bloom),
            },
        }
        # --- Compatibilidad con versión vieja:
        plan_info["candidates"] = cand_paths
        plan_info["count"] = len(cand_paths)

        return plan_info


# -------------------- Reindex (post-hoc) --------------------

def _to_json_scalar(v: Any) -> Any:
    if isinstance(v, pd.Timestamp):
        return v.tz_convert("UTC").isoformat()
    try:
        import numpy as _np_local
        if isinstance(v, (_np_local.generic,)):
            return v.item()
    except Exception:
        pass
    if isinstance(v, (type(None), bool, int, float, str)):
        return v
    return str(v)

def reindex(path: str, indexes: Dict[str, Dict[str, Any]]) -> None:
    """Reconstruye índices solicitados sin reescribir los chunks."""
    to_write: Dict[str, Any] = {}

    with ZipFile(path, mode="r") as zf:
        chunk_paths = _list_chunk_paths(zf)
        id_to_path = {_get_chunk_id_from_path(p): p for p in chunk_paths}

        for col, kinds in (indexes or {}).items():
            if "minmax" not in kinds:
                continue
            entries = []
            for cid, p in id_to_path.items():
                with zf.open(p, "r") as f:
                    try:
                        dfc = pd.read_parquet(f, columns=[col])
                    except Exception:
                        continue
                if col not in dfc.columns or dfc.empty:
                    continue
                s = dfc[col]
                if col == "ts":
                    sv = pd.to_datetime(s, utc=True)
                    if sv.dropna().empty:
                        continue
                    minv = _to_json_scalar(sv.min())
                    maxv = _to_json_scalar(sv.max())
                else:
                    if pd.api.types.is_numeric_dtype(s):
                        sv = pd.to_numeric(s, errors="coerce").dropna()
                        if sv.empty:
                            continue
                        minv = float(sv.min()); maxv = float(sv.max())
                    else:
                        sv = s.astype("string").dropna()
                        if sv.empty:
                            continue
                        minv = _to_json_scalar(min(sv)); maxv = _to_json_scalar(max(sv))
                entries.append({"chunk_id": cid, "path": p, "min": minv, "max": maxv})
            idx_obj = {"version": 1, "column": col, "index": "minmax", "entries": entries}
            to_write[f"indexes/{col}.minmax.json"] = idx_obj

        for col, kinds in (indexes or {}).items():
            if "bloom" not in kinds:
                continue
            fp = kinds["bloom"].get("fp_rate", 0.01)
            bloom_entries = []
            for cid, p in id_to_path.items():
                with zf.open(p, "r") as f:
                    try:
                        dfc = pd.read_parquet(f, columns=[col])
                    except Exception:
                        continue
                if col not in dfc.columns or dfc.empty:
                    continue
                vset = {str(v) for v in dfc[col].dropna().unique().tolist()}
                b = _build_bloom_for_values(vset, fp_rate=fp)
                bloom_entries.append({"chunk_id": cid, "path": p, "bloom": _serialize_bloom(b)})
            idx_obj = {"version": 1, "column": col, "index": "bloom", "entries": bloom_entries}
            to_write[f"indexes/{col}.bloom.json"] = idx_obj

    for inner_path, obj in to_write.items():
        _zip_write_json_replace(path, inner_path, obj)

    _journal_append(path, "reindex", {"written": list(to_write.keys())})


# -------------------- Usage aggregate --------------------

def _compute_usage_agg(path: str, limit: int = 1000) -> Dict[str, Any]:
    with ZipFile(path, "r") as zf:
        files = [n for n in zf.namelist() if n.startswith("profiles/usage/") and n.endswith(".json")]
        if not files:
            return {}
        files.sort()
        files = files[-limit:]
        bytes_list: list[int] = []
        chunks_list: list[int] = []
        col_counter: Counter[str] = Counter()
        where_counter: Counter[str] = Counter()
        for n in files:
            rec = _read_json_from_zip(zf, n)
            br = int(rec.get("bytes_read") or 0); bytes_list.append(br)
            ch = int(rec.get("chunks_scanned") or 0); chunks_list.append(ch)
            cols = rec.get("columns") or []
            for c in cols:
                col_counter[str(c)] += 1
            w = rec.get("where")
            if w:
                where_counter[str(w)] += 1
        arr_b = _np.array(bytes_list, dtype=float)
        arr_c = _np.array(chunks_list, dtype=float)
        agg = {
            "reads": len(files),
            "bytes_total": int(arr_b.sum()) if arr_b.size else 0,
            "chunks_total": int(arr_c.sum()) if arr_c.size else 0,
            "bytes_p50": float(_np.percentile(arr_b, 50)) if arr_b.size else 0.0,
            "bytes_p95": float(_np.percentile(arr_b, 95)) if arr_b.size else 0.0,
            "chunks_p50": float(_np.percentile(arr_c, 50)) if arr_c.size else 0.0,
            "chunks_p95": float(_np.percentile(arr_c, 95)) if arr_c.size else 0.0,
            "top_columns": [[k, int(v)] for k, v in col_counter.most_common(10)],
            "top_where": [[k, int(v)] for k, v in where_counter.most_common(10)],
        }
        return agg

def _update_usage_agg(path: str) -> None:
    agg = _compute_usage_agg(path, limit=1000)
    if agg:
        _zip_write_json_replace(path, _posix_join("profiles", "usage.json"), agg)

def update_usage_kpis(path: str, window: int | None = None, baseline: bool = False) -> dict:
    """
    Calcula KPIs agregados de uso y los persiste de forma estable.
    - Si baseline=True → guarda en profiles/usage/pre_kpis.json
    - Si baseline=False → guarda en profiles/usage/post_kpis.json y computa delta_vs_pre
    - También mantiene un resumen combinado en profiles/usage.json para consumo rápido.
    """
    import json as _json
    import zipfile as _zip

    BASE = "profiles/usage/pre_kpis.json"
    POST = "profiles/usage/post_kpis.json"
    SUMMARY = "profiles/usage.json"

    # --- Recolectar eventos recientes ---
    with _zip.ZipFile(path, "r") as zf:
        events = []
        for e in sorted(
            [e for e in zf.infolist()
             if e.filename.startswith("profiles/usage/") and e.filename.endswith(".json")
             and e.filename not in (BASE, POST, SUMMARY)],
            key=lambda x: x.filename
        ):
            try:
                events.append(_json.loads(zf.read(e.filename)))
            except Exception:
                pass
        if window:
            events = events[-int(window):]

        bytes_vals, chunks_vals = [], []
        for obj in events:
            br, cs = obj.get("bytes_read"), obj.get("chunks_scanned")
            if isinstance(br, (int, float)) and isinstance(cs, (int, float)):
                bytes_vals.append(int(br)); chunks_vals.append(int(cs))

        def _pct(a, p):
            if not a: return 0
            a = sorted(a); k = max(0, min(len(a)-1, int(round((p/100)*(len(a)-1)))))
            return int(a[k])

        agg = {
            "reads_total": len(bytes_vals),
            "bytes_read_total": int(sum(bytes_vals)) if bytes_vals else 0,
            "chunks_scanned_total": int(sum(chunks_vals)) if chunks_vals else 0,
            "bytes_p50": _pct(bytes_vals, 50),
            "bytes_p95": _pct(bytes_vals, 95),
            "chunks_p50": _pct(chunks_vals, 50),
            "chunks_p95": _pct(chunks_vals, 95),
        }

        # Leer pre/post existentes para armar el SUMMARY
        try:
            pre_old = _json.loads(zf.read(BASE)) if BASE in zf.namelist() else None
        except Exception:
            pre_old = None
        try:
            post_old = _json.loads(zf.read(POST)) if POST in zf.namelist() else None
        except Exception:
            post_old = None

    # --- Persistencia (escritura atómica usando helper local) ---
    to_delete = [SUMMARY]  # siempre recalculamos el resumen
    to_add = {}

    saved = None
    if baseline:
        to_add[BASE] = _json.dumps(agg, ensure_ascii=False, indent=2).encode("utf-8")
        saved = "pre_kpis"
        pre_obj = agg
        post_obj = post_old
    else:
        to_add[POST] = _json.dumps(agg, ensure_ascii=False, indent=2).encode("utf-8")
        saved = "post_kpis"
        pre_obj = pre_old
        post_obj = agg

    # Armar SUMMARY combinado
    merged = {}
    if pre_obj:
        merged["pre_kpis"] = pre_obj
    if post_obj:
        merged["post_kpis"] = post_obj
    delta = None
    if pre_obj and post_obj:
        def _d(key): return int((post_obj.get(key) or 0) - (pre_obj.get(key) or 0))
        delta = {
            "bytes_p50": _d("bytes_p50"),
            "bytes_p95": _d("bytes_p95"),
            "chunks_p50": _d("chunks_p50"),
            "chunks_p95": _d("chunks_p95"),
        }
        merged["delta_vs_pre"] = delta
    from datetime import timezone as _tz
    from datetime import datetime as _dt
    merged["kpis_updated_at"] = _dt.now(_tz.utc).strftime("%Y%m%dT%H%M%SZ")

    to_add[SUMMARY] = _json.dumps(merged, ensure_ascii=False, indent=2).encode("utf-8")

    _zip_replace_entries(path, to_delete, to_add)
    return {"saved": saved, "pre_kpis": merged.get("pre_kpis"), "post_kpis": merged.get("post_kpis"),
            "delta_vs_pre": merged.get("delta_vs_pre")}

# -------------------- surx advise (estimación conservadora) --------------------

def advise(path: str) -> dict:
    import json as _json, zipfile as _zip
    with _zip.ZipFile(path, "r") as zf:
        quality = _safe_json(zf, "profiles/quality.json")
        usage   = _safe_json(zf, "profiles/usage.json")
    agg = usage or {}
    bytes_p50 = ((agg.get("post_kpis") or {}).get("bytes_p50")
                 or (agg.get("pre_kpis") or {}).get("bytes_p50")
                 or (agg.get("bytes_p50")))
    # Heurística de selectividad por rango (muy simple)
    rng_cols = sorted((agg.get("columns_range") or {}).items(), key=lambda x: x[1], reverse=True)
    eq_cols  = sorted((agg.get("columns_eq") or {}).items(),    key=lambda x: x[1], reverse=True)

    order = rng_cols[0][0] if rng_cols else None
    bloom = [c for c,_ in eq_cols if 10 <= (quality.get("columns", {}).get(c, {}).get("distinct_est") or 0) <= 1_000_000]
    minmax = [c for c,_ in rng_cols]
    parts = [c for c,_ in eq_cols if 5 <= (quality.get("columns", {}).get(c, {}).get("distinct_est") or 0) <= 200]

    est = {}
    if bytes_p50:
        # si hay columna de orden sugerida, asumimos 30–50% de ahorro
        est["bytes_p50_after"] = int(bytes_p50 * (0.6 if order else 0.8))
        est["ordering_gain"] = (bytes_p50 - est["bytes_p50_after"])

    return {
        "reads_analyzed": agg.get("reads_total") or agg.get("reads") or 0,
        "recommendations": {
            "indexes": {"bloom": bloom, "minmax": minmax},
            "partitions": parts,
            "order": order,
        },
        "estimated_savings": est,
    }

def _safe_json(zf, name):
    try:
        return json.loads(zf.read(name))
    except Exception:
        return {}

# -------------------- Snapshots & Journal (público) --------------------

def snapshot(path: str, note: Optional[str] = None) -> Dict[str, Any]:
    """Crea un snapshot de estado y lo guarda en snapshots/<ts>.json. Devuelve el objeto snapshot."""
    with ZipFile(path, "r") as zf:
        chunks = [n for n in zf.namelist() if n.startswith("chunks/") and n.endswith(".parquet")]
        idxs = [n for n in zf.namelist() if n.startswith("indexes/") and n.endswith(".json")]
        # mapear chunk_id
        entries = []
        for n in chunks:
            m = re.search(r"part-(\d+)\.parquet$", n)
            cid = m.group(1) if m else n
            entries.append({"chunk_id": cid, "path": n})
        snap = {
            "version": 1,
            "ts": _now_iso(),
            "manifest_hash": _compute_manifest_hash(zf),
            "chunks": sorted(entries, key=lambda e: e["chunk_id"]),
            "indexes": sorted(idxs),
            "profiles": {"quality": "profiles/quality.json"},
            "note": note,
        }
    # escribir snapshot
    ts_name = pd.to_datetime(snap["ts"], utc=True).strftime("%Y%m%dT%H%M%S%fZ")
    inner = _posix_join("snapshots", f"{ts_name}.json")
    _zip_write_json_replace(path, inner, snap)
    _journal_append(path, "snapshot", {"file": inner})
    return snap

def log(path: str) -> List[Dict[str, Any]]:
    """Devuelve la lista de eventos del journal ordenados por id ascendente."""
    with ZipFile(path, "r") as zf:
        files = [n for n in zf.namelist() if n.startswith("journal/") and n.endswith(".json")]
        files.sort()
        return [_read_json_from_zip(zf, n) for n in files]

def list_snapshots(path: str) -> List[Dict[str, Any]]:
    """Lista todos los snapshots con metadatos mínimos (ordenados por ts asc)."""
    out: List[Dict[str, Any]] = []
    with ZipFile(path, mode="r") as zf:
        files = _list_snapshot_files(zf)
        for n in files:
            s = _read_json_from_zip(zf, n)
            out.append({
                "file": n,
                "ts": s.get("ts"),
                "chunks": len(s.get("chunks") or []),
                "indexes": len(s.get("indexes") or []),
                "note": s.get("note"),
            })
    return out

def _latest_snapshot(zf: ZipFile) -> Optional[Dict[str, Any]]:
    files = _list_snapshot_files(zf)
    if not files:
        return None
    s = _read_json_from_zip(zf, files[-1])
    return s

def resolve_as_of(path: str, as_of_token: Optional[str]) -> Optional[str]:
    """
    Normaliza el token `as_of`:
      - None -> None
      - "latest" -> ts del snapshot más reciente
      - "snapshots/<archivo>.json" -> ts del snapshot indicado (si existe)
      - ISO8601
    """
    if not as_of_token:
        return None
    token = as_of_token.strip()
    with ZipFile(path, "r") as zf:
        if token.lower() == "latest":
            s = _latest_snapshot(zf)
            return s.get("ts") if s else None
        if token.startswith("snapshots/") and token.endswith(".json"):
            if token in zf.namelist():
                s = _read_json_from_zip(zf, token)
                return s.get("ts")
            return None
    return token  # ya es ISO

def get_snapshot(path: str, as_of: Optional[str] = None) -> Dict[str, Any]:
    """
    Devuelve el snapshot a usar para `as_of`.
    - as_of=None  -> snapshot más reciente (si existe)
    - as_of=ISO   -> snapshot más reciente <= as_of
    - as_of="latest" o "snapshots/....json" -> resueltos automáticamente
    """
    with ZipFile(path, "r") as zf:
        if as_of is None or as_of.lower() == "latest":
            s = _latest_snapshot(zf)
            if not s:
                raise ValueError("No hay snapshots en el contenedor.")
            return s
        if as_of.startswith("snapshots/") and as_of.endswith(".json"):
            if as_of not in zf.namelist():
                raise ValueError(f"No existe {as_of} en el contenedor.")
            return _read_json_from_zip(zf, as_of)
        s = _pick_snapshot_as_of(zf, as_of)
        if not s:
            raise ValueError(f"No hay snapshot <= {as_of}.")
        return s


# === Nivel 4: Optimize (compact + order) y Planner PLUS =====================
# Utilidad: listar Parquet dentro de /chunks

def _list_parquet_chunks(zf: _zip.ZipFile) -> list[str]:
    out = []
    for e in zf.infolist():
        if e.filename.startswith("chunks/") and e.filename.endswith(".parquet"):
            out.append(e.filename)
    return sorted(out)

def _detect_existing_indexes(zf: _zip.ZipFile) -> dict:
    cols = {"minmax": [], "bloom": []}
    for e in zf.infolist():
        if e.filename.startswith("indexes/") and e.filename.endswith(".json"):
            base = e.filename.rsplit("/", 1)[-1]
            if base.endswith(".minmax.json"):
                cols["minmax"].append(base.replace(".minmax.json", ""))
            elif base.endswith(".bloom.json"):
                cols["bloom"].append(base.replace(".bloom.json", ""))
    cols["minmax"] = sorted(set(cols["minmax"]))
    cols["bloom"] = sorted(set(cols["bloom"]))
    return cols

def _write_parquet_to_mem(df: _pd.DataFrame) -> bytes:
    table = _pa.Table.from_pandas(df, preserve_index=False)
    sink = _io.BytesIO()
    _pq.write_table(table, sink, compression="zstd")
    return sink.getvalue()

def _usage_kpis_aggregate(zf: _zip.ZipFile) -> dict:
    values = []
    for e in zf.infolist():
        if e.filename.startswith("profiles/usage/") and e.filename.endswith(".json"):
            try:
                obj = _json.loads(zf.read(e.filename))
                br = obj.get("bytes_read")
                cs = obj.get("chunks_scanned")
                if isinstance(br, (int, float)) and isinstance(cs, (int, float)):
                    values.append((int(br), int(cs)))
            except Exception:
                pass
    if not values:
        return {}
    bytes_vals  = [b for b, _ in values]
    chunks_vals = [c for _, c in values]
    def pct(a, p):
        if not a: return None
        a = sorted(a)
        k = max(0, min(len(a)-1, int(round((p/100.0)*(len(a)-1)))))
        return a[k]
    return {
        "reads_total": len(values),
        "bytes_read_total": int(sum(bytes_vals)),
        "chunks_scanned_total": int(sum(chunks_vals)),
        "bytes_p50": int(pct(bytes_vals, 50)),
        "bytes_p95": int(pct(bytes_vals, 95)),
        "chunks_p50": int(pct(chunks_vals, 50)),
        "chunks_p95": int(pct(chunks_vals, 95)),
    }

def _has_crypto(zf: _zip.ZipFile) -> bool:
    try:
        for e in zf.infolist():
            if e.filename == "config/crypto.json":
                return True
        return False
    except Exception:
        return False
    

def _zip_replace_entries(zip_path: str, to_delete: list[str], to_add: dict[str, bytes]) -> None:
    """Reescribe el ZIP copiando todo menos 'to_delete' y agregando 'to_add'."""
    import os, zipfile, tempfile
    tmp = zip_path + ".swap"
    dels = set(to_delete or [])
    with zipfile.ZipFile(zip_path, "r") as zin, zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            if info.filename in dels:
                continue
            data = zin.read(info.filename)
            zout.writestr(info, data)
        for name, data in (to_add or {}).items():
            zout.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
    _fsync_file_and_dir(tmp)
    os.replace(tmp, zip_path)
    _fsync_file_and_dir(zip_path)


def optimize(path: str,
             *,
             compact: bool = False,
             target_rows: int = 100_000,
             order: list[str] | None = None,
             min_chunks: int = 1) -> dict:
    """
    Recompone chunks: compactación y/o ordenación dentro del .surx.
    - Reconstruye índices existentes (minmax/bloom)
    - Escribe snapshot + journal

    **Limitación MVP**: si hay columnas cifradas (config/crypto.json) se rechaza
    la operación para no desincronizar side-cars.
    """
    if not compact and not order:
        raise ValueError("Nada para hacer: pasá --compact y/o --order")

    # 1) Abrimos ZIP y medimos KPIs pre + cifrado
    with _zip.ZipFile(path, "r") as zf:
        if _has_crypto(zf):
            raise ValueError(
                "Dataset con columnas cifradas (config/crypto.json). "
                "Por seguridad, optimize() se bloquea en este MVP."
            )
        pre_kpis = _usage_kpis_aggregate(zf)
        chunk_paths = _list_parquet_chunks(zf)
        if not chunk_paths:
            return {"changed": False, "reason": "no_chunks"}

        # Validar columnas de orden contra un sample
        if order:
            sample = chunk_paths[0]
            with zf.open(sample) as f:
                cols = _pq.read_table(f).column_names
            for c in order:
                if c not in cols:
                    raise ValueError(f"Columna de orden no existe en chunks: {c}")

    # 2) Particionado por partición (preserva subcarpetas, e.g., chunks/country=AR/)
    new_parts: list[tuple[str, bytes]] = []

    def _part_prefix(p: str) -> str:
        # "chunks/country=AR/part-000123.parquet" -> "chunks/country=AR"
        # "chunks/part-000000.parquet" -> "chunks"
        segs = p.split("/")
        return "/".join(segs[:2]) if len(segs) >= 3 else segs[0]

    groups: dict[str, list[str]] = {}
    for p_old in chunk_paths:
        groups.setdefault(_part_prefix(p_old), []).append(p_old)

    # --- contador global de IDs para evitar colisiones entre particiones
    next_id = 0

    # Procesamos cada grupo de partición de forma independiente
    for prefix, paths in sorted(groups.items()):
        dfs = []
        with _zip.ZipFile(path, "r") as zf_local:
            for p_old in sorted(paths):
                with zf_local.open(p_old) as f:
                    dfs.append(_pd.read_parquet(f))
        grp = _pd.concat(dfs, ignore_index=True) if dfs else _pd.DataFrame()

        if order and not grp.empty:
            grp = grp.sort_values(by=order, kind="mergesort", ignore_index=True)

        n = len(grp)
        if n == 0:
            continue

        # decidir # de partes del grupo
        if compact:
            if target_rows <= 0:
                raise ValueError("target_rows debe ser > 0")
            n_parts = max(min_chunks, _math.ceil(n / target_rows))
        else:
            n_parts = len(paths)

        step = _math.ceil(n / n_parts)
        for start in range(0, n, step):
            end = min(n, start + step)
            buf = _write_parquet_to_mem(grp.iloc[start:end].reset_index(drop=True))
            out_name = f"{prefix}/part-{next_id:06d}.parquet"   # IDs globales
            new_parts.append((out_name, buf))
            next_id += 1

    # Detectar índices existentes ANTES de reescribir (para poder reconstruirlos luego)
    with _zip.ZipFile(path, "r") as zf_prev:
        idx_cols_pre = _detect_existing_indexes(zf_prev)

    # 3) Reescritura atómica del ZIP (usa helper local _zip_replace_entries)
    # Borrar tanto chunks como todos los archivos de indexes/, y mantener todo lo demás (profiles/usage/* incluido)
    with _zip.ZipFile(path, "r") as zf_idx:
        index_paths = [e.filename for e in zf_idx.infolist() if e.filename.startswith("indexes/")]
    to_delete = chunk_paths + index_paths
    to_add = {name: data for name, data in new_parts}
    _zip_replace_entries(path, to_delete, to_add)

    # 4) Reconstrucción de índices existentes + snapshot + journal
    # Usar los índices detectados antes de la reescritura
    idx_cols = idx_cols_pre

    rebuild_spec = {}
    for c in idx_cols.get("minmax", []):
        rebuild_spec.setdefault(c, {})["minmax"] = {}
    for c in idx_cols.get("bloom", []):
        rebuild_spec.setdefault(c, {})["bloom"] = {}

    reindexed_cols = []
    if rebuild_spec:
        from . import reindex as _reindex_api, snapshot as _snapshot_api
        _reindex_api(path, rebuild_spec)
        _snapshot_api(path)
        _journal_append(path, "optimize", {
            "compact": compact, "target_rows": target_rows, "order": order,
            "reindex": list(rebuild_spec.keys())
        })
        reindexed_cols = list(rebuild_spec.keys())

    # 5) (Importante) No tocar profiles/usage.json aquí. Baseline/Post lo maneja `surx stats`.

    return {
        "changed": True,
        "new_parts": len(new_parts),
        "reindexed_columns": reindexed_cols,
        "pre_kpis": pre_kpis,
        "order": order or [],
        "target_rows": target_rows if compact else None
    }


# ---------------- Planner PLUS: OR / IN / BETWEEN ---------------------------
_OR_SPLIT = _re.compile(r"(?i)\s+\bOR\b\s+")
_IN_CLAUSE = _re.compile(r"(?i)([A-Za-z_]\w*)\s+IN\s*\(([^)]+)\)")
_BETWEEN_CLAUSE = _re.compile(r"(?i)([A-Za-z_]\w*)\s+BETWEEN\s+([^\s]+)\s+AND\s+([^\s]+)")

def _load_index_entries(zf: _zip.ZipFile):
    out = {}
    for e in zf.infolist():
        if e.filename.startswith("indexes/") and e.filename.endswith(".json"):
            try:
                obj = _json.loads(zf.read(e.filename))
            except Exception:
                continue
            col = obj.get("column")
            kind = obj.get("index")
            if not col or not kind:
                base = e.filename.rsplit("/", 1)[-1]
                if base.endswith(".minmax.json"):
                    kind = "minmax"; col = base.replace(".minmax.json", "")
                elif base.endswith(".bloom.json"):
                    kind = "bloom"; col = base.replace(".bloom.json", "")
            if not col or not kind:
                continue
            out.setdefault(col, {})[kind] = obj.get("entries", [])
    return out

def _bloom_maybe(bloom_meta: dict, value: str) -> bool:
    """
    Devuelve True si el bloom 'quizás' contiene el valor.
    Si falta metadata, retorna True (conservador).
    """
    try:
        m = int(bloom_meta.get("m") or bloom_meta["bloom"]["m"])
        k = int(bloom_meta.get("k") or bloom_meta["bloom"]["k"])
        salt = (bloom_meta.get("salt") or bloom_meta["bloom"].get("salt") or "surx_v1")
        bits_hex = bloom_meta.get("bits_hex") or bloom_meta["bloom"].get("bits_hex")
    except Exception:
        return True  # sin datos, conservador

    if not (m and k and bits_hex):
        return True

    bits = bytes.fromhex(bits_hex)
    val = str(value)
    for i in range(k):
        h = _hashlib.md5(f"{salt}|{val}|{i}".encode("utf-8")).digest()
        pos = int.from_bytes(h[:8], "little") % m
        byte_i = pos // 8
        mask = 1 << (pos % 8)
        if byte_i >= len(bits) or not (bits[byte_i] & mask):
            return False
    return True

def _cands_for_pred(idx, col, op, val):
    paths = set()
    by_kind = idx.get(col, {})
    if op in ("=", "=="):
        if by_kind.get("bloom"):
            for ent in by_kind["bloom"]:
                if _bloom_maybe(ent, val):  # usa bitset real
                    paths.add(ent["path"])
        elif by_kind.get("minmax"):
            for ent in by_kind["minmax"]:
                paths.add(ent["path"])
    elif op in (">=", ">", "<=", "<"):
        for ent in by_kind.get("minmax", []):
            mn, mx = ent.get("min"), ent.get("max")
            if op in (">=", ">"):
                if mx is None or str(mx) >= str(val):
                    paths.add(ent["path"])
            else:
                if mn is None or str(mn) <= str(val):
                    paths.add(ent["path"])
    return paths

def plan_plus(path: str, where: str) -> dict:
    with _zip.ZipFile(path, "r") as zf:
        idx = _load_index_entries(zf)
        expr = where

        # IN -> OR de igualdades
        for m in _IN_CLAUSE.finditer(where):
            col, vals = m.group(1), m.group(2)
            alts = [v.strip() for v in vals.split(",")]
            ors = " OR ".join([f"{col} = {v}" for v in alts])
            expr = expr.replace(m.group(0), f"({ors})")

        # BETWEEN -> >= AND <=
        for m in _BETWEEN_CLAUSE.finditer(where):
            col, a, b = m.group(1), m.group(2), m.group(3)
            repl = f"({col} >= {a} AND {col} <= {b})"
            expr = expr.replace(m.group(0), repl)

        or_parts = _OR_SPLIT.split(expr)
        per_clause = []
        accum_or: set[str] = set()
        for part in or_parts:
            and_preds = [p.strip() for p in _re.split(r"(?i)\s+\bAND\b\s+", part)]
            sets = []
            for pred in and_preds:
                m = _re.search(r"([A-Za-z_]\w*)\s*(==|=|>=|<=|>|<)\s*(.+)", pred)
                if not m:
                    continue
                col, op, val = m.group(1), m.group(2), m.group(3).strip()
                val = val.strip(" '\"")
                cand = _cands_for_pred(idx, col, op, val)
                # normalización estética de pred (limpia paréntesis redundantes)
                pred_clean = pred.strip()
                if pred_clean.startswith("(") and pred_clean.endswith(")"):
                    pred_clean = pred_clean[1:-1].strip()
                pred_clean = pred_clean.strip("() ").strip()
                per_clause.append({"pred": pred_clean, "candidates": len(cand)})

                sets.append(cand if cand else set())
            inter = sets[0] if sets else set()
            for s in sets[1:]:
                inter = inter & s
            accum_or |= inter

        return {
            "candidates": sorted(accum_or),
            "count": len(accum_or),
            "explain": per_clause,
            "normalized": expr,
        }
