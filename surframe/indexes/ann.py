# surframe/indexes/ann.py
from __future__ import annotations

import io
import json
import re
import zipfile
from typing import Iterable, List, Tuple, Optional

import numpy as np
import pandas as pd

# Reusamos el helper atómico que ya tenés (Windows-safe)
from surframe.crypto import _rewrite_zip_with_replacements  # type: ignore

INDEX_DIR = "indexes/embedding.flat"
META_PATH = f"{INDEX_DIR}/meta.json"
VECS_PATH = f"{INDEX_DIR}/vectors.npy"
MAP_PATH = f"{INDEX_DIR}/mapping.npy"  # int32[N,2] => (chunk_idx, row_idx)


def _list_chunks(zf: zipfile.ZipFile) -> List[Tuple[str, str]]:
    """[(chunk_id, path parquet)] en orden estable."""
    out: List[Tuple[str, str]] = []
    rx = re.compile(r"part-(\d+)\.parquet$")
    for e in zf.infolist():
        if e.filename.startswith("chunks/") and e.filename.endswith(".parquet"):
            m = rx.search(e.filename)
            if m:
                out.append((m.group(1), e.filename))
    out.sort(key=lambda x: x[0])
    return out


def _load_snapshot_index_allow(zf: zipfile.ZipFile, as_of: Optional[str]) -> bool:
    """Devuelve True si el índice es utilizable bajo as_of (None=siempre)."""
    if not as_of:
        return True
    # Si hay snapshots, verificamos que este índice exista en el snapshot <= as_of
    # Usamos la heurística simple: si hay archivos en snapshots/, buscamos el más cercano <= as_of
    snaps = [
        e.filename
        for e in zf.infolist()
        if e.filename.startswith("snapshots/") and e.filename.endswith(".json")
    ]
    if not snaps:
        return True
    # Formato snapshots/2025...Z.json → extraemos el timestamp
    snaps_sorted = sorted(snaps)  # lexicográfico sirve por el formato ISO-like
    target = None
    if as_of == "latest":
        target = snaps_sorted[-1]
    else:
        # tomamos el último <= as_of (si no existe exacto)
        try:
            iso = as_of.replace(":", "").replace("-", "")
            # buscamos primer nombre <= iso traducido burdamente
            for p in snaps_sorted:
                ts = p.split("/")[-1].split(".json")[0]
                if ts <= iso:
                    target = p
                else:
                    break
        except Exception:
            target = snaps_sorted[-1]
    if not target:
        return False
    # Leemos ese snapshot y revisamos que META_PATH esté listado en "indexes"
    with zf.open(target, "r") as f:
        snap = json.loads(f.read().decode("utf-8"))
    indexes = set(snap.get("indexes", []))
    return META_PATH in indexes or INDEX_DIR in indexes


def ann_build(
    path: str,
    col: str = "embedding",
    metric: str = "cosine",  # o "l2"
    dim: Optional[int] = None,
) -> dict:
    """Construye índice 'flat' (np.dot/argpartition) como side-car dentro del .surx."""
    assert metric in ("cosine", "l2"), "metric debe ser 'cosine' o 'l2'"
    with zipfile.ZipFile(path, "r") as zf:
        chunks = _list_chunks(zf)
        if not chunks:
            raise ValueError("No se encontraron chunks/*.parquet dentro del SURX")
        Xs: List[np.ndarray] = []
        mapping: List[Tuple[int, int]] = []  # (chunk_idx, row_idx)
        for ci, (_, pth) in enumerate(chunks):
            with zf.open(pth, "r") as f:
                df = pd.read_parquet(f, columns=[col])
            if col not in df.columns:
                raise ValueError(f"Columna '{col}' no existe en {pth}")
            # Series de listas/arrays → np.float32[:, dim]
            ser = df[col]
            # normalizamos input a array 2D
            arr = np.asarray(ser.tolist(), dtype=np.float32)
            if arr.ndim != 2:
                raise ValueError(
                    f"{col} debe ser 2D (N,D). Encontrado shape={arr.shape} en {pth}"
                )
            if dim is None:
                dim = arr.shape[1]
            if arr.shape[1] != dim:
                raise ValueError(
                    f"Dimensión inconsistente: esperado D={dim}, en {pth} es {arr.shape[1]}"
                )
            Xs.append(arr)
            # mapeo filas
            n = arr.shape[0]
            mapping.extend((ci, r) for r in range(n))
        if dim is None:
            raise ValueError("No se pudo inferir dimensión del embedding.")
        X = np.vstack(Xs) if Xs else np.zeros((0, dim), np.float32)
        M = np.asarray(mapping, dtype=np.int32).reshape(-1, 2)
        if metric == "cosine" and X.size:
            # normalizar filas
            norms = np.linalg.norm(X, axis=1, keepdims=True) + 1e-12
            X = X / norms

        # Serializamos a bytes para escribir en el ZIP de forma atómica
        b_vecs = io.BytesIO()
        np.save(b_vecs, X)
        b_vecs.seek(0)
        b_map = io.BytesIO()
        np.save(b_map, M)
        b_map.seek(0)

        meta = {
            "version": 1,
            "algo": "flat",
            "column": col,
            "metric": metric,
            "dim": int(dim),
            "vectors_path": VECS_PATH,
            "mapping_path": MAP_PATH,
            "vectors_n": int(X.shape[0]),
            "chunks": [{"chunk_id": cid, "path": p} for cid, p in chunks],
        }
        additions = {
            META_PATH: json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"),
            VECS_PATH: b_vecs.read(),
            MAP_PATH: b_map.read(),
        }
    # Reescritura atómica del ZIP con los nuevos artefactos
    _rewrite_zip_with_replacements(path, replacements={}, additions=additions)
    return meta


def vsearch(
    path: str,
    query_vec: Iterable[float],
    k: int = 10,
    where: Optional[str] = None,
    columns: Optional[List[str]] = None,
    as_of: Optional[str] = None,
    metric_fallback: Optional[str] = None,
    oversample: int = 10,
) -> pd.DataFrame:
    """Busca top-k por vector. Usa índice flat si existe y está permitido por as_of; si no, hace brute-force exacto."""
    q = np.asarray(list(query_vec), dtype=np.float32)
    with zipfile.ZipFile(path, "r") as zf:
        # ¿podemos usar índice?
        use_index = any(e.filename == META_PATH for e in zf.infolist()) and _load_snapshot_index_allow(zf, as_of)
        if use_index:
            with zf.open(META_PATH, "r") as f:
                meta = json.loads(f.read().decode("utf-8"))
            dim = int(meta["dim"])
            metric = meta["metric"]
            if q.shape[0] != dim:
                raise ValueError(f"Dimensión del query {q.shape[0]} != {dim}")
            # cargamos arrays
            X = np.load(io.BytesIO(zf.read(VECS_PATH)))
            M = np.load(io.BytesIO(zf.read(MAP_PATH)))  # int32[:,2]
            if metric == "cosine":
                q = q / (np.linalg.norm(q) + 1e-12)
                scores = X @ q  # similitud
                top = int(min(len(scores), max(k * oversample, k)))
                idx = np.argpartition(scores, -top)[-top:]
                idx = idx[np.argsort(-scores[idx])]
            else:
                # L2
                dif = X - q
                d2 = np.sum(dif * dif, axis=1)
                top = int(min(len(d2), max(k * oversample, k)))
                idx = np.argpartition(d2, top)[:top]
                idx = idx[np.argsort(d2[idx])]
            candidates = M[idx]  # (chunk_idx, row_idx)
            # post-filtrado por WHERE y selección de columnas
            # (para simplicidad, cargamos filas necesarias de cada chunk)
            chunks = meta["chunks"]
            rows = []
            for ci in np.unique(candidates[:, 0]):
                ci = int(ci)
                pth = chunks[ci]["path"]
                with zf.open(pth, "r") as f:
                    df = pd.read_parquet(f)  # pequeño -> simple
                # columnas auxiliares
                df = df.copy()
                df["__chunk_idx__"] = ci
                rows.append(df)
            big = pd.concat(rows, ignore_index=True) if rows else pd.DataFrame()

            # --- BLOQUE NUEVO: evita SettingWithCopyWarning y ordena según ANN ---
            # aseguramos tener el row_idx del Parquet para matchear con candidates
            big = big.reset_index().rename(columns={"index": "__row_idx__"}).copy()

            if where:
                try:
                    big = big.query(where)
                except Exception:
                    pass

            # armamos claves (chunk_idx, row_idx) -> orden y (opcional) score
            pairs = list(zip(candidates[:, 0].tolist(), candidates[:, 1].tolist()))
            order_key = {pair: i for i, pair in enumerate(pairs)}

            # si querés también exponer el score en modo índice:
            if meta["metric"] == "cosine":
                # reutilizamos 'scores' calculados más arriba
                score_key = {pair: float(scores[i]) for pair, i in zip(pairs, idx)}
            else:
                # en L2 usamos distancia positiva; convertimos a similitud negativa para ordenar
                score_key = {pair: float(-d2[i]) for pair, i in zip(pairs, idx)}

            # asignaciones seguras (sin warning)
            big.loc[:, "__ord__"] = big.apply(
                lambda r: order_key.get(
                    (int(r["__chunk_idx__"]), int(r["__row_idx__"])), 1e12
                ),
                axis=1,
            )
            big.loc[:, "__score__"] = big.apply(
                lambda r: score_key.get(
                    (int(r["__chunk_idx__"]), int(r["__row_idx__"])), float("nan")
                ),
                axis=1,
            )

            # top-k por orden del ANN
            big = big.nsmallest(k, "__ord__")

            keep = list(columns) if columns else [
                c for c in big.columns if not c.startswith("__")
            ]
            # devolvemos también el score cuando existe
            if "__score__" in big.columns:
                keep = keep + ["__score__"]

            return big[keep]
        else:
            # brute force exacto: escaneamos embedding en los chunks y devolvemos top-k
            chunks = _list_chunks(zf)
            all_rows = []
            col = "embedding"
            for _, pth in chunks:
                with zf.open(pth, "r") as f:
                    df = pd.read_parquet(f)
                if where:
                    try:
                        df = df.query(where)
                    except Exception:
                        pass
                if col not in df.columns or not len(df):
                    continue
                X = np.asarray(df[col].tolist(), dtype=np.float32)
                if X.ndim != 2 or not len(X):
                    continue
                if metric_fallback == "l2":
                    dif = X - q
                    score = -np.sum(dif * dif, axis=1)  # mayor es mejor
                else:
                    X = X / (np.linalg.norm(X, axis=1, keepdims=True) + 1e-12)
                    qq = q / (np.linalg.norm(q) + 1e-12)
                    score = X @ qq
                df = df.copy()
                df["__score__"] = score
                all_rows.append(df)
            big = pd.concat(all_rows, ignore_index=True) if all_rows else pd.DataFrame()
            big = (
                big.nlargest(k, "__score__")
                if "__score__" in big.columns
                else big.head(0)
            )
            keep = (
                list(columns)
                if columns
                else [c for c in big.columns if c != "embedding"]
            )
            if "__score__" in big.columns:
                keep = keep + ["__score__"]
            return big[keep]
