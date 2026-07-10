from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Sequence
import json
import os

import numpy as np
import pandas as pd

# Nos apoyamos en el reader Core
try:
    from ..io import read as _read
except Exception as e:
    raise RuntimeError("surframe.ann.flat requiere surframe.io.read") from e


def _profiles_dir(container: str) -> str:
    """
    Devuelve la carpeta donde se guardan perfiles/índices.
    - Si el contenedor es un directorio: <container>/profiles
    - Si es un archivo (p.ej. .surx):  <container>.profiles (carpeta hermana)
    """
    if os.path.isdir(container):
        p = os.path.join(container, "profiles")
    else:
        p = container + ".profiles"
    os.makedirs(p, exist_ok=True)
    return p


def _to_matrix(seq_of_vecs: Iterable[Sequence[float]]) -> np.ndarray:
    arr = np.array(list(seq_of_vecs), dtype=float)
    if arr.ndim != 2:
        raise ValueError("La columna de embeddings debe ser 2D (lista de listas).")
    return arr


def _cosine_scores(mat: np.ndarray, q: np.ndarray) -> np.ndarray:
    # mat: (N, D), q: (D,)
    denom = (np.linalg.norm(mat, axis=1) * (np.linalg.norm(q) + 1e-12)) + 1e-12
    return (mat @ q) / denom


def _euclidean_scores(mat: np.ndarray, q: np.ndarray) -> np.ndarray:
    # Distancia menor = mejor; devolvemos score negativo para ordenar desc
    return -np.linalg.norm(mat - q, axis=1)


def ann_build(
    container: str,
    *,
    col: str,
    metric: str = "cosine",
    dim: Optional[int] = None,
    id_col: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Construye un índice 'flat' (brute force) y lo persiste en profiles/ann_flat.{npz,json}.
    - container: ruta a .surx ya escrito con surframe.write(...)
    - col: nombre de la columna con embeddings (lista de floats)
    - metric: "cosine" o "euclidean"
    - dim: dimensión esperada (opcional, valida si coincide)
    - id_col: columna de ids a devolver (si None -> usa 'id' si existe o rango)
    """
    df: pd.DataFrame = _read(container)
    if col not in df.columns:
        raise ValueError(f"Columna de embeddings inexistente: {col}")

    vecs = _to_matrix(df[col])
    if dim is not None and vecs.shape[1] != int(dim):
        raise ValueError(f"Dimensión esperada {dim}, pero la columna tiene {vecs.shape[1]}")

    # IDs
    if id_col and id_col in df.columns:
        ids = df[id_col].to_numpy()
        id_kind, id_name = "col", id_col
    elif "id" in df.columns:
        ids = df["id"].to_numpy()
        id_kind, id_name = "col", "id"
    else:
        ids = np.arange(len(df))
        id_kind, id_name = "range", None

    prof = _profiles_dir(container)
    np.savez(os.path.join(prof, "ann_flat.npz"), vecs=vecs, ids=ids)
    meta = {
        "col": col,
        "metric": metric,
        "dim": int(vecs.shape[1]),
        "id_kind": id_kind,
        "id_col": id_name,
        "container": container,
    }
    with open(os.path.join(prof, "ann_flat_meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False)

    return {"ok": True, "index_path": os.path.join(prof, "ann_flat.npz")}


def ann_query(
    container: str,
    *,
    col: str,
    q: Optional[Sequence[float]] = None,
    k: int = 5,
    metric: str = "cosine",
    where: Optional[Dict[str, Any]] = None,
    id_col: str = "id",
    columns: Optional[Sequence[str]] = None,
) -> pd.DataFrame:
    """
    Consulta ANN 'flat'. Si `q` es None intenta usar el primer vector de la columna.
    - `where`: dict simple {col: valor|[valores]} aplicado con .isin / ==
    - `columns`: columnas a devolver además del id_col; se agrega __score__
    """
    prof = _profiles_dir(container)
    npz_path = os.path.join(prof, "ann_flat.npz")
    meta_path = os.path.join(prof, "ann_flat_meta.json")
    if not (os.path.exists(npz_path) and os.path.exists(meta_path)):
        raise FileNotFoundError("Índice flat no encontrado; ejecute ann_build() primero.")

    data = np.load(npz_path)
    vecs: np.ndarray = data["vecs"]
    ids: np.ndarray = data["ids"]

    with open(meta_path, "r", encoding="utf-8") as fh:
        meta = json.load(fh)
    if meta.get("col") != col:
        # Permitimos mismatch si el usuario sabe lo que hace, pero avisamos.
        pass

    df: pd.DataFrame = _read(container)
    if col not in df.columns:
        raise ValueError(f"Columna de embeddings inexistente: {col}")

    mask = np.ones(len(df), dtype=bool)
    if where:
        for c, v in where.items():
            if c not in df.columns:
                raise ValueError(f"Filtro usa columna inexistente: {c}")
            if isinstance(v, (list, tuple, set)):
                mask &= df[c].isin(list(v)).to_numpy()
            else:
                mask &= (df[c] == v).to_numpy()

    if q is None:
        q = df[col].iloc[0]
    qvec = np.array(q, dtype=float).reshape(-1)
    if qvec.size != int(meta.get("dim", vecs.shape[1])):
        raise ValueError(f"Dim de query {qvec.size} != índice {meta.get('dim')}")

    mat = vecs[mask]
    if metric == "cosine":
        scores = _cosine_scores(mat, qvec)
    elif metric == "euclidean":
        scores = _euclidean_scores(mat, qvec)
    else:
        raise ValueError("Métrica no soportada (use 'cosine' o 'euclidean').")

    k = int(max(1, min(int(k), len(scores))))
    ord_idx = np.argsort(-scores)[:k]  # mayor score primero
    sel = np.flatnonzero(mask)[ord_idx]

    # Armar salida
    out_cols = [id_col] if columns is None else list(columns)
    out = df.loc[sel, out_cols].copy()
    out["__score__"] = scores[ord_idx]
    return out
