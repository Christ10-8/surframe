# -*- coding: utf-8 -*-
"""Índice MinMax por chunk para columnas ordenables (ej. timestamps)."""

from __future__ import annotations
from typing import Any, Dict, Iterable, List, Tuple


def build_minmax_index(values_by_chunk: Dict[str, Iterable[Any]]) -> Dict[str, Tuple[Any, Any]]:
    """
    Recibe: {chunk_id: iterable_de_valores}
    Devuelve: {chunk_id: (min, max)}
    """
    index: Dict[str, Tuple[Any, Any]] = {}
    for cid, it in values_by_chunk.items():
        vlist = list(it)
        if not vlist:
            continue
        index[cid] = (min(vlist), max(vlist))
    return index


def query_minmax(index: Dict[str, Tuple[Any, Any]], op: str, value: Any) -> List[str]:
    """
    Devuelve chunk_ids candidatos según la condición unaria sobre una columna.
    Soporta: '>=', '<=', '>', '<', '=='
    """
    out: List[str] = []
    for cid, (mn, mx) in index.items():
        if op == "==":
            if mn <= value <= mx:
                out.append(cid)
        elif op == ">=":
            if mx >= value:
                out.append(cid)
        elif op == "<=":
            if mn <= value:
                out.append(cid)
        elif op == ">":
            if mx > value:
                out.append(cid)
        elif op == "<":
            if mn < value:
                out.append(cid)
        else:
            raise ValueError(f"Operador no soportado: {op}")
    return out
