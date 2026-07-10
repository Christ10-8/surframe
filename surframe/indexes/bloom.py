# -*- coding: utf-8 -*-
"""Bloom filter simple (doble hash via hashlib) + helpers para índice por chunk."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple
import math
import hashlib


def _hashes(item: str, m: int, k: int) -> List[int]:
    # Doble hash: h1, h2 → h(i) = (h1 + i*h2) % m
    b = item.encode("utf-8")
    h1 = int(hashlib.blake2b(b, digest_size=8).hexdigest(), 16)
    h2 = int(hashlib.sha256(b).hexdigest(), 16)
    return [((h1 + i * h2) % m) for i in range(k)]


@dataclass
class Bloom:
    m: int   # bits
    k: int   # hash functions
    bits: bytearray  # bitmap (m bits)

    @classmethod
    def with_fp_rate(cls, n: int, fp_rate: float = 0.01) -> "Bloom":
        m = max(8, int(-(n * math.log(fp_rate)) / (math.log(2) ** 2)))
        k = max(1, int((m / n) * math.log(2))) if n else 1
        nbytes = (m + 7) // 8
        return cls(m=m, k=k, bits=bytearray(nbytes))

    def add(self, item: str) -> None:
        for h in _hashes(item, self.m, self.k):
            byte_i = h // 8
            mask = 1 << (h % 8)
            self.bits[byte_i] |= mask

    def __contains__(self, item: str) -> bool:
        for h in _hashes(item, self.m, self.k):
            byte_i = h // 8
            mask = 1 << (h % 8)
            if (self.bits[byte_i] & mask) == 0:
                return False
        return True


def build_bloom_index(values_by_chunk: Dict[str, Iterable[str]], fp_rate: float = 0.01):
    """
    Devuelve: {chunk_id: Bloom}
    """
    index: Dict[str, Bloom] = {}
    for cid, vals in values_by_chunk.items():
        vset = {str(v) for v in vals if v is not None}
        bloom = Bloom.with_fp_rate(n=max(1, len(vset)), fp_rate=fp_rate)
        for v in vset:
            bloom.add(v)
        index[cid] = bloom
    return index


def query_bloom(index: Dict[str, Bloom], value: str) -> List[str]:
    """
    Devuelve chunk_ids donde el bloom de ese chunk posiblemente contenga 'value'.
    """
    out: List[str] = []
    for cid, bloom in index.items():
        if value in bloom:
            out.append(cid)
    return out
