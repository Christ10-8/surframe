# -*- coding: utf-8 -*-
"""HyperLogLog (HLL) simple para estimar cardinalidad (distinct)."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Dict, Any
import math
import hashlib


def _hash64(x: str) -> int:
    # 64-bit hash reproducible
    return int(hashlib.blake2b(x.encode("utf-8"), digest_size=8).hexdigest(), 16)


def _leading_zeros(x: int, bits: int) -> int:
    # Cuenta ceros a la izquierda en 'bits' menos significativos de x
    if x == 0:
        return bits
    return (x.bit_length() ^ bits)


@dataclass
class HLL:
    p: int  # precision, m = 2**p
    m: int
    reg: bytearray  # registers

    @classmethod
    def create(cls, p: int = 12) -> "HLL":
        # p=12 => m=4096 registers (buena precisión ~2%)
        m = 1 << p
        return cls(p=p, m=m, reg=bytearray(m))

    def add(self, item: str) -> None:
        h = _hash64(item)
        idx = h >> (64 - self.p)                  # primeros p bits
        w = (h << self.p) & ((1 << 64) - 1)       # restante (64-p bits)
        rho = _leading_zeros(w, 64 - self.p) + 1  # posición del primer 1
        if rho > 255:
            rho = 255
        if self.reg[idx] < rho:
            self.reg[idx] = rho

    def merge(self, other: "HLL") -> None:
        if self.p != other.p:
            raise ValueError("HLL precision mismatch")
        for i in range(self.m):
            if other.reg[i] > self.reg[i]:
                self.reg[i] = other.reg[i]

    def estimate(self) -> float:
        # Estimación estándar HLL con correcciones
        m = float(self.m)
        # α_m
        if self.m == 16:
            alpha = 0.673
        elif self.m == 32:
            alpha = 0.697
        elif self.m == 64:
            alpha = 0.709
        else:
            alpha = 0.7213 / (1 + 1.079 / m)
        # E = α m^2 / sum(2^{-M[i]})
        inv_sum = 0.0
        zeros = 0
        for r in self.reg:
            inv_sum += 2.0 ** (-int(r))
            if r == 0:
                zeros += 1
        E = alpha * (m * m) / inv_sum

        # Small-range correction (linear counting)
        if zeros > 0:
            LC = m * math.log(m / float(zeros))
            if LC <= 2.5 * m:
                return LC

        # Large-range correction (no necesaria con 64-bit en nuestro rango)
        return E

    def to_json(self) -> Dict[str, Any]:
        return {"p": self.p, "m": self.m, "reg_hex": self.reg.hex()}

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "HLL":
        return cls(p=d["p"], m=d["m"], reg=bytearray.fromhex(d["reg_hex"]))
