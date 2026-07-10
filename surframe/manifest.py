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
"""Utilidades simples para manifest.json (cargar/validar mínima)."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import json
from pathlib import Path


@dataclass
class Manifest:
    version: int
    name: str
    schema: List[Dict[str, Any]]
    primary_key: Optional[List[str]] = None
    partitions: Optional[List[Dict[str, Any]]] = None
    indexes: Optional[Dict[str, Any]] = None
    lineage: Optional[Dict[str, Any]] = None

    @staticmethod
    def load(path: str | Path) -> "Manifest":
        with Path(path).open("r", encoding="utf-8") as f:
            obj = json.load(f)
        return Manifest(**obj)

    def dump(self, path: str | Path) -> None:
        with Path(path).open("w", encoding="utf-8") as f:
            json.dump(self.__dict__, f, ensure_ascii=False, indent=2)


def ensure_minimal(manifest: Dict[str, Any]) -> None:
    required = ["version", "name", "schema"]
    for k in required:
        if k not in manifest:
            raise ValueError(f"Manifest inválido: falta '{k}'")
