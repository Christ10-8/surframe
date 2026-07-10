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
"""Registro básico de plugins de índices (minmax, bloom)."""

from __future__ import annotations
from typing import Callable, Dict, Any

_REGISTRY: Dict[str, Dict[str, Callable[..., Any]]] = {
    # "minmax": {"build": fn, "query": fn},
    # "bloom":  {"build": fn, "query": fn},
}


def register(index_name: str, build_fn, query_fn) -> None:
    _REGISTRY[index_name] = {"build": build_fn, "query": query_fn}


def get(index_name: str) -> Dict[str, Callable[..., Any]]:
    return _REGISTRY[index_name]
