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
from __future__ import annotations
import json, re, zipfile, math
from collections import Counter
from typing import Dict, Any

EQ_PAT = re.compile(r"(?i)(\b[A-Za-z_]\w*)\s*(==|=)\s*('([^']*)'|\"([^\"]*)\"|([0-9.\-]+))")
RANGE_PAT = re.compile(r"(?i)(\b[A-Za-z_]\w*)\s*(>=|<=|>|<)\s*('([^']*)'|\"([^\"]*)\"|([0-9.\-]+))")
BETWEEN_PAT = re.compile(r"(?i)(\b[A-Za-z_]\w*)\s*BETWEEN\s*('([^']*)'|\"([^\"]*)\"|([0-9.\-]+))\s*AND\s*('([^']*)'|\"([^\"]*)\"|([0-9.\-]+))")
IN_PAT = re.compile(r"(?i)(\b[A-Za-z_]\w*)\s*IN\s*\(([^)]+)\)")

def _read_json(zf: zipfile.ZipFile, path: str) -> Dict[str, Any] | None:
    try:
        return json.loads(zf.read(path))
    except Exception:
        return None

def _iter_usage(zf: zipfile.ZipFile):
    for e in zf.infolist():
        if e.filename.startswith("profiles/usage/") and e.filename.endswith(".json"):
            try:
                obj = json.loads(zf.read(e.filename))
                if isinstance(obj, dict):
                    yield obj
            except Exception:
                pass

def _parse_where_stats(where: str) -> tuple[Counter, Counter]:
    eq, rng = Counter(), Counter()
    w = where or ""
    for m in EQ_PAT.finditer(w):
        eq[m.group(1)] += 1
    for m in RANGE_PAT.finditer(w):
        rng[m.group(1)] += 1
    for m in BETWEEN_PAT.finditer(w):
        rng[m.group(1)] += 1
    for m in IN_PAT.finditer(w):
        col = m.group(1)
        vals = [v.strip() for v in m.group(2).split(",")]
        eq[col] += max(1, len(vals))
    return eq, rng

def advise(path: str) -> Dict[str, Any]:
    with zipfile.ZipFile(path, "r") as zf:
        quality = _read_json(zf, "profiles/quality.json") or {}
        columns_meta = quality.get("columns", {}) if isinstance(quality, dict) else {}
        distinct = {c: (columns_meta.get(c, {}) or {}).get("distinct_est") for c in columns_meta}

        eq_cnt, rng_cnt = Counter(), Counter()
        reads = 0
        chunks_scanned = []
        for rec in _iter_usage(zf):
            reads += 1
            eq_c, rng_c = _parse_where_stats(rec.get("where") or "")
            eq_cnt.update(eq_c)
            rng_cnt.update(rng_c)
            cs = rec.get("chunks_scanned")
            if isinstance(cs, (int, float)):
                chunks_scanned.append(int(cs))

        p95_chunks = None
        if chunks_scanned:
            arr = sorted(chunks_scanned)
            k = max(0, min(len(arr) - 1, int(round(0.95 * (len(arr) - 1)))))
            p95_chunks = arr[k]

        bloom_candidates = [c for c, n in eq_cnt.most_common() if n >= 2]
        minmax_candidates = [c for c, n in rng_cnt.most_common() if n >= 2]

        partitions = []
        for c in bloom_candidates:
            d = distinct.get(c)
            if d is None:
                continue
            if 5 <= d <= 2000:
                partitions.append((c, int(d)))

        order_col = None
        if minmax_candidates:
            for c in minmax_candidates:
                if c in columns_meta:
                    order_col = c
                    break

        est = {}
        if p95_chunks:
            if partitions:
                c, d = partitions[0]
                denom = min(10.0, max(1.5, math.sqrt(float(d))))
                est["partitions"] = max(0.0, 1.0 - (1.0 / denom))
            if order_col:
                est["ordering"] = 0.3  # heurística conservadora

        rec_indexes = {
            "bloom": bloom_candidates[:5],
            "minmax": minmax_candidates[:5],
        }
        rec_partitions = [{"column": c, "distinct_est": d} for c, d in partitions[:3]]

        return {
            "reads_analyzed": reads,
            "top_eq": eq_cnt.most_common(10),
            "top_ranges": rng_cnt.most_common(10),
            "recommendations": {
                "indexes": rec_indexes,
                "partitions": rec_partitions,
                "order": order_col,
            },
            "estimated_savings": est,
        }
