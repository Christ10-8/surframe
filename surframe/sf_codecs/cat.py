# -*- coding: utf-8 -*-
"""Categorical profile stub (top-K dict, escape)."""
from __future__ import annotations
from typing import Dict, Any

def estimate_profile(values_count: int, max_dict: int = 65536) -> Dict[str, Any]:
    return {"type": "cat", "values_count": int(values_count), "max_dict": int(max_dict), "status": "stub"}
