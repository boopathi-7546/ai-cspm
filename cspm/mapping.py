"""Curated misconfiguration -> MITRE ATT&CK technique mapping."""
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

from .config import MAPPING_CSV


def load_mapping(path: Path = MAPPING_CSV) -> dict[str, list[dict]]:
    """check_id -> [{technique_id, technique_name, rationale}, ...]"""
    mapping: dict[str, list[dict]] = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            mapping[row["check_id"].strip()].append({
                "technique_id": row["technique_id"].strip(),
                "technique_name": row["technique_name"].strip(),
                "rationale": row.get("rationale", "").strip(),
            })
    return dict(mapping)


def base_id(tid: str) -> str:
    """T1078.004 -> T1078"""
    return tid.split(".")[0]


def related(a: str, b: str) -> bool:
    """Two technique IDs are related if identical, or one is the parent of the other.
    (T1552 relates to T1552.001; T1078.004 does NOT relate to T1078.001.)"""
    return a == b or a == base_id(b) or b == base_id(a)


def technique_ids(mapping: dict, check_id: str) -> list[str]:
    return [m["technique_id"] for m in mapping.get(check_id, [])]
