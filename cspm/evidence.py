"""Index of CTI evidence: which reports support which ATT&CK technique."""
from __future__ import annotations

from .mapping import related


def build_evidence_index(reports: list[dict]) -> dict[str, list[dict]]:
    """technique_id -> [{report_id, actors, evidence}]"""
    index: dict[str, list[dict]] = {}
    for r in reports:
        for t in r["techniques"]:
            index.setdefault(t["id"], []).append(
                {"report_id": r["report_id"], "actors": r.get("actors", []), "evidence": t["evidence"]})
    return index


def supporting_reports(tid: str, index: dict[str, list[dict]]) -> list[dict]:
    """All distinct reports citing `tid` or its parent/child technique."""
    seen: dict[str, dict] = {}
    for other, entries in index.items():
        if related(tid, other):
            for e in entries:
                seen.setdefault(e["report_id"], e)
    return list(seen.values())
