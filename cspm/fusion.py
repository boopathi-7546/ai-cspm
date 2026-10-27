"""Risk fusion: Severity x AssetCriticality x (1 + CTI relevance weight).

The CTI term is a *relevance weight* (share of loaded reports that reference the mapped
technique). It is NOT an attack probability. Using (1 + weight) means CTI evidence boosts a
finding (x1 .. x2) but a technique absent from a small corpus never erases a Critical finding.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, field

from .config import CRITICALITY_SCORE, MAX_RAW_SCORE, PRIORITY_BANDS, SEVERITY_SCORE
from .evidence import supporting_reports
from .mapping import technique_ids
from .scanner import Finding


@dataclass
class ScoredFinding:
    resource: str
    resource_type: str
    check_id: str
    title: str
    severity: str
    criticality: str
    detail: str
    category: str
    technique_ids: list = field(default_factory=list)
    cti_report_ids: list = field(default_factory=list)
    cti_actors: list = field(default_factory=list)
    cti_report_count: int = 0
    total_reports: int = 0
    cti_weight: float = 0.0
    cti_multiplier: float = 1.0
    risk_raw: float = 0.0
    risk_score: float = 0.0
    priority: str = "Low"
    explanation: str = ""
    explanation_source: str = "template"
    remediation: str = ""
    baseline_rank: int = 0
    fused_rank: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def priority_for(score: float) -> str:
    for floor, label in PRIORITY_BANDS:
        if score >= floor:
            return label
    return "Low"


def compute_risk(severity: str, criticality: str, cti_weight: float) -> tuple[float, float, str]:
    sev = SEVERITY_SCORE[severity]
    crit = CRITICALITY_SCORE.get(str(criticality).lower(), CRITICALITY_SCORE["medium"])
    raw = sev * crit * (1.0 + cti_weight)
    score = round(raw / MAX_RAW_SCORE * 100, 1)
    return round(raw, 2), score, priority_for(score)


def build_explanation(sf: ScoredFinding) -> str:
    tech = ", ".join(sf.technique_ids) or "None mapped"
    if sf.cti_report_count:
        actors = f" (threat actors identified: {', '.join(sf.cti_actors)})" if sf.cti_actors else ""
        cti_text = (
            f"Active threat intelligence matches {sf.cti_report_count} of {sf.total_reports} loaded report(s) "
            f"({', '.join(sf.cti_report_ids)}) referencing technique(s) {tech}{actors}. "
        )
    else:
        cti_text = (
            f"Associated with technique(s) {tech}, with no currently active threat intelligence mentions in the loaded corpus. "
        )

    evidence_text = f"Configuration evidence: {sf.detail}." if sf.detail else ""
    return (
        f"Resource '{sf.resource}' ({sf.resource_type}) failed check {sf.check_id}: {sf.title}. "
        f"{evidence_text} "
        f"Why this matters: This misconfiguration creates an exploitable exposure that adversaries can leverage. "
        f"{cti_text}"
        f"Risk analysis: Rule severity '{sf.severity}' combined with asset criticality '{sf.criticality}' "
        f"and CTI empirical weight {sf.cti_weight:.2f} results in a fused risk score of {sf.risk_score}/100 ({sf.priority} priority). "
        f"Recommended fix: {sf.remediation}"
    )


def score_findings(findings: list[Finding], mapping: dict, evidence_index: dict,
                   total_reports: int) -> list[ScoredFinding]:
    scored: list[ScoredFinding] = []
    for f in findings:
        tids = technique_ids(mapping, f.check_id)
        reports: dict[str, dict] = {}
        for tid in tids:
            for e in supporting_reports(tid, evidence_index):
                reports.setdefault(e["report_id"], e)
        actors = sorted({a for e in reports.values() for a in e["actors"]})
        weight = len(reports) / total_reports if total_reports else 0.0
        raw, score, prio = compute_risk(f.severity, f.criticality, weight)
        sf = ScoredFinding(
            resource=f.resource, resource_type=f.resource_type, check_id=f.check_id, title=f.title,
            severity=f.severity, criticality=f.criticality, detail=f.detail, category=f.category,
            technique_ids=tids, cti_report_ids=sorted(reports), cti_actors=actors,
            cti_report_count=len(reports), total_reports=total_reports,
            cti_weight=round(weight, 4), cti_multiplier=round(1 + weight, 4),
            risk_raw=raw, risk_score=score, priority=prio, remediation=f.remediation)
        sf.explanation = build_explanation(sf)
        scored.append(sf)

    # Ranks: baseline = severity only; fused = full risk score. Deterministic tie-breaks.
    by_base = sorted(scored, key=lambda s: (-SEVERITY_SCORE[s.severity], s.check_id, s.resource))
    for i, s in enumerate(by_base, 1):
        s.baseline_rank = i
    by_fused = sorted(scored, key=lambda s: (-s.risk_score, s.check_id, s.resource))
    for i, s in enumerate(by_fused, 1):
        s.fused_rank = i
    return by_fused


POLISH_SYSTEM = (
    "Rewrite the security finding below as a clear 2-3 sentence explanation for a cloud engineer. "
    "Use ONLY the facts provided; do not add new facts, numbers, techniques or remediation claims. "
    "Keep the technique IDs, report IDs and the final risk score exactly as given."
)


def polish_explanations(scored: list[ScoredFinding], client) -> None:
    """Optional: LLM rewrites each template explanation. Falls back silently to the template."""
    from .llm import complete
    for sf in scored:
        try:
            text = complete(client, POLISH_SYSTEM, sf.explanation, max_tokens=300).strip()
            if text and sf.risk_score and str(sf.risk_score) in text:
                sf.explanation, sf.explanation_source = text, "llm"
        except Exception:
            pass
