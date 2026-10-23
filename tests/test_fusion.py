from cspm.config import CONFIG_DIR
from cspm.evidence import build_evidence_index
from cspm.fusion import compute_risk, priority_for, score_findings
from cspm.mapping import load_mapping, related
from cspm.scanner import Finding, load_config, scan_config


def test_formula_values():
    raw, score, prio = compute_risk("Critical", "high", 0.0)
    assert (raw, score) == (30.0, 50.0) and prio == "Critical"
    raw, score, _ = compute_risk("Critical", "high", 1.0)
    assert (raw, score) == (60.0, 100.0)


def test_cti_zero_never_zeroes_a_critical_finding():
    """Regression for the multiplicative-zero flaw: Critical + no CTI must outrank Low + strong CTI."""
    crit_no_cti = compute_risk("Critical", "medium", 0.0)[1]
    low_cti = compute_risk("Low", "medium", 0.75)[1]
    assert crit_no_cti > 0 and crit_no_cti > low_cti


def test_cti_weight_only_boosts():
    base = compute_risk("High", "medium", 0.0)[0]
    assert compute_risk("High", "medium", 0.5)[0] == base * 1.5


def test_priority_bands():
    assert [priority_for(x) for x in (0, 14.9, 15, 30, 50, 100)] == ["Low", "Low", "Medium", "High", "Critical", "Critical"]


def test_related_techniques():
    assert related("T1552", "T1552.001") and related("T1078.004", "T1078")
    assert not related("T1078.004", "T1078.001") and not related("T1110", "T1190")


def _scored(reports):
    cfg = load_config(CONFIG_DIR / "vulnerable_env.json")
    return score_findings(scan_config(cfg), load_mapping(), build_evidence_index(reports), len(reports))


def test_scoring_with_and_without_cti():
    r = [{"report_id": "R1", "actors": ["X"], "techniques": [{"id": "T1530", "evidence": "e", "evidence_verified": True}]}]
    with_cti = {(s.resource, s.check_id): s for s in _scored(r)}
    s = with_cti[("customer-data-prod", "S3-01")]
    assert s.cti_report_count == 1 and s.cti_weight == 1.0 and s.cti_actors == ["X"]
    none = {(s.resource, s.check_id): s for s in _scored([])}
    assert none[("customer-data-prod", "S3-01")].cti_weight == 0.0
    assert none[("customer-data-prod", "S3-01")].risk_score > 0
    assert s.risk_score > none[("customer-data-prod", "S3-01")].risk_score


def test_ranks_are_permutations_and_explanation_present():
    scored = _scored([])
    n = len(scored)
    assert sorted(s.fused_rank for s in scored) == list(range(1, n + 1))
    assert sorted(s.baseline_rank for s in scored) == list(range(1, n + 1))
    assert all(s.check_id in s.explanation and "risk" in s.explanation for s in scored)
