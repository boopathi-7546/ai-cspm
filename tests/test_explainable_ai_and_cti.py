import pytest
from conftest import SAMPLE_REPORTS, SAMPLE_LABELS, FIXTURES
from cspm.attack_catalog import is_valid_technique, get_technique_info
from cspm.cti_extractor import extract_report, parse_report, validate_llm_payload
from cspm.evaluate import compare_extractors, evaluate_extraction
from cspm.fusion import ScoredFinding, build_explanation


def test_attack_catalog_validation():
    # Standard valid cloud & enterprise techniques
    assert is_valid_technique("T1078.004") is True
    assert is_valid_technique("T1530") is True
    assert is_valid_technique("T1190") is True
    assert is_valid_technique("T1552.001") is True

    # Hallucinated or non-existent techniques
    assert is_valid_technique("T9999") is False
    assert is_valid_technique("T0000.999") is False
    assert is_valid_technique("NOT_A_TECHNIQUE") is False
    assert is_valid_technique("") is False

    info = get_technique_info("T1530")
    assert "Cloud Storage" in info["name"]
    assert "Collection" in info["tactic"]


def test_finding_explanation_structure():
    sf = ScoredFinding(
        resource="my-prod-data",
        resource_type="s3_bucket",
        check_id="S3-01",
        title="S3 bucket is publicly readable",
        severity="Critical",
        criticality="high",
        detail="public_read = true",
        category="Storage",
        technique_ids=["T1530"],
        cti_report_ids=["R01_scarleteel"],
        cti_actors=["SCARLETEEL"],
        cti_report_count=1,
        total_reports=8,
        cti_weight=0.125,
        risk_raw=50.0,
        risk_score=83.3,
        priority="Critical",
        explanation_source="template",
        remediation="Remove public read access from bucket policy and ACLs.",
    )
    explanation = build_explanation(sf)
    # Plain English & resource & evidence
    assert "my-prod-data" in explanation
    assert "s3_bucket" in explanation
    assert "public_read = true" in explanation
    # Why it matters
    assert "Why this matters:" in explanation
    # Risk explanation
    assert "Risk analysis:" in explanation
    assert "Critical" in explanation
    assert "83.3/100" in explanation
    # ATT&CK technique
    assert "T1530" in explanation
    # Remediation
    assert "Recommended fix: Remove public read access" in explanation
    # Source marker
    assert sf.explanation_source == "template"


def test_llm_payload_validates_against_catalog():
    payload = {
        "techniques": [
            {"id": "T1530", "evidence": "stole data from the s3 bucket"},
            {"id": "T9999", "evidence": "hallucinated technique"},
            {"id": "INVALID", "evidence": "bad format"},
        ],
        "actors": ["APT-X"],
        "iocs": [],
    }
    text = "Attackers stole data from the s3 bucket in a targeted intrusion."
    kept, actors, iocs, rejected = validate_llm_payload(payload, text)

    kept_ids = [k["id"] for k in kept]
    assert "T1530" in kept_ids
    assert "T9999" not in kept_ids
    assert "INVALID" not in kept_ids

    # Verified evidence receives high confidence
    t1530 = next(k for k in kept if k["id"] == "T1530")
    assert t1530["evidence_verified"] is True
    assert t1530["confidence"] >= 0.85

    # Rejection list records the reasons
    assert any("T9999" in r and "unrecognized" in r for r in rejected)
    assert any("INVALID" in r and "malformed" in r for r in rejected)


EXPANDED_REPORTS = FIXTURES / "cti_expanded"
EXPANDED_LABELS = FIXTURES / "cti_labels_expanded.json"


def test_negative_samples_and_prompt_injection_resistance():
    # R9 is a clean infrastructure report with 0 attack activity
    r9 = parse_report(EXPANDED_REPORTS / "R9_clean_infrastructure.txt")
    res9 = extract_report(r9)
    assert res9["techniques"] == []

    # R10 contains prompt injection attempting to force T9999
    r10 = parse_report(EXPANDED_REPORTS / "R10_prompt_injection_test.txt")
    res10 = extract_report(r10)
    # T9999 must not be accepted
    assert not any(t["id"] == "T9999" for t in res10["techniques"])


def test_compare_extractors_on_labelled_dataset():
    comp = compare_extractors(EXPANDED_REPORTS, EXPANDED_LABELS, client=None)
    offline_eval = comp["offline"]
    overall = offline_eval["overall"]

    # Must produce actual metrics
    assert "precision" in overall
    assert "recall" in overall
    assert "f1" in overall
    assert "tp" in overall and "fp" in overall and "fn" in overall
    assert overall["precision"] > 0
    assert overall["recall"] > 0
    assert offline_eval["labelled_reports"] >= 3
