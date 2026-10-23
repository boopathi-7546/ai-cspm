from conftest import SAMPLE_REPORTS
from cspm.cti_extractor import (extract_iocs, extract_offline, extract_report, parse_report,
                                validate_llm_payload)


def rep(name):
    return parse_report(SAMPLE_REPORTS / f"{name}.txt")


def ids(res):
    return {t["id"] for t in res["techniques"]}


def test_offline_picks_explicit_ids():
    res = extract_offline(rep("R1_cloud_credential_theft"))
    assert ids(res) == {"T1552.001", "T1078.004", "T1530"}
    assert res["actors"] == ["CloudHarvest"]
    assert all(t["evidence"] for t in res["techniques"])


def test_offline_keyword_fallback_when_no_ids():
    res = extract_offline(rep("R6_log_tampering"))
    assert {"T1562.008", "T1078.004"} <= ids(res)
    assert "LogGhost" in res["actors"]


def test_ioc_extraction_validates_ips_and_hashes():
    iocs = extract_iocs("hit 203.0.113.45 and 999.1.1.1 via evil.example-c2.com hash "
                        + "a" * 64 + " and " + "b" * 32)
    assert iocs["ipv4"] == ["203.0.113.45"]
    assert iocs["domains"] == ["evil.example-c2.com"]
    assert iocs["sha256"] == ["a" * 64] and iocs["md5"] == ["b" * 32]


def test_llm_validation_rejects_hallucinations():
    text = "The actor used stolen keys to read a bucket. Nothing else happened."
    payload = {"techniques": [
        {"id": "T1530", "evidence": "The actor used stolen keys to read a bucket."},   # verified
        {"id": "T1486", "evidence": "They encrypted everything."},                    # invented evidence
        {"id": "T99", "evidence": "x"},                                               # malformed
        {"id": "T1078.004", "evidence": "paraphrased, not in report"}],               # not in text
        "actors": ["A" * 200, "RealActor"], "iocs": ["203.0.113.9", "not an ioc"]}
    kept, actors, iocs, rejected = validate_llm_payload(payload, text)
    assert [t["id"] for t in kept] == ["T1530"] and kept[0]["evidence_verified"]
    assert actors == ["RealActor"] and iocs["ipv4"] == ["203.0.113.9"]
    assert len(rejected) == 3


def test_llm_validation_keeps_id_literally_in_text_even_if_evidence_paraphrased():
    kept, *_ = validate_llm_payload({"techniques": [{"id": "T1190", "evidence": "paraphrase"}]},
                                    "Exploited app (T1190).")
    assert kept[0]["id"] == "T1190" and not kept[0]["evidence_verified"]


def test_llm_failure_falls_back_to_offline():
    class Boom:
        class messages:
            @staticmethod
            def create(**kw):
                raise RuntimeError("no network")
    res = extract_report(rep("R3_exposed_services"), client=Boom())
    assert res["method"].startswith("offline") and {"T1190", "T1133"} <= ids(res)
