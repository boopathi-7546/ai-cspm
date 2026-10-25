import json

from cspm import db, pipeline
from cspm.config import CONFIG_DIR
from cspm.cti_extractor import extract_corpus
from conftest import SAMPLE_LABELS, SAMPLE_REPORTS
from cspm.evaluate import evaluate_detection, evaluate_extraction, run_evaluation


def test_detection_matches_ground_truth_exactly():
    res = evaluate_detection()
    assert res["overall"]["precision"] == 1.0 and res["overall"]["recall"] == 1.0, res
    assert res["false_positive_resource_rate"] == 0.0


def test_extraction_on_labelled_subset(tmp_path):
    cti = extract_corpus(SAMPLE_REPORTS, out_json=tmp_path / "x.json")
    assert len(cti) == 8
    res = evaluate_extraction(cti, SAMPLE_LABELS)
    assert res["overall"]["recall"] == 1.0, res


def test_end_to_end_run_persists_to_sqlite(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "EXTRACTED_JSON", tmp_path / "cti.json")
    monkeypatch.setattr("cspm.cti_extractor.EXTRACTED_JSON", tmp_path / "cti.json")
    dbp = tmp_path / "t.db"
    runs = pipeline.run_all(CONFIG_DIR, dbp, refresh=True)
    assert set(runs) == {"vulnerable_env", "secure_env", "ambiguous_env", "workload_env"}
    conn = db.connect(dbp)
    vuln = db.load_findings(conn, runs["vulnerable_env"])
    assert len(vuln) == 24 and vuln[0]["fused_rank"] == 1
    assert [f["fused_rank"] for f in vuln] == sorted(f["fused_rank"] for f in vuln)
    assert db.load_findings(conn, runs["secure_env"]) == []
    assert all(isinstance(f["technique_ids"], list) for f in vuln)
    assert db.load_cti(conn)


def test_run_evaluation_writes_results(tmp_path):
    cti = extract_corpus(out_json=tmp_path / "x.json")
    res = run_evaluation(cti, out_dir=tmp_path)
    assert (tmp_path / "evaluation_results.json").exists()
    assert json.loads((tmp_path / "evaluation_results.json").read_text())["detection"]["overall"]["recall"] == 1.0
    assert res["ranking"]["findings"] == 24


def test_real_corpus_data_integrity():
    """The shipped CTI corpus and its labels must be well-formed and consistent with each other."""
    import re
    from cspm.config import CTI_DIR, GROUND_TRUTH_DIR
    from cspm.cti_extractor import parse_report
    reports = [parse_report(p) for p in sorted(CTI_DIR.glob("*.txt"))]
    assert len(reports) == 8
    for r in reports:
        assert r["title"] and "http" in r["source"] and r["published"] and len(r["text"]) > 200
    labels = json.loads((GROUND_TRUTH_DIR / "cti_labels.json").read_text())
    ids = {r["report_id"] for r in reports}
    for rid, techs in labels.items():
        if rid.startswith("_"):
            continue
        assert rid in ids
        assert techs and all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in techs)
