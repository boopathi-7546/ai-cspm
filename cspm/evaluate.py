"""Evaluation harness: detection accuracy, CTI extraction quality, baseline vs fused ranking.

Ground truth lives in data/ground_truth/ and was hand-labelled for the sample data.
Re-label it for your own configs/reports before quoting any number in a report.
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import CONFIG_DIR, GROUND_TRUTH_DIR, RESULTS_DIR
from .evidence import build_evidence_index, supporting_reports
from .fusion import score_findings
from .mapping import load_mapping, related
from .scanner import list_resources, load_config, scan_config


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)}


def evaluate_detection(config_dir: Path = CONFIG_DIR) -> dict:
    expected_all = json.loads((GROUND_TRUTH_DIR / "expected_findings.json").read_text())
    per_config, TP, FP, FN = {}, 0, 0, 0
    clean_total, clean_flagged = 0, 0
    for name, exp in expected_all.items():
        cfg = load_config(Path(config_dir) / f"{name}.json")
        found = {(f.resource, f.check_id) for f in scan_config(cfg)}
        exp_set = {tuple(x) for x in exp}
        tp, fp, fn = len(found & exp_set), len(found - exp_set), len(exp_set - found)
        per_config[name] = {**_prf(tp, fp, fn),
                            "false_positives": sorted(map(list, found - exp_set)),
                            "missed": sorted(map(list, exp_set - found))}
        TP, FP, FN = TP + tp, FP + fp, FN + fn
        flagged = {r for r, _ in found}
        expected_res = {r for r, _ in exp_set}
        clean = [r for r in list_resources(cfg) if r not in expected_res]
        clean_total += len(clean)
        clean_flagged += sum(1 for r in clean if r in flagged)
    return {"overall": _prf(TP, FP, FN), "per_config": per_config,
            "clean_resources": clean_total, "clean_resources_flagged": clean_flagged,
            "false_positive_resource_rate": round(clean_flagged / clean_total, 3) if clean_total else 0.0}


def _in_scope(tid: str, scope: set[str]) -> bool:
    return any(related(tid, m) for m in scope)


def evaluate_extraction(cti: list[dict], labels_path: Path | None = None) -> dict:
    """Exact-ID metrics over ALL labelled techniques, plus 'in-scope' metrics restricted to techniques
    that the misconfiguration mapping can use (matched with parent/child relatedness, as fusion does)."""
    labels = json.loads(Path(labels_path or GROUND_TRUTH_DIR / "cti_labels.json").read_text())
    scope = {m["technique_id"] for ms in load_mapping().values() for m in ms}
    by_id = {r["report_id"]: r for r in cti}
    TP = FP = FN = 0
    sc_truth = sc_got = sc_truth_hit = sc_got_hit = 0
    per_report = {}
    for rid, truth in labels.items():
        if rid.startswith("_") or rid not in by_id:
            continue
        got = {t["id"] for t in by_id[rid]["techniques"]}
        tru = set(truth)
        tp, fp, fn = len(got & tru), len(got - tru), len(tru - got)
        per_report[rid] = {**_prf(tp, fp, fn), "extra": sorted(got - tru), "missing": sorted(tru - got)}
        TP, FP, FN = TP + tp, FP + fp, FN + fn
        g = {x for x in got if _in_scope(x, scope)}
        t_ = {x for x in tru if _in_scope(x, scope)}
        sc_truth += len(t_)
        sc_got += len(g)
        sc_truth_hit += sum(1 for x in t_ if any(related(x, y) for y in g))
        sc_got_hit += sum(1 for y in g if any(related(y, x) for x in t_))
    methods = sorted({r["method"] for r in cti})
    unverified = sum(1 for r in cti for t in r["techniques"] if not t["evidence_verified"])
    rejected = sum(len(r.get("rejected", [])) for r in cti)
    in_scope = {"labelled_techniques": sc_truth, "extracted_techniques": sc_got,
                "precision": round(sc_got_hit / sc_got, 3) if sc_got else 1.0,
                "recall": round(sc_truth_hit / sc_truth, 3) if sc_truth else 1.0}
    return {"overall": _prf(TP, FP, FN), "in_scope": in_scope, "per_report": per_report, "methods": methods,
            "labelled_reports": len(per_report), "total_reports": len(cti),
            "techniques_with_unverified_evidence": unverified, "llm_outputs_rejected": rejected}


def evaluate_ranking(cti: list[dict], k: int = 5) -> dict:
    """Compare 'severity only' vs 'severity x criticality x CTI' on the vulnerable sample."""
    mapping, index = load_mapping(), build_evidence_index(cti)
    cfg = load_config(CONFIG_DIR / "vulnerable_env.json")
    scored = score_findings(scan_config(cfg), mapping, index, len(cti))
    moves = [abs(s.baseline_rank - s.fused_rank) for s in scored]
    top_b = {(s.resource, s.check_id) for s in scored if s.baseline_rank <= k}
    top_f = {(s.resource, s.check_id) for s in scored if s.fused_rank <= k}
    boosted = [s for s in scored if s.cti_report_count]
    return {"findings": len(scored), "mean_abs_rank_change": round(sum(moves) / len(moves), 2) if moves else 0,
            f"top{k}_overlap": f"{len(top_b & top_f)}/{k}", "findings_with_cti_support": len(boosted),
            "top_fused": [{"resource": s.resource, "check": s.check_id, "score": s.risk_score,
                           "priority": s.priority, "baseline_rank": s.baseline_rank,
                           "fused_rank": s.fused_rank} for s in scored[:k]]}


def evaluate_mapping_coverage(cti: list[dict]) -> dict:
    mapping, index = load_mapping(), build_evidence_index(cti)
    covered = {cid: bool(any(supporting_reports(m["technique_id"], index) for m in ms))
               for cid, ms in mapping.items()}
    return {"checks_mapped": len(mapping), "checks_with_cti_support": sum(covered.values()),
            "unsupported_checks": sorted(c for c, v in covered.items() if not v)}


def run_evaluation(cti: list[dict], out_dir: Path = RESULTS_DIR, write: bool = True) -> dict:
    result = {"detection": evaluate_detection(), "extraction": evaluate_extraction(cti),
              "ranking": evaluate_ranking(cti), "mapping_coverage": evaluate_mapping_coverage(cti),
              "note": "Detection numbers come from 3 hand-made sample configs. CTI numbers come from 8 paraphrased public reports labelled by one reader. Both sets are small, so treat the results as indicative only."}
    if write:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "evaluation_results.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
