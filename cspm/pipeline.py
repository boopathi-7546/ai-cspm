"""End-to-end orchestration: extract CTI -> scan -> map -> fuse -> persist."""
from __future__ import annotations

import uuid
from pathlib import Path

from . import db
from .config import CONFIG_DIR, CTI_DIR, DB_PATH, EXTRACTED_JSON
from .cti_extractor import extract_corpus, load_extracted
from .evidence import build_evidence_index
from .fusion import polish_explanations, score_findings
from .llm import get_client
from .mapping import load_mapping
from .scanner import load_config, scan_config


def get_cti(refresh: bool = False, use_llm: bool = False, cti_dir: Path = CTI_DIR) -> list[dict]:
    """Return extracted CTI, re-extracting if requested or no cache exists."""
    if refresh or not Path(EXTRACTED_JSON).exists():
        client = get_client() if use_llm else None
        if use_llm and client is None:
            print("[warn] --llm requested but ANTHROPIC_API_KEY / anthropic SDK not available; using offline extractor")
        return extract_corpus(cti_dir, client=client, out_json=EXTRACTED_JSON)
    return load_extracted()


def run_scan(config_path, cti: list[dict], conn, use_llm_explain: bool = False) -> tuple[str, list]:
    return run_scan_dict(load_config(config_path), Path(config_path).stem, cti, conn, use_llm_explain)


def run_scan_dict(cfg: dict, name: str, cti: list[dict], conn, use_llm_explain: bool = False) -> tuple[str, list]:
    mapping = load_mapping()
    index = build_evidence_index(cti)
    scored = score_findings(scan_config(cfg), mapping, index, total_reports=len(cti))
    if use_llm_explain:
        client = get_client()
        if client:
            polish_explanations(scored, client)
    run_id = uuid.uuid4().hex[:8]
    db.save_run(conn, run_id, name, scored, len(cti))
    return run_id, scored


def run_all(config_dir: Path = CONFIG_DIR, db_path: Path = DB_PATH, refresh: bool = False,
            use_llm: bool = False, use_llm_explain: bool = False) -> dict[str, str]:
    conn = db.connect(db_path)
    cti = get_cti(refresh=refresh, use_llm=use_llm)
    db.save_cti(conn, cti)
    runs = {}
    for p in sorted(Path(config_dir).glob("*.json")) + sorted(Path(config_dir).glob("*.y*ml")):
        run_id, scored = run_scan(p, cti, conn, use_llm_explain)
        runs[p.stem] = run_id
    conn.close()
    return runs
