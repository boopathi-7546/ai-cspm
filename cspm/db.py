"""SQLite persistence for runs, findings and CTI evidence."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .config import DB_PATH
from .fusion import ScoredFinding

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  run_id TEXT PRIMARY KEY, config_name TEXT, created_at TEXT, total_reports INTEGER);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, resource TEXT, resource_type TEXT,
  check_id TEXT, title TEXT, severity TEXT, criticality TEXT, detail TEXT, category TEXT,
  technique_ids TEXT, cti_report_ids TEXT, cti_actors TEXT, cti_report_count INTEGER,
  total_reports INTEGER, cti_weight REAL, risk_raw REAL, risk_score REAL, priority TEXT,
  explanation TEXT, explanation_source TEXT, baseline_rank INTEGER, fused_rank INTEGER,
  remediation TEXT DEFAULT '',
  FOREIGN KEY(run_id) REFERENCES runs(run_id));
CREATE TABLE IF NOT EXISTS cti_techniques(
  report_id TEXT, technique_id TEXT, evidence TEXT, evidence_verified INTEGER, actors TEXT, method TEXT);
"""
JSON_COLS = ("technique_ids", "cti_report_ids", "cti_actors")


def connect(path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    from .auth import init_auth_db
    init_auth_db(conn)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    if "remediation" not in cols:  # database created by an older version of the project
        conn.execute("ALTER TABLE findings ADD COLUMN remediation TEXT DEFAULT ''")
        conn.commit()
    return conn


def save_cti(conn: sqlite3.Connection, reports: list[dict]) -> None:
    conn.execute("DELETE FROM cti_techniques")
    for r in reports:
        for t in r["techniques"]:
            conn.execute("INSERT INTO cti_techniques VALUES (?,?,?,?,?,?)",
                         (r["report_id"], t["id"], t["evidence"], int(t["evidence_verified"]),
                          json.dumps(r["actors"]), r["method"]))
    conn.commit()


def save_run(conn: sqlite3.Connection, run_id: str, config_name: str,
             scored: list[ScoredFinding], total_reports: int) -> None:
    conn.execute("INSERT INTO runs VALUES (?,?,?,?)",
                 (run_id, config_name, datetime.now(timezone.utc).isoformat(timespec="seconds"), total_reports))
    for s in scored:
        d = s.to_dict()
        d.pop("cti_multiplier")
        for c in JSON_COLS:
            d[c] = json.dumps(d[c])
        d["run_id"] = run_id
        cols = ",".join(d)
        conn.execute(f"INSERT INTO findings({cols}) VALUES ({','.join('?' * len(d))})", list(d.values()))
    conn.commit()


def _decode(row: sqlite3.Row) -> dict:
    d = dict(row)
    for c in JSON_COLS:
        d[c] = json.loads(d[c])
    return d


def list_runs(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM runs ORDER BY created_at DESC, rowid DESC")]


def load_findings(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute("SELECT * FROM findings WHERE run_id=? ORDER BY fused_rank", (run_id,))
    return [_decode(r) for r in rows]


def load_cti(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM cti_techniques ORDER BY technique_id, report_id")]
