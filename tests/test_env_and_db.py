import os
import sqlite3

from cspm import db
from cspm.env import load_dotenv, parse_env_text


def test_parse_env_text():
    text = """# comment
ANTHROPIC_API_KEY=abc123
export CTI_LLM_MODEL = "my-model"
QUOTED='single quoted'
INLINE=value # trailing comment
EMPTY=
bad line
1BAD=x
"""
    assert parse_env_text(text) == {"ANTHROPIC_API_KEY": "abc123", "CTI_LLM_MODEL": "my-model",
                                     "QUOTED": "single quoted", "INLINE": "value"}


def test_load_dotenv_priority_and_no_values_returned(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text("ZZ_TEST_A=from_file\nZZ_TEST_B=from_file\n", encoding="utf-8")
    monkeypatch.delenv("ZZ_TEST_A", raising=False)
    monkeypatch.setenv("ZZ_TEST_B", "from_environment")
    names = load_dotenv(f)
    assert names == ["ZZ_TEST_A"] and "from_file" not in names
    assert os.environ["ZZ_TEST_A"] == "from_file"
    assert os.environ["ZZ_TEST_B"] == "from_environment"  # real env wins
    load_dotenv(f, override=True)
    assert os.environ["ZZ_TEST_B"] == "from_file"
    monkeypatch.delenv("ZZ_TEST_A"); monkeypatch.delenv("ZZ_TEST_B")


def test_load_dotenv_missing_file(tmp_path):
    assert load_dotenv(tmp_path / "nope.env") == []


def test_db_migrates_database_from_previous_version(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""CREATE TABLE runs(run_id TEXT PRIMARY KEY, config_name TEXT, created_at TEXT, total_reports INTEGER);
    CREATE TABLE findings(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, resource TEXT, resource_type TEXT,
      check_id TEXT, title TEXT, severity TEXT, criticality TEXT, detail TEXT, category TEXT,
      technique_ids TEXT, cti_report_ids TEXT, cti_actors TEXT, cti_report_count INTEGER,
      total_reports INTEGER, cti_weight REAL, risk_raw REAL, risk_score REAL, priority TEXT,
      explanation TEXT, explanation_source TEXT, baseline_rank INTEGER, fused_rank INTEGER);""")
    conn.close()
    conn = db.connect(path)  # must add the missing column instead of failing on insert
    assert "remediation" in {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    from cspm.fusion import score_findings
    from cspm.scanner import scan_config
    scored = score_findings(scan_config({"s3_buckets": [{"name": "b", "public_read": True}]}), {}, {}, 0)
    db.save_run(conn, "r1", "x", scored, 0)
    assert db.load_findings(conn, "r1")[0]["remediation"]
