"""Flask backend: JSON API + static HTML/CSS/JS dashboard."""
from __future__ import annotations

import re
import sqlite3
from collections import Counter
from contextlib import closing
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from cspm import db, pipeline
from cspm.config import DB_PATH
from cspm.evaluate import run_evaluation
from cspm.scanner import parse_config

STATIC = Path(__file__).resolve().parent / "static"
MAX_UPLOAD_BYTES = 1_000_000
PRIORITIES = ("Critical", "High", "Medium", "Low")


def _safe_name(filename: str) -> str:
    stem = Path(filename or "uploaded").stem
    return re.sub(r"[^\w.-]", "_", stem)[:60] or "uploaded"


def _summary(findings: list[dict]) -> dict:
    by_pri = Counter(f["priority"] for f in findings)
    return {
        "total": len(findings),
        "by_priority": {p: by_pri.get(p, 0) for p in PRIORITIES},
        "with_cti_support": sum(1 for f in findings if f["cti_report_count"] > 0),
        "total_reports": findings[0]["total_reports"] if findings else 0,
    }


def create_app(db_path: Path | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    path = Path(db_path) if db_path else DB_PATH

    def connect() -> sqlite3.Connection:
        return db.connect(path)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        return resp

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error=f"file too large (limit {MAX_UPLOAD_BYTES // 1000} KB)"), 413

    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC, name)

    @app.get("/api/runs")
    def runs():
        with closing(connect()) as conn:
            return jsonify(db.list_runs(conn))

    @app.get("/api/runs/<run_id>")
    def run_detail(run_id):
        with closing(connect()) as conn:
            run = next((r for r in db.list_runs(conn) if r["run_id"] == run_id), None)
            if run is None:
                return jsonify(error="run not found"), 404
            findings = db.load_findings(conn, run_id)
        return jsonify(run=run, summary=_summary(findings), findings=findings)

    @app.get("/api/cti")
    def cti():
        with closing(connect()) as conn:
            return jsonify(db.load_cti(conn))

    @app.post("/api/scan/demo")
    def scan_demo():
        runs_ = pipeline.run_all(db_path=path)
        return jsonify(runs=runs_)

    @app.post("/api/scan")
    def scan_upload():
        f = request.files.get("file")
        if f is None or not f.filename:
            return jsonify(error="no file uploaded (field name: file)"), 400
        suffix = Path(f.filename).suffix.lower()
        if suffix not in (".json", ".yaml", ".yml"):
            return jsonify(error="only .json, .yaml or .yml files are accepted"), 400
        try:
            cfg = parse_config(f.read().decode("utf-8"), suffix)
        except UnicodeDecodeError:
            return jsonify(error="file is not valid UTF-8 text"), 400
        except ValueError as exc:  # includes json.JSONDecodeError
            return jsonify(error=f"invalid config: {exc}"), 400
        except Exception:
            return jsonify(error="could not parse file as JSON/YAML"), 400
        with closing(connect()) as conn:
            cti_ = pipeline.get_cti()
            db.save_cti(conn, cti_)
            try:
                run_id, scored = pipeline.run_scan_dict(cfg, _safe_name(f.filename), cti_, conn)
            except (KeyError, TypeError, AttributeError, ValueError):
                return jsonify(error="config structure is invalid (e.g. a resource is missing its 'name' "
                                     "or a field has the wrong type)"), 400
        return jsonify(run_id=run_id, findings=len(scored))

    @app.get("/api/evaluation")
    def evaluation():
        return jsonify(run_evaluation(pipeline.get_cti(), write=False))

    return app
