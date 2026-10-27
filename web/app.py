import hmac
import os
import re
import secrets
import sqlite3
import time
from collections import Counter
from contextlib import closing
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, request, send_from_directory, session

from cspm import auth, db, pipeline
from cspm.config import DB_PATH
from cspm.env import load_dotenv
from cspm.evaluate import run_evaluation
from cspm.scanner import parse_config

load_dotenv()

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
    secret = os.getenv("CSPM_SECRET_KEY")
    if not secret or "generate-a-strong" in secret:
        secret = "ai-cspm-insecure-dev-secret-change-me"
    app.secret_key = secret

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("CSPM_COOKIE_SECURE", "false").lower() == "true"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=int(os.getenv("CSPM_SESSION_HOURS", "8")))

    path = Path(db_path) if db_path else DB_PATH

    def connect() -> sqlite3.Connection:
        return db.connect(path)

    def is_auth_required() -> bool:
        return app.config.get("REQUIRE_AUTH", False) or os.getenv("CSPM_REQUIRE_AUTH", "false").lower() in ("true", "1", "yes")

    def check_session_validity() -> bool:
        user = session.get("user")
        if not user:
            return False
        login_time = session.get("login_time", 0)
        max_age = int(os.getenv("CSPM_SESSION_TIMEOUT_SECONDS", 8 * 3600))
        if login_time and (time.time() - login_time > max_age):
            session.clear()
            return False
        return True

    def get_csrf_token() -> str:
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_hex(32)
            session["csrf_token"] = token
        return token

    def validate_csrf(token_override: str | None = None) -> bool:
        expected = session.get("csrf_token")
        token = (
            token_override
            or request.form.get("csrf_token")
            or request.headers.get("X-CSRFToken")
            or request.headers.get("X-CSRF-Token")
            or (request.is_json and (request.get_json(silent=True) or {}).get("csrf_token"))
        )
        if not expected or not token or not hmac.compare_digest(str(token), str(expected)):
            return False
        return True

    def require_auth(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if is_auth_required():
                if not check_session_validity():
                    return jsonify(error="Authentication required. Please log in first."), 401
            return fn(*args, **kwargs)
        return wrapper

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        return resp

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error=f"file too large (limit {MAX_UPLOAD_BYTES // 1000} KB)"), 413

    # Static Assets & Navigation Views
    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/dashboard")
    def dashboard():
        if is_auth_required() and not check_session_validity():
            return redirect("/login?next=/dashboard")
        return send_from_directory(STATIC, "index.html")

    @app.get("/login")
    def login_view():
        if check_session_validity():
            return redirect(request.args.get("next") or "/#dashboard")
        get_csrf_token()
        return send_from_directory(STATIC, "login.html")

    @app.get("/logout")
    def logout_view():
        session.clear()
        return redirect("/login?logged_out=1")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC, name)

    # CSRF & Authentication API
    @app.get("/api/auth/csrf")
    def get_csrf():
        return jsonify(csrf_token=get_csrf_token())

    @app.post("/login")
    def login_form():
        client_ip = request.remote_addr or "127.0.0.1"
        if not auth.login_rate_limiter.is_allowed(client_ip):
            return redirect("/login?error=Too+many+failed+attempts.+Please+wait+60+seconds.")

        if not validate_csrf():
            return redirect("/login?error=Invalid+or+missing+CSRF+token.+Please+refresh+and+try+again.")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with closing(connect()) as conn:
            user = auth.verify_user(conn, username, password)

        if not user:
            auth.login_rate_limiter.record_attempt(client_ip)
            return redirect("/login?error=Invalid+username+or+password.")

        auth.login_rate_limiter.reset(client_ip)
        session.permanent = True
        session["user"] = user["username"]
        session["role"] = user["role"]
        session["login_time"] = time.time()
        next_url = request.args.get("next") or request.form.get("next") or "/#dashboard"
        return redirect(next_url)

    @app.post("/api/auth/login")
    def login():
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = data.get("password", "")
        client_ip = request.remote_addr or "127.0.0.1"

        if not auth.login_rate_limiter.is_allowed(client_ip):
            return jsonify(error="Too many failed login attempts. Please wait 60 seconds."), 429

        # Validate CSRF when sent via form or explicitly supplied in payload
        if request.form and not validate_csrf():
            return jsonify(error="CSRF token missing or invalid."), 400
        if isinstance(data, dict) and data.get("csrf_token") and not validate_csrf():
            return jsonify(error="CSRF token missing or invalid."), 400

        with closing(connect()) as conn:
            user = auth.verify_user(conn, username, password)

        if not user:
            auth.login_rate_limiter.record_attempt(client_ip)
            return jsonify(error="Invalid username or password."), 401

        auth.login_rate_limiter.reset(client_ip)
        session.permanent = True
        session["user"] = user["username"]
        session["role"] = user["role"]
        session["login_time"] = time.time()
        return jsonify(ok=True, user=user["username"], role=user["role"], redirect="/#dashboard")

    @app.post("/api/auth/logout")
    def logout():
        session.clear()
        return jsonify(ok=True, redirect="/login")

    @app.get("/api/auth/me")
    def current_user():
        valid = check_session_validity()
        return jsonify(
            authenticated=valid,
            auth_required=is_auth_required(),
            user=session.get("user") if valid else None,
            role=session.get("role") if valid else None,
        )

    # Core CSPM API Endpoints
    @app.get("/api/runs")
    def runs():
        with closing(connect()) as conn:
            return jsonify(db.list_runs(conn))

    @app.get("/api/runs/<run_id>")
    @require_auth
    def run_detail(run_id):
        with closing(connect()) as conn:
            run = next((r for r in db.list_runs(conn) if r["run_id"] == run_id), None)
            if run is None:
                return jsonify(error="run not found"), 404
            findings = db.load_findings(conn, run_id)
        return jsonify(run=run, summary=_summary(findings), findings=findings)

    @app.get("/api/runs/<run_id>/attack-paths")
    @require_auth
    def run_attack_paths(run_id):
        with closing(connect()) as conn:
            run = next((r for r in db.list_runs(conn) if r["run_id"] == run_id), None)
            if run is None:
                return jsonify(error="run not found"), 404

        cti_reports = pipeline.get_cti()
        cfg = None
        from cspm.config import CONFIG_DIR
        cfg_name = run.get("config_name", "")
        for ext in (".json", ".yaml", ".yml"):
            p = CONFIG_DIR / f"{cfg_name}{ext}"
            if p.exists():
                from cspm.scanner import load_config
                try:
                    cfg = load_config(p)
                    break
                except Exception:
                    pass

        from cspm.attack_path import analyze_attack_paths
        paths = analyze_attack_paths(cfg or {}, cti_reports=cti_reports)
        return jsonify(run_id=run_id, config_name=cfg_name, attack_paths=[p.to_dict() for p in paths])

    @app.get("/api/cti")
    def cti():
        with closing(connect()) as conn:
            return jsonify(db.load_cti(conn))

    @app.post("/api/scan/demo")
    @require_auth
    def scan_demo():
        runs_ = pipeline.run_all(db_path=path)
        return jsonify(runs=runs_)

    @app.post("/api/scan")
    @require_auth
    def scan_upload():
        f = request.files.get("file")
        if f is None or not f.filename:
            return jsonify(error="no file uploaded (field name: file)"), 400
        suffix = Path(f.filename).suffix.lower()
        if suffix not in (".json", ".yaml", ".yml", ".tf"):
            return jsonify(error="only .json, .yaml, .yml or .tf files are accepted"), 400

        if suffix == ".tf":
            from cspm.terraform_scanner import scan_terraform_text
            try:
                tf_text = f.read().decode("utf-8")
            except UnicodeDecodeError:
                return jsonify(error="file is not valid UTF-8 text"), 400
            tf_findings = scan_terraform_text(tf_text, filename=f.filename)
            with closing(connect()) as conn:
                cti_ = pipeline.get_cti()
                db.save_cti(conn, cti_)
                from cspm.mapping import load_mapping
                from cspm.evidence import build_evidence_index
                from cspm.fusion import score_findings
                import uuid
                mapping = load_mapping()
                index = build_evidence_index(cti_)
                scored = score_findings(tf_findings, mapping, index, total_reports=len(cti_))
                run_id = uuid.uuid4().hex[:8]
                db.save_run(conn, run_id, _safe_name(f.filename), scored, len(cti_))
            return jsonify(run_id=run_id, findings=len(scored))

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
            except (KeyError, TypeError, AttributeError, ValueError) as exc:
                return jsonify(error=f"config structure is invalid: {exc}"), 400
        return jsonify(run_id=run_id, findings=len(scored))

    @app.get("/api/runs/<run_id>/compliance")
    @require_auth
    def run_compliance(run_id):
        with closing(connect()) as conn:
            run = next((r for r in db.list_runs(conn) if r["run_id"] == run_id), None)
            if run is None:
                return jsonify(error="run not found"), 404
            findings = db.load_findings(conn, run_id)
        from cspm.compliance import generate_full_compliance_report
        report = generate_full_compliance_report(findings)
        return jsonify(run_id=run_id, config_name=run.get("config_name"), compliance=report)

    @app.post("/api/scan/terraform")
    @require_auth
    def scan_terraform():
        f = request.files.get("file")
        if f is None or not f.filename:
            return jsonify(error="no file uploaded (field name: file)"), 400
        suffix = Path(f.filename).suffix.lower()
        if suffix not in (".tf", ".json"):
            return jsonify(error="only .tf or .json files are accepted for Terraform analysis"), 400
        from cspm.terraform_scanner import scan_terraform_text
        try:
            content = f.read().decode("utf-8")
        except UnicodeDecodeError:
            return jsonify(error="file is not valid UTF-8 text"), 400

        findings = scan_terraform_text(content, filename=f.filename)
        from cspm.mapping import load_mapping
        from cspm.evidence import build_evidence_index
        from cspm.fusion import score_findings
        import uuid

        with closing(connect()) as conn:
            cti_ = pipeline.get_cti()
            mapping = load_mapping()
            index = build_evidence_index(cti_)
            scored = score_findings(findings, mapping, index, total_reports=len(cti_))
            run_id = f"tf_{uuid.uuid4().hex[:6]}"
            db.save_run(conn, run_id, f"tf_{_safe_name(f.filename)}", scored, len(cti_))
        return jsonify(run_id=run_id, findings=len(scored))

    @app.get("/api/evaluation")
    def evaluation():
        return jsonify(run_evaluation(pipeline.get_cti(), write=False))

    return app
