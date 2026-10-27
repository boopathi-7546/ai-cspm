import json
import pytest
from cspm import auth, db
from cspm.scanner import parse_config, scan_config
from cspm.rules import Rule
from web.app import create_app


def test_empty_config_rejected():
    with pytest.raises(ValueError, match="configuration file is empty"):
        parse_config("")
    with pytest.raises(ValueError, match="configuration file is empty"):
        parse_config("   \n\t  ")


def test_unsupported_format_rejected():
    with pytest.raises(ValueError, match="unsupported file format"):
        parse_config("{}", suffix=".xml")
    with pytest.raises(ValueError, match="unsupported file format"):
        parse_config("{}", suffix=".txt")


def test_non_dict_config_rejected():
    with pytest.raises(ValueError, match="must be a JSON/YAML object"):
        parse_config("[]", suffix=".json")
    with pytest.raises(ValueError, match="must be a JSON/YAML object"):
        parse_config("- a\n- b", suffix=".yaml")


def test_missing_known_sections_rejected():
    with pytest.raises(ValueError, match="at least one of"):
        parse_config('{"random_key": 123}')


def test_malformed_resource_items_rejected():
    with pytest.raises(ValueError, match="must be an object"):
        parse_config('{"s3_buckets": ["bucket-string-not-dict"]}')
    with pytest.raises(ValueError, match="missing required 'name' field"):
        parse_config('{"s3_buckets": [{"public_read": true}]}')


def test_scan_config_deduplication():
    # A rule that intentionally yields duplicates
    dummy_rule = Rule(
        check_id="TEST-01",
        title="Duplicate test",
        severity="Low",
        category="Storage",
        remediation="Fix it",
        fn=lambda cfg: [
            ("my-bucket", "s3_bucket", "low", "issue 1"),
            ("my-bucket", "s3_bucket", "low", "issue 1 duplicate"),
            ("other-bucket", "s3_bucket", "low", "issue 2"),
        ],
    )
    cfg = {"s3_buckets": [{"name": "my-bucket"}, {"name": "other-bucket"}]}
    findings = scan_config(cfg, rules=[dummy_rule])
    assert len(findings) == 2
    assert {f.resource for f in findings} == {"my-bucket", "other-bucket"}


def test_scan_config_handles_faulty_rule_gracefully():
    def exploding_rule(cfg):
        raise RuntimeError("Rule exploded unexpectedly")
        yield  # make it a generator

    faulty = Rule("FAIL-01", "Fails", "High", "IAM", "None", exploding_rule)
    working = Rule("PASS-01", "Works", "Low", "IAM", "None", lambda cfg: [("u1", "iam_user", "low", "ok")])
    findings = scan_config({"iam_users": [{"name": "u1"}]}, rules=[faulty, working])
    assert len(findings) == 1
    assert findings[0].check_id == "PASS-01"


def test_auth_user_creation_and_verification(tmp_path):
    conn = db.connect(tmp_path / "test_auth.db")
    # Verify default admin exists
    admin = auth.verify_user(conn, "admin", "admin123")
    assert admin is not None
    assert admin["role"] == "admin"

    # Create new analyst
    ok = auth.create_user(conn, "security_alice", "SuperSecretPass!23", role="analyst")
    assert ok is True

    # Duplicate username fails
    ok_dup = auth.create_user(conn, "security_alice", "OtherPass123", role="analyst")
    assert ok_dup is False

    # Valid login
    user = auth.verify_user(conn, "security_alice", "SuperSecretPass!23")
    assert user is not None
    assert user["username"] == "security_alice"
    assert user["role"] == "analyst"

    # Wrong password fails
    assert auth.verify_user(conn, "security_alice", "wrong_pass") is None


def test_auth_rate_limiting():
    limiter = auth.RateLimiter(max_attempts=3, window_seconds=10)
    ip = "192.168.1.100"
    assert limiter.is_allowed(ip) is True
    limiter.record_attempt(ip)
    limiter.record_attempt(ip)
    assert limiter.is_allowed(ip) is True
    limiter.record_attempt(ip)
    assert limiter.is_allowed(ip) is False
    limiter.reset(ip)
    assert limiter.is_allowed(ip) is True


def test_flask_auth_endpoints(tmp_path):
    app = create_app(tmp_path / "app_auth.db")
    client = app.test_client()

    # Initially not authenticated
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.get_json()["authenticated"] is False

    # Bad login
    r = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert r.status_code == 401

    # Good login
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert r.status_code == 200
    assert r.get_json()["user"] == "admin"

    # Now authenticated
    r = client.get("/api/auth/me")
    assert r.get_json()["authenticated"] is True
    assert r.get_json()["user"] == "admin"

    # Logout
    r = client.post("/api/auth/logout")
    assert r.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is False


def test_protected_endpoints_when_require_auth_enabled(tmp_path):
    app = create_app(tmp_path / "app_protected.db")
    app.config["REQUIRE_AUTH"] = True
    client = app.test_client()

    # Reading public runs is allowed
    assert client.get("/api/runs").status_code == 200

    # Scanning requires auth
    assert client.post("/api/scan/demo").status_code == 401

    # Log in
    client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})

    # Now scan succeeds
    assert client.post("/api/scan/demo").status_code == 200
