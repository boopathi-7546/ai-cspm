"""Comprehensive automated tests for AI-CSPM authentication, login system, and route protection."""
import json
import time
import pytest

from cspm import auth, db
from web.app import create_app


@pytest.fixture()
def app_instance(tmp_path):
    """Create a test application instance with temporary database."""
    test_db = tmp_path / "test_auth_suite.db"
    app = create_app(test_db)
    app.config["TESTING"] = True
    return app


def test_login_page_served_with_framer_design(app_instance):
    """Test that GET /login serves the login page with all expected fields and design elements."""
    client = app_instance.test_client()
    resp = client.get("/login")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Sign In to AI-CSPM" in html
    assert 'name="username"' in html
    assert 'name="password"' in html
    assert 'id="togglePasswordBtn"' in html
    assert 'id="csrfToken"' in html
    assert "style.css" in html
    assert "AI-CSPM" in html


def test_csrf_token_endpoint(app_instance):
    """Test that /api/auth/csrf returns a valid CSRF token."""
    client = app_instance.test_client()
    resp = client.get("/api/auth/csrf")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "csrf_token" in data
    assert len(data["csrf_token"]) == 64  # 32 bytes hex


def test_login_form_csrf_protection(app_instance):
    """Test that HTML form submissions require a valid CSRF token."""
    client = app_instance.test_client()

    # Form submission without CSRF token should be rejected
    r_bad = client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        content_type="application/x-www-form-urlencoded",
    )
    assert r_bad.status_code == 302
    assert "CSRF" in r_bad.headers["Location"]

    # Now fetch page to seed session CSRF token
    client.get("/login")
    csrf_resp = client.get("/api/auth/csrf")
    token = csrf_resp.get_json()["csrf_token"]

    # Form submission with valid CSRF token succeeds
    r_good = client.post(
        "/login",
        data={"username": "admin", "password": "admin123", "csrf_token": token},
        content_type="application/x-www-form-urlencoded",
    )
    assert r_good.status_code == 302
    assert "dashboard" in r_good.headers["Location"]

    # Verify session is authenticated
    me = client.get("/api/auth/me").get_json()
    assert me["authenticated"] is True
    assert me["user"] == "admin"


def test_api_login_success_and_logout(app_instance):
    """Test API login with valid credentials, session establishment, and logout."""
    client = app_instance.test_client()

    # Initial state: unauthenticated
    me = client.get("/api/auth/me").get_json()
    assert me["authenticated"] is False

    # Successful login
    r_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert r_login.status_code == 200
    login_data = r_login.get_json()
    assert login_data["ok"] is True
    assert login_data["user"] == "admin"
    assert login_data["role"] == "admin"

    # Authenticated state
    me_after = client.get("/api/auth/me").get_json()
    assert me_after["authenticated"] is True
    assert me_after["user"] == "admin"

    # Logout
    r_logout = client.post("/api/auth/logout")
    assert r_logout.status_code == 200
    assert r_logout.get_json()["ok"] is True

    # State after logout
    me_logged_out = client.get("/api/auth/me").get_json()
    assert me_logged_out["authenticated"] is False


def test_api_login_invalid_credentials(app_instance):
    """Test that wrong credentials return HTTP 401 with informative error."""
    client = app_instance.test_client()

    # Wrong password
    r1 = client.post("/api/auth/login", json={"username": "admin", "password": "wrong_password!"})
    assert r1.status_code == 401
    assert "Invalid username or password" in r1.get_json()["error"]

    # Nonexistent user
    r2 = client.post("/api/auth/login", json={"username": "nonexistent_analyst", "password": "any_password"})
    assert r2.status_code == 401
    assert "Invalid username or password" in r2.get_json()["error"]


def test_login_rate_limiting_enforcement(app_instance):
    """Test that exceeding the rate limit blocks further login attempts with HTTP 429."""
    client = app_instance.test_client()
    limiter = auth.login_rate_limiter
    limiter.reset("127.0.0.1")

    # Perform 5 failed attempts
    for _ in range(5):
        resp = client.post("/api/auth/login", json={"username": "admin", "password": "bad_password"})
        assert resp.status_code == 401

    # 6th attempt should be blocked by rate limiter
    resp_blocked = client.post("/api/auth/login", json={"username": "admin", "password": "bad_password"})
    assert resp_blocked.status_code == 429
    assert "Too many failed login attempts" in resp_blocked.get_json()["error"]

    # Reset limiter for subsequent tests
    limiter.reset("127.0.0.1")


def test_protected_routes_when_auth_enabled(tmp_path):
    """Test that sensitive routes are protected with HTTP 401/302 when REQUIRE_AUTH is enabled."""
    app = create_app(tmp_path / "protected_test.db")
    app.config["REQUIRE_AUTH"] = True
    app.config["TESTING"] = True
    client = app.test_client()

    # 1. Dashboard HTML route redirects to login
    r_dash = client.get("/dashboard")
    assert r_dash.status_code == 302
    assert "/login" in r_dash.headers["Location"]

    # 2. Scanning endpoints return 401 Unauthorized
    assert client.post("/api/scan/demo").status_code == 401
    assert client.post("/api/scan").status_code == 401
    assert client.post("/api/scan/terraform").status_code == 401

    # 3. Log in with admin credentials
    r_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert r_login.status_code == 200

    # 4. Now dashboard and scan actions succeed
    r_demo = client.post("/api/scan/demo")
    assert r_demo.status_code == 200
    runs = r_demo.get_json()["runs"]
    vuln_run = runs["vulnerable_env"]

    # 5. Protected detail endpoints succeed when authenticated
    assert client.get(f"/api/runs/{vuln_run}").status_code == 200
    assert client.get(f"/api/runs/{vuln_run}/attack-paths").status_code == 200
    assert client.get(f"/api/runs/{vuln_run}/compliance").status_code == 200


def test_auth_disabled_preserves_public_demo_behavior(tmp_path):
    """Test that when REQUIRE_AUTH is disabled, public demo behavior works without credentials."""
    app = create_app(tmp_path / "demo_unprotected.db")
    app.config["REQUIRE_AUTH"] = False
    app.config["TESTING"] = True
    client = app.test_client()

    # Index page is accessible
    assert client.get("/").status_code == 200

    # Demo scan is accessible without session
    r_demo = client.post("/api/scan/demo")
    assert r_demo.status_code == 200
    assert "runs" in r_demo.get_json()

    # Auth status endpoint indicates auth is not required
    me = client.get("/api/auth/me").get_json()
    assert me["auth_required"] is False
    assert me["authenticated"] is False


def test_session_expiration_handling(tmp_path, monkeypatch):
    """Test that expired sessions are cleared and reject access with HTTP 401."""
    app = create_app(tmp_path / "expired_session.db")
    app.config["REQUIRE_AUTH"] = True
    app.config["TESTING"] = True
    client = app.test_client()

    # Log in
    client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert client.get("/api/auth/me").get_json()["authenticated"] is True

    # Simulate session timeout by setting login_time in the past
    with client.session_transaction() as sess:
        sess["login_time"] = time.time() - 90000  # > 24 hours ago

    # Protected call should detect expired session and return 401
    r_scan = client.post("/api/scan/demo")
    assert r_scan.status_code == 401

    # Session is now cleared
    assert client.get("/api/auth/me").get_json()["authenticated"] is False


def test_environment_credentials_sync(tmp_path, monkeypatch):
    """Test that custom CSPM_ADMIN_USER and CSPM_ADMIN_PASSWORD from environment are honored."""
    monkeypatch.setenv("CSPM_ADMIN_USER", "sec_director")
    monkeypatch.setenv("CSPM_ADMIN_PASSWORD", "ComplexPass#98765")

    conn = db.connect(tmp_path / "custom_env.db")
    user = auth.verify_user(conn, "sec_director", "ComplexPass#98765")
    assert user is not None
    assert user["username"] == "sec_director"
    assert user["role"] == "admin"
