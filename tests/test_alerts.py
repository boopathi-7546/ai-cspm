"""Comprehensive unit tests for the Webhook Alerting Engine."""
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from cspm.alerts import (
    AlertDeduplicator,
    format_generic_alert,
    format_slack_alert,
    format_teams_alert,
    notify_critical_attack_paths,
    redact_payload,
    redact_sensitive_text,
    send_webhook,
)
from cspm.attack_path import AttackPath, AttackStep

# Mark all tests in this module as mock unit tests
pytestmark = pytest.mark.mock


@pytest.fixture
def sample_attack_path():
    return AttackPath(
        path_id="ap-demo-001",
        title="Public EC2 IMDSv1 Credential Exfiltration to Database",
        entry_point="Internet (0.0.0.0/0)",
        target="RDS Database 'customer-prod'",
        steps=[
            AttackStep("Internet (0.0.0.0/0)", "Security Group 'sg-web'", "PUBLIC_INGRESS", "Port 22 open to 0.0.0.0/0", "T1190"),
            AttackStep("Security Group 'sg-web'", "EC2 Instance 'web-01'", "HOST_COMPROMISE", "IMDSv1 enabled", "T1552.005"),
            AttackStep("EC2 Instance 'web-01'", "RDS Database 'customer-prod'", "DATA_EXFILTRATION", "Admin role", "T1530"),
        ],
        severity="Critical",
        criticality="high",
        risk_score=92.5,
        explanation="Public SSH combined with IMDSv1 allows unauthenticated credential theft.",
        mitigations=["Enforce IMDSv2", "Close port 22 on sg-web"],
        techniques=["T1190", "T1552.005", "T1530"],
    )


def test_redact_sensitive_text_aws_key():
    raw = "Found compromised key AKIAIOSFODNN7EXAMPLE in repository config."
    cleaned = redact_sensitive_text(raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
    assert "[REDACTED_AWS_KEY]" in cleaned


def test_redact_sensitive_text_private_key():
    raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    cleaned = redact_sensitive_text(raw)
    assert "BEGIN RSA PRIVATE KEY" not in cleaned
    assert "[REDACTED_PRIVATE_KEY]" in cleaned


def test_redact_sensitive_text_tokens_and_passwords():
    raw = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsIn... and password="SuperSecretPassword123!"'
    cleaned = redact_sensitive_text(raw)
    assert "SuperSecretPassword123!" not in cleaned
    assert "[REDACTED_TOKEN]" in cleaned
    assert "[REDACTED_SECRET]" in cleaned


def test_redact_payload_nested_dict():
    nested = {
        "title": "Exposure with key AKIA1111222233334444",
        "nested": {
            "token": "Bearer secret-token-value-here",
            "items": ["plain", "password='MyUltraSecretPass123'"],
        },
    }
    cleaned = redact_payload(nested)
    assert "AKIA1111222233334444" not in cleaned["title"]
    assert "secret-token-value-here" not in cleaned["nested"]["token"]
    assert "MyUltraSecretPass123" not in cleaned["nested"]["items"][1]


def test_format_slack_alert(sample_attack_path):
    alert = format_slack_alert(sample_attack_path, "run-123", "production_env")
    assert "blocks" in alert
    assert any("AI-CSPM Alert" in b.get("text", {}).get("text", "") for b in alert["blocks"] if b.get("text"))
    assert any("production_env" in b.get("text", {}).get("text", "") for b in alert["blocks"] if b.get("text"))


def test_format_teams_alert(sample_attack_path):
    alert = format_teams_alert(sample_attack_path, "run-123", "production_env")
    assert alert["@type"] == "MessageCard"
    assert "themeColor" in alert
    assert "production_env" in alert["sections"][0]["activityTitle"]
    assert any(f["name"] == "Risk Score" for f in alert["sections"][0]["facts"])


def test_format_generic_alert(sample_attack_path):
    alert = format_generic_alert(sample_attack_path, "run-123", "production_env")
    assert alert["event"] == "cspm.attack_path_alert"
    assert alert["run_id"] == "run-123"
    assert alert["path"]["risk_score"] == 92.5


def test_send_webhook_success_mock():
    mock_response = MagicMock()
    mock_response.getcode.return_value = 200
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        res = send_webhook("https://hooks.slack.com/services/T00/B00/X00", {"text": "hello"})
        assert res["success"] is True
        assert res["status_code"] == 200


def test_send_webhook_http_error_mock():
    http_error = urllib.error.HTTPError(
        url="https://hooks.slack.com/services/fail",
        code=400,
        msg="Bad Request",
        hdrs={},
        fp=None,
    )
    with patch("urllib.request.urlopen", side_effect=http_error):
        res = send_webhook("https://hooks.slack.com/services/fail", {"text": "hello"})
        assert res["success"] is False
        assert res["status_code"] == 400
        assert "400" in res["error"]


def test_alert_deduplication(sample_attack_path):
    dedup = AlertDeduplicator(ttl_seconds=3600)
    fp = dedup.get_fingerprint(
        sample_attack_path.title,
        sample_attack_path.entry_point,
        sample_attack_path.target,
        sample_attack_path.risk_score,
    )

    assert dedup.is_duplicate(fp) is False
    dedup.mark_sent(fp)
    assert dedup.is_duplicate(fp) is True


def test_notify_critical_attack_paths_with_all_webhooks(sample_attack_path, monkeypatch):
    monkeypatch.setenv("CSPM_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/mock")
    monkeypatch.setenv("CSPM_TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/mock")
    monkeypatch.setenv("CSPM_WEBHOOK_URL", "https://api.corp.internal/webhook")

    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = notify_critical_attack_paths([sample_attack_path], run_id="run-123", config_name="prod", force=True)
        assert res["configured"] is True
        assert res["sent"] == 3  # Slack + Teams + Generic
        assert len(res["results"]) == 3
