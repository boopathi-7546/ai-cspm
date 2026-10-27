"""Configurable Webhook Alerting for AI-CSPM.

Dispatches real-time security alerts for critical attack paths and vulnerabilities
to Slack, Microsoft Teams, and Generic Webhooks.

Features:
- Reads webhook URLs safely from environment variables.
- Redacts sensitive credentials, tokens, and secrets from payloads.
- Deduplicates alert notifications to avoid alert flooding.
- Safe offline fallback with comprehensive mock testing.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# Secret Redaction Patterns
REDACTION_PATTERNS = [
    # AWS Access Key IDs
    (re.compile(r'\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b'), "[REDACTED_AWS_KEY]"),
    # Private Keys
    (re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----'), "[REDACTED_PRIVATE_KEY]"),
    # Inline passwords, tokens, client secrets
    (re.compile(r'(?i)(["\']?(?:password|client_secret|secret_key|api_key|token|auth_token)["\']?\s*[:=]\s*["\'])([^"\'\s]{6,})(["\'])'), r'\1[REDACTED_SECRET]\3'),
    # Authorization header / Bearer tokens
    (re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9_\-\.]{12,}'), r'\1[REDACTED_TOKEN]'),
    # URLs with embedded credentials
    (re.compile(r'(https?://)[^:@\s]+:[^:@\s]+@'), r'\1[REDACTED_USER:PASS]@'),
]


def redact_sensitive_text(text: str) -> str:
    """Scan and redact any credentials, tokens, or private keys from a string."""
    if not isinstance(text, str):
        return text
    redacted = text
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_payload(data: Any) -> Any:
    """Recursively scrub secrets from dictionaries, lists, or strings."""
    if isinstance(data, dict):
        return {k: redact_payload(v) for k, v in data.items()}
    if isinstance(data, list):
        return [redact_payload(item) for item in data]
    if isinstance(data, str):
        return redact_sensitive_text(data)
    return data


class AlertDeduplicator:
    """In-memory cache to prevent repeated alerting for the same attack path."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self.ttl = ttl_seconds
        self._cache: dict[str, float] = {}

    def get_fingerprint(self, path_title: str, entry_point: str, target: str, risk_score: float) -> str:
        raw = f"{path_title}|{entry_point}|{target}|{risk_score:.1f}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def is_duplicate(self, fingerprint: str) -> bool:
        now = time.time()
        last_sent = self._cache.get(fingerprint)
        if last_sent is not None and (now - last_sent) < self.ttl:
            return True
        return False

    def mark_sent(self, fingerprint: str) -> None:
        self._cache[fingerprint] = time.time()

    def clear(self) -> None:
        self._cache.clear()


# Global deduplicator instance
deduplicator = AlertDeduplicator()


def format_slack_alert(path: Any, run_id: str, config_name: str) -> dict[str, Any]:
    """Format an AttackPath into a rich Slack Block Kit message."""
    title = redact_sensitive_text(getattr(path, "title", "Critical Attack Path"))
    severity = getattr(path, "severity", "Critical")
    risk_score = getattr(path, "risk_score", 0.0)
    entry_point = redact_sensitive_text(getattr(path, "entry_point", "Internet"))
    target = redact_sensitive_text(getattr(path, "target", "Cloud Asset"))
    remediation = redact_sensitive_text(getattr(path, "remediation", "Investigate immediately."))
    steps = getattr(path, "steps", []) or []

    steps_text = "\n".join(
        f"• *{s.from_node}* —[{s.relationship}]→ *{s.to_node}* ({s.technique_id or 'chain'})"
        for s in steps
    ) or "Single-stage direct compromise."

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 AI-CSPM Alert: [{severity.upper()}] Chained Attack Path Detected",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Environment:* `{config_name}` (Run: `{run_id}`)\n*Path:* *{title}*\n*Fused Risk Score:* `{risk_score}/100`",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Entry Point:*\n{entry_point}"},
                {"type": "mrkdwn", "text": f"*Compromised Target:*\n{target}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Kill-Chain Sequence:*\n{redact_sensitive_text(steps_text)}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🛠️ *Recommended Action:* {remediation}",
                }
            ],
        },
    ]

    return {"text": f"AI-CSPM Alert: {title} (Risk: {risk_score})", "blocks": blocks}


def format_teams_alert(path: Any, run_id: str, config_name: str) -> dict[str, Any]:
    """Format an AttackPath into a Microsoft Teams MessageCard."""
    title = redact_sensitive_text(getattr(path, "title", "Critical Attack Path"))
    severity = getattr(path, "severity", "Critical")
    risk_score = getattr(path, "risk_score", 0.0)
    entry_point = redact_sensitive_text(getattr(path, "entry_point", "Internet"))
    target = redact_sensitive_text(getattr(path, "target", "Cloud Asset"))
    remediation = redact_sensitive_text(getattr(path, "remediation", "Investigate immediately."))
    steps = getattr(path, "steps", []) or []

    steps_text = "<br>".join(
        f"• <strong>{s.from_node}</strong> —[{s.relationship}]→ <strong>{s.to_node}</strong> ({s.technique_id or 'chain'})"
        for s in steps
    ) or "Single-stage direct compromise."

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "E03E2D" if severity.lower() == "critical" else "FF593F",
        "summary": f"AI-CSPM Security Alert: {title}",
        "title": f"🚨 AI-CSPM [{severity.upper()}]: {title}",
        "sections": [
            {
                "activityTitle": f"Cloud Environment: {config_name} (Run ID: {run_id})",
                "facts": [
                    {"name": "Risk Score", "value": f"{risk_score} / 100"},
                    {"name": "Severity", "value": severity},
                    {"name": "Entry Vector", "value": entry_point},
                    {"name": "Target Asset", "value": target},
                ],
                "markdown": True,
            },
            {
                "title": "Kill-Chain Sequence",
                "text": redact_sensitive_text(steps_text),
                "markdown": False,
            },
            {
                "title": "Remediation Strategy",
                "text": remediation,
                "markdown": True,
            },
        ],
    }


def format_generic_alert(path: Any, run_id: str, config_name: str) -> dict[str, Any]:
    """Format an AttackPath into a standardized JSON webhook payload."""
    return redact_payload({
        "event": "cspm.attack_path_alert",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_id": run_id,
        "config_name": config_name,
        "path": path.to_dict() if hasattr(path, "to_dict") else path,
    })


def send_webhook(url: str, payload: dict[str, Any], timeout: int = 5) -> dict[str, Any]:
    """Deliver a JSON payload to a webhook URL using standard urllib."""
    clean_url = redact_sensitive_text(url)
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "AI-CSPM-Alert-Engine/2.0",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            try:
                code_val = response.getcode()
                status = int(code_val) if code_val is not None else 200
            except (TypeError, ValueError):
                status = 200
            return {
                "success": 200 <= status < 300,
                "status_code": status,
                "url": clean_url,
            }
    except urllib.error.HTTPError as exc:
        logger.error("Webhook HTTP error %s to %s", exc.code, clean_url)
        return {
            "success": False,
            "status_code": exc.code,
            "error": f"HTTP {exc.code}: {exc.reason}",
            "url": clean_url,
        }
    except Exception as exc:
        logger.error("Webhook connection error to %s: %s", clean_url, exc)
        return {
            "success": False,
            "status_code": 0,
            "error": str(exc),
            "url": clean_url,
        }


def notify_critical_attack_paths(
    paths: list[Any],
    run_id: str,
    config_name: str,
    force: bool = False,
) -> dict[str, Any]:
    """Inspect paths, filter for high/critical risks, and notify configured webhooks.

    Environment variables:
    - CSPM_SLACK_WEBHOOK_URL
    - CSPM_TEAMS_WEBHOOK_URL
    - CSPM_WEBHOOK_URL (Generic)
    """
    slack_url = os.getenv("CSPM_SLACK_WEBHOOK_URL")
    teams_url = os.getenv("CSPM_TEAMS_WEBHOOK_URL")
    generic_url = os.getenv("CSPM_WEBHOOK_URL")

    if not any([slack_url, teams_url, generic_url]):
        return {
            "sent": 0,
            "deduplicated": 0,
            "configured": False,
            "message": "No webhook URLs configured (CSPM_SLACK_WEBHOOK_URL, CSPM_TEAMS_WEBHOOK_URL, CSPM_WEBHOOK_URL).",
        }

    results: list[dict[str, Any]] = []
    sent_count = 0
    dedup_count = 0

    # Only alert on high or critical attack paths (or risk_score >= 30)
    for p in paths:
        sev = getattr(p, "severity", "").lower()
        score = getattr(p, "risk_score", 0.0)
        if sev not in ("critical", "high") and score < 30.0:
            continue

        title = getattr(p, "title", "Untitled Path")
        entry = getattr(p, "entry_point", "")
        tgt = getattr(p, "target", "")
        fp = deduplicator.get_fingerprint(title, entry, tgt, score)

        if not force and deduplicator.is_duplicate(fp):
            logger.info("Skipping alert for duplicate path '%s' (fp: %s)", title, fp)
            dedup_count += 1
            continue

        # Dispatch to Slack
        if slack_url:
            slack_payload = format_slack_alert(p, run_id, config_name)
            res = send_webhook(slack_url, slack_payload)
            results.append({"type": "slack", "path": title, "result": res})
            if res.get("success"):
                sent_count += 1

        # Dispatch to Teams
        if teams_url:
            teams_payload = format_teams_alert(p, run_id, config_name)
            res = send_webhook(teams_url, teams_payload)
            results.append({"type": "teams", "path": title, "result": res})
            if res.get("success"):
                sent_count += 1

        # Dispatch to Generic Webhook
        if generic_url:
            generic_payload = format_generic_alert(p, run_id, config_name)
            res = send_webhook(generic_url, generic_payload)
            results.append({"type": "generic", "path": title, "result": res})
            if res.get("success"):
                sent_count += 1

        deduplicator.mark_sent(fp)

    return {
        "sent": sent_count,
        "deduplicated": dedup_count,
        "configured": True,
        "results": results,
    }
