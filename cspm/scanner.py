"""Loads configuration exports and runs the rule engine."""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path

from .rules import RULES, Rule, ROOT_RESOURCE, PASSWORD_POLICY_RESOURCE


@dataclass(frozen=True)
class Finding:
    resource: str
    resource_type: str
    check_id: str
    title: str
    severity: str
    criticality: str
    detail: str
    category: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


KNOWN_SECTIONS = ("account", "iam_users", "iam_policies", "s3_buckets", "security_groups",
                  "ec2_instances", "cloudtrail")


def parse_config(text: str, suffix: str = ".json") -> dict:
    """Parse JSON or YAML text into a config dict (YAML via safe_load only)."""
    if suffix.lower() in (".yml", ".yaml"):
        import yaml  # imported lazily so JSON-only use needs no PyYAML
        cfg = yaml.safe_load(text)
    else:
        cfg = json.loads(text)
    if not isinstance(cfg, dict) or not any(k in cfg for k in KNOWN_SECTIONS):
        raise ValueError("config must be an object with at least one of: " + ", ".join(KNOWN_SECTIONS))
    return cfg


def load_config(path) -> dict:
    """Load a JSON or YAML AWS configuration export from disk."""
    path = Path(path)
    return parse_config(path.read_text(encoding="utf-8"), path.suffix)


def scan_config(cfg: dict, rules: list[Rule] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for r in rules or RULES:
        for resource, rtype, crit, detail in r.fn(cfg):
            findings.append(Finding(resource, rtype, r.check_id, r.title,
                                    r.severity, crit, detail, r.category, r.remediation))
    return findings


def list_resources(cfg: dict) -> list[str]:
    """Every assessable resource name in a config (used to compute false-positive rate)."""
    names: list[str] = []
    acct = cfg.get("account", {})
    if "root_mfa_enabled" in acct or "root_last_used_days" in acct:
        names.append(ROOT_RESOURCE)
    if "password_policy" in acct:
        names.append(PASSWORD_POLICY_RESOURCE)
    if "cloudtrail" in cfg:
        names.append("cloudtrail")
    for key in ("iam_users", "iam_policies", "s3_buckets", "security_groups", "ec2_instances"):
        names += [x["name"] for x in cfg.get(key, [])]
    return names
