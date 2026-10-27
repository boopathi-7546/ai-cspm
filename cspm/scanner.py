"""Loads configuration exports and runs the rule engine."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from pathlib import Path

from .rules import RULES, Rule, ROOT_RESOURCE, PASSWORD_POLICY_RESOURCE

logger = logging.getLogger(__name__)


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


KNOWN_SECTIONS = (
    "account",
    "iam_users",
    "iam_policies",
    "s3_buckets",
    "security_groups",
    "ec2_instances",
    "cloudtrail",
)

SUPPORTED_EXTENSIONS = (".json", ".yaml", ".yml")


def parse_config(text: str, suffix: str = ".json") -> dict:
    """Parse JSON or YAML text into a validated config dict (YAML via safe_load only)."""
    if not text or not text.strip():
        raise ValueError("configuration file is empty")

    suf = suffix.lower()
    if suf not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"unsupported file format: '{suffix}'. Only .json, .yaml, and .yml are accepted."
        )

    if suf in (".yml", ".yaml"):
        import yaml  # imported lazily so JSON-only use needs no PyYAML
        try:
            cfg = yaml.safe_load(text)
        except Exception as exc:
            raise ValueError(f"invalid YAML configuration: {exc}") from exc
    else:
        try:
            cfg = json.loads(text)
        except Exception as exc:
            raise ValueError(f"invalid JSON configuration: {exc}") from exc

    if not isinstance(cfg, dict):
        raise ValueError("configuration must be a JSON/YAML object at the root level")

    if not any(k in cfg for k in KNOWN_SECTIONS):
        raise ValueError("config must be an object with at least one of: " + ", ".join(KNOWN_SECTIONS))

    # Validate resource list sections contain dictionaries with 'name'
    for sec in ("iam_users", "iam_policies", "s3_buckets", "security_groups", "ec2_instances"):
        if sec in cfg:
            items = cfg[sec]
            if not isinstance(items, list):
                raise ValueError(f"section '{sec}' must be a list of resources")
            for idx, item in enumerate(items):
                if not isinstance(item, dict):
                    raise ValueError(f"resource #{idx + 1} in '{sec}' must be an object")
                if "name" not in item or not str(item["name"]).strip():
                    raise ValueError(f"resource #{idx + 1} in '{sec}' is missing required 'name' field")

    return cfg


def load_config(path) -> dict:
    """Load a JSON or YAML AWS configuration export from disk."""
    path = Path(path)
    return parse_config(path.read_text(encoding="utf-8"), path.suffix)


def scan_config(cfg: dict, rules: list[Rule] | None = None) -> list[Finding]:
    """Execute compliance rules on the config with deduplication and error isolation."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for r in rules or RULES:
        try:
            for hit in r.fn(cfg):
                if not isinstance(hit, (tuple, list)) or len(hit) < 4:
                    continue
                resource, rtype, crit, detail = hit[0], hit[1], hit[2], hit[3]
                dedup_key = (str(resource), str(rtype), str(r.check_id))
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(
                    Finding(
                        resource=str(resource),
                        resource_type=str(rtype),
                        check_id=r.check_id,
                        title=r.title,
                        severity=r.severity,
                        criticality=str(crit),
                        detail=str(detail),
                        category=r.category,
                        remediation=r.remediation,
                    )
                )
        except Exception as exc:
            logger.warning("Error running rule %s on configuration: %s", r.check_id, exc)

    return findings


def list_resources(cfg: dict) -> list[str]:
    """Every assessable resource name in a config (used to compute false-positive rate)."""
    names: list[str] = []
    acct = cfg.get("account")
    if isinstance(acct, dict):
        if "root_mfa_enabled" in acct or "root_last_used_days" in acct:
            names.append(ROOT_RESOURCE)
        if "password_policy" in acct:
            names.append(PASSWORD_POLICY_RESOURCE)
    if "cloudtrail" in cfg and isinstance(cfg["cloudtrail"], dict):
        names.append("cloudtrail")

    for key in ("iam_users", "iam_policies", "s3_buckets", "security_groups", "ec2_instances"):
        items = cfg.get(key, [])
        if isinstance(items, list):
            for x in items:
                if isinstance(x, dict) and "name" in x and x["name"]:
                    names.append(str(x["name"]))

    return names
