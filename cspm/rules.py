"""CSPM rule engine: deterministic checks for IAM, S3 and security groups.

Each rule is a plain Python generator that inspects the configuration dict and
yields one tuple per failing resource:
    (resource_name, resource_type, criticality, detail)
Rules are registered with the @rule decorator and collected in RULES.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator

Hit = tuple  # (resource, resource_type, criticality, detail)


@dataclass(frozen=True)
class Rule:
    check_id: str
    title: str
    severity: str  # Critical | High | Medium | Low
    category: str  # IAM | Storage | Network
    fn: Callable[[dict], Iterator[Hit]]


RULES: list[Rule] = []


def rule(check_id: str, title: str, severity: str, category: str):
    def deco(fn):
        RULES.append(Rule(check_id, title, severity, category, fn))
        return fn
    return deco


# ---------------------------------------------------------------- helpers
WORLD = {"0.0.0.0/0", "::/0"}
DB_PORTS = (1433, 3306, 5432, 6379, 27017)
ROOT_RESOURCE = "root-account"
PASSWORD_POLICY_RESOURCE = "password-policy"


def _as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _crit(obj: dict, default: str = "medium") -> str:
    return str(obj.get("criticality", default)).lower()


def _statements(policy: dict) -> list[dict]:
    st = policy.get("document", {}).get("Statement", [])
    return [st] if isinstance(st, dict) else list(st)


def _is_world(rule_: dict) -> bool:
    return str(rule_.get("cidr", "")) in WORLD


def _is_all_traffic(rule_: dict) -> bool:
    proto = str(rule_.get("protocol", "tcp")).lower()
    lo = int(rule_.get("port_from", 0))
    hi = int(rule_.get("port_to", 65535))
    return proto in ("-1", "all") or (lo == 0 and hi == 65535)


def _exposes_port(rule_: dict, ports) -> bool:
    """True if the ingress rule opens a specific TCP port in `ports` to the world.
    All-traffic rules are excluded here; NET-04 reports those separately."""
    if not _is_world(rule_) or _is_all_traffic(rule_):
        return False
    if str(rule_.get("protocol", "tcp")).lower() not in ("tcp", "6"):
        return False
    lo, hi = int(rule_["port_from"]), int(rule_["port_to"])
    return any(lo <= p <= hi for p in ports)


# -------------------------------------------------------------------- IAM
@rule("IAM-01", "IAM policy grants full administrator access (Action * on Resource *)", "Critical", "IAM")
def iam_admin_wildcard(cfg):
    for p in cfg.get("iam_policies", []):
        for st in _statements(p):
            if (st.get("Effect") == "Allow"
                    and "*" in _as_list(st.get("Action"))
                    and "*" in _as_list(st.get("Resource"))):
                yield (p["name"], "iam_policy", _crit(p, "high"), "Statement allows * on *")
                break


@rule("IAM-02", "IAM policy allows a service-wide wildcard action on all resources", "High", "IAM")
def iam_service_wildcard(cfg):
    for p in cfg.get("iam_policies", []):
        for st in _statements(p):
            actions = [a for a in _as_list(st.get("Action")) if a != "*"]
            if (st.get("Effect") == "Allow"
                    and "*" in _as_list(st.get("Resource"))
                    and any(str(a).endswith(":*") for a in actions)):
                yield (p["name"], "iam_policy", _crit(p), "Service wildcard action on Resource *")
                break


@rule("IAM-03", "Root account has no MFA enabled", "Critical", "IAM")
def iam_root_no_mfa(cfg):
    if cfg.get("account", {}).get("root_mfa_enabled") is False:
        yield (ROOT_RESOURCE, "account", "high", "root_mfa_enabled = false")


@rule("IAM-04", "Root account used within the last 30 days", "High", "IAM")
def iam_root_recent_use(cfg):
    days = cfg.get("account", {}).get("root_last_used_days")
    if days is not None and days <= 30:
        yield (ROOT_RESOURCE, "account", "high", f"root last used {days} day(s) ago")


@rule("IAM-05", "IAM user with console access has no MFA", "High", "IAM")
def iam_user_no_mfa(cfg):
    for u in cfg.get("iam_users", []):
        if u.get("console_access") and not u.get("mfa_enabled"):
            yield (u["name"], "iam_user", _crit(u), "console_access = true, mfa_enabled = false")


@rule("IAM-06", "IAM access key not rotated for more than 90 days", "Medium", "IAM")
def iam_old_keys(cfg):
    for u in cfg.get("iam_users", []):
        old = [k for k in u.get("access_keys", []) if k.get("age_days", 0) > 90]
        if old:
            yield (u["name"], "iam_user", _crit(u), f"{len(old)} key(s) older than 90 days")


@rule("IAM-07", "IAM access key unused for more than 45 days", "Medium", "IAM")
def iam_unused_keys(cfg):
    for u in cfg.get("iam_users", []):
        stale = [k for k in u.get("access_keys", [])
                 if k.get("last_used_days") is not None and k["last_used_days"] > 45]
        if stale:
            yield (u["name"], "iam_user", _crit(u), f"{len(stale)} key(s) unused > 45 days")


@rule("IAM-08", "Account password policy minimum length below 14", "Medium", "IAM")
def iam_weak_password_policy(cfg):
    pp = cfg.get("account", {}).get("password_policy")
    if pp is not None and pp.get("min_length", 0) < 14:
        yield (PASSWORD_POLICY_RESOURCE, "account", "medium", f"min_length = {pp.get('min_length')}")


# ---------------------------------------------------------------- Storage
@rule("S3-01", "S3 bucket is publicly readable", "Critical", "Storage")
def s3_public_read(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("public_read"):
            yield (b["name"], "s3_bucket", _crit(b), "public_read = true")


@rule("S3-02", "S3 bucket is publicly writable", "Critical", "Storage")
def s3_public_write(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("public_write"):
            yield (b["name"], "s3_bucket", _crit(b), "public_write = true")


@rule("S3-03", "S3 Block Public Access is not enabled", "Medium", "Storage")
def s3_no_block_public(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("block_public_access") is False:
            yield (b["name"], "s3_bucket", _crit(b), "block_public_access = false")


@rule("S3-04", "S3 bucket default encryption is disabled", "Medium", "Storage")
def s3_no_encryption(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("encryption_enabled") is False:
            yield (b["name"], "s3_bucket", _crit(b), "encryption_enabled = false")


@rule("S3-05", "S3 bucket access logging is disabled", "Low", "Storage")
def s3_no_logging(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("logging_enabled") is False:
            yield (b["name"], "s3_bucket", _crit(b), "logging_enabled = false")


@rule("S3-06", "S3 bucket versioning is disabled", "Low", "Storage")
def s3_no_versioning(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("versioning_enabled") is False:
            yield (b["name"], "s3_bucket", _crit(b), "versioning_enabled = false")


# ---------------------------------------------------------------- Network
def _sg_rule(cfg, predicate, detail):
    for sg in cfg.get("security_groups", []):
        for r in sg.get("ingress", []):
            if predicate(r):
                yield (sg["name"], "security_group", _crit(sg), f"{detail} ({r.get('cidr')})")
                break


@rule("NET-01", "Security group allows SSH (22) from the internet", "High", "Network")
def net_ssh_open(cfg):
    yield from _sg_rule(cfg, lambda r: _exposes_port(r, (22,)), "port 22 open")


@rule("NET-02", "Security group allows RDP (3389) from the internet", "Critical", "Network")
def net_rdp_open(cfg):
    yield from _sg_rule(cfg, lambda r: _exposes_port(r, (3389,)), "port 3389 open")


@rule("NET-03", "Security group exposes a database port to the internet", "Critical", "Network")
def net_db_open(cfg):
    yield from _sg_rule(cfg, lambda r: _exposes_port(r, DB_PORTS), "database port open")


@rule("NET-04", "Security group allows all traffic from the internet", "Critical", "Network")
def net_all_open(cfg):
    yield from _sg_rule(cfg, lambda r: _is_world(r) and _is_all_traffic(r), "all ports/protocols open")
