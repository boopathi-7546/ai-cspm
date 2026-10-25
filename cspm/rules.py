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
    category: str  # IAM | Storage | Network | Logging | Compute
    remediation: str
    fn: Callable[[dict], Iterator[Hit]]


RULES: list[Rule] = []


def rule(check_id: str, title: str, severity: str, category: str, remediation: str):
    def deco(fn):
        RULES.append(Rule(check_id, title, severity, category, remediation, fn))
        return fn
    return deco


# ---------------------------------------------------------------- helpers
WORLD = {"0.0.0.0/0", "::/0"}
DB_PORTS = (1433, 3306, 5432, 6379, 27017)
DOCKER_API_PORTS = (2375,)
KUBELET_PORTS = (10250,)
CLOUDTRAIL_RESOURCE = "cloudtrail"
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
@rule("IAM-01", "IAM policy grants full administrator access (Action * on Resource *)", "Critical", "IAM",
      "Replace the wildcard policy with least-privilege permissions scoped to the actions and resources each role needs.")
def iam_admin_wildcard(cfg):
    for p in cfg.get("iam_policies", []):
        for st in _statements(p):
            if (st.get("Effect") == "Allow"
                    and "*" in _as_list(st.get("Action"))
                    and "*" in _as_list(st.get("Resource"))):
                yield (p["name"], "iam_policy", _crit(p, "high"), "Statement allows * on *")
                break


@rule("IAM-02", "IAM policy allows a service-wide wildcard action on all resources", "High", "IAM",
      "Narrow the service-wide wildcard to the specific actions required and limit Resource to named ARNs.")
def iam_service_wildcard(cfg):
    for p in cfg.get("iam_policies", []):
        for st in _statements(p):
            actions = [a for a in _as_list(st.get("Action")) if a != "*"]
            if (st.get("Effect") == "Allow"
                    and "*" in _as_list(st.get("Resource"))
                    and any(str(a).endswith(":*") for a in actions)):
                yield (p["name"], "iam_policy", _crit(p), "Service wildcard action on Resource *")
                break


@rule("IAM-03", "Root account has no MFA enabled", "Critical", "IAM",
      "Enable an MFA device on the root account and delete any root access keys.")
def iam_root_no_mfa(cfg):
    if cfg.get("account", {}).get("root_mfa_enabled") is False:
        yield (ROOT_RESOURCE, "account", "high", "root_mfa_enabled = false")


@rule("IAM-04", "Root account used within the last 30 days", "High", "IAM",
      "Stop using the root account for routine work; use IAM roles or users with MFA and keep root for break-glass tasks only.")
def iam_root_recent_use(cfg):
    days = cfg.get("account", {}).get("root_last_used_days")
    if days is not None and days <= 30:
        yield (ROOT_RESOURCE, "account", "high", f"root last used {days} day(s) ago")


@rule("IAM-05", "IAM user with console access has no MFA", "High", "IAM",
      "Require MFA for every IAM user that has console access.")
def iam_user_no_mfa(cfg):
    for u in cfg.get("iam_users", []):
        if u.get("console_access") and not u.get("mfa_enabled"):
            yield (u["name"], "iam_user", _crit(u), "console_access = true, mfa_enabled = false")


@rule("IAM-06", "IAM access key not rotated for more than 90 days", "Medium", "IAM",
      "Rotate access keys older than 90 days and prefer short-lived role credentials over long-lived keys.")
def iam_old_keys(cfg):
    for u in cfg.get("iam_users", []):
        old = [k for k in u.get("access_keys", []) if k.get("age_days", 0) > 90]
        if old:
            yield (u["name"], "iam_user", _crit(u), f"{len(old)} key(s) older than 90 days")


@rule("IAM-07", "IAM access key unused for more than 45 days", "Medium", "IAM",
      "Disable or delete access keys that have been unused for more than 45 days.")
def iam_unused_keys(cfg):
    for u in cfg.get("iam_users", []):
        stale = [k for k in u.get("access_keys", [])
                 if k.get("last_used_days") is not None and k["last_used_days"] > 45]
        if stale:
            yield (u["name"], "iam_user", _crit(u), f"{len(stale)} key(s) unused > 45 days")


@rule("IAM-08", "Account password policy minimum length below 14", "Medium", "IAM",
      "Raise the account password policy minimum length to 14 or more characters.")
def iam_weak_password_policy(cfg):
    pp = cfg.get("account", {}).get("password_policy")
    if pp is not None and pp.get("min_length", 0) < 14:
        yield (PASSWORD_POLICY_RESOURCE, "account", "medium", f"min_length = {pp.get('min_length')}")


# ---------------------------------------------------------------- Storage
@rule("S3-01", "S3 bucket is publicly readable", "Critical", "Storage",
      "Remove public read access from the bucket policy and ACLs; serve public content through a CDN if it must be public.")
def s3_public_read(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("public_read"):
            yield (b["name"], "s3_bucket", _crit(b), "public_read = true")


@rule("S3-02", "S3 bucket is publicly writable", "Critical", "Storage",
      "Remove public write access from the bucket policy and ACLs immediately and review the bucket for tampered objects.")
def s3_public_write(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("public_write"):
            yield (b["name"], "s3_bucket", _crit(b), "public_write = true")


@rule("S3-03", "S3 Block Public Access is not enabled", "Medium", "Storage",
      "Turn on S3 Block Public Access for the bucket and for the whole account.")
def s3_no_block_public(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("block_public_access") is False:
            yield (b["name"], "s3_bucket", _crit(b), "block_public_access = false")


@rule("S3-04", "S3 bucket default encryption is disabled", "Medium", "Storage",
      "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.")
def s3_no_encryption(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("encryption_enabled") is False:
            yield (b["name"], "s3_bucket", _crit(b), "encryption_enabled = false")


@rule("S3-05", "S3 bucket access logging is disabled", "Low", "Storage",
      "Enable server access logging and deliver the logs to a separate, protected bucket.")
def s3_no_logging(cfg):
    for b in cfg.get("s3_buckets", []):
        if b.get("logging_enabled") is False:
            yield (b["name"], "s3_bucket", _crit(b), "logging_enabled = false")


@rule("S3-06", "S3 bucket versioning is disabled", "Low", "Storage",
      "Enable bucket versioning, and consider MFA delete for critical data.")
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


@rule("NET-01", "Security group allows SSH (22) from the internet", "High", "Network",
      "Restrict SSH to known IP ranges, or use a bastion host or Session Manager instead of opening port 22 to the internet.")
def net_ssh_open(cfg):
    yield from _sg_rule(cfg, lambda r: _exposes_port(r, (22,)), "port 22 open")


@rule("NET-02", "Security group allows RDP (3389) from the internet", "Critical", "Network",
      "Restrict RDP to known IP ranges, or use a VPN or Session Manager instead of opening port 3389 to the internet.")
def net_rdp_open(cfg):
    yield from _sg_rule(cfg, lambda r: _exposes_port(r, (3389,)), "port 3389 open")


@rule("NET-03", "Security group exposes a database port to the internet", "Critical", "Network",
      "Remove internet access to database ports and keep databases in private subnets reachable only from the application tier.")
def net_db_open(cfg):
    yield from _sg_rule(cfg, lambda r: _exposes_port(r, DB_PORTS), "database port open")


@rule("NET-04", "Security group allows all traffic from the internet", "Critical", "Network",
      "Replace the allow-all rule with rules for only the ports and source ranges that are actually needed.")
def net_all_open(cfg):
    yield from _sg_rule(cfg, lambda r: _is_world(r) and _is_all_traffic(r), "all ports/protocols open")


@rule("NET-05", "Security group exposes the Docker Engine API (2375) to the internet", "Critical", "Network",
      "Do not expose the Docker Engine API (port 2375) to the internet; bind it to localhost or require TLS client authentication, and restrict the security group.")
def net_docker_api_open(cfg):
    yield from _sg_rule(cfg, lambda r: _exposes_port(r, DOCKER_API_PORTS), "Docker API port open")


@rule("NET-06", "Security group exposes the Kubernetes kubelet API (10250) to the internet", "Critical", "Network",
      "Block internet access to the kubelet API (port 10250), enable kubelet authentication and authorization, and limit the security group to the control plane.")
def net_kubelet_open(cfg):
    yield from _sg_rule(cfg, lambda r: _exposes_port(r, KUBELET_PORTS), "kubelet port open")


# ---------------------------------------------------------------- Logging
@rule("LOG-01", "CloudTrail logging is disabled", "High", "Logging",
      "Enable a multi-region CloudTrail trail with log file validation, delivered to a protected S3 bucket.")
def log_cloudtrail_disabled(cfg):
    ct = cfg.get("cloudtrail")
    if ct is not None and ct.get("enabled") is False:
        yield (CLOUDTRAIL_RESOURCE, "account", _crit(ct, "high"), "cloudtrail enabled = false")


# ---------------------------------------------------------------- Compute
@rule("EC2-01", "EC2 instance does not require IMDSv2 (instance metadata service v1 allowed)", "High", "Compute",
      "Require IMDSv2 by setting HttpTokens to required in the instance metadata options.")
def ec2_imdsv1_allowed(cfg):
    for i in cfg.get("ec2_instances", []):
        if i.get("imds_v2_required") is False:
            yield (i["name"], "ec2_instance", _crit(i), "imds_v2_required = false")
