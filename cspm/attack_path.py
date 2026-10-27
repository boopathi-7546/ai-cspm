"""Graph-based attack path analysis for AI-CSPM.

Constructs a directed property graph representing cloud resources, exposures,
identities, and permissions based strictly on configuration evidence. Identifies
chained vulnerability paths that allow an adversary to reach critical targets.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from .config import CRITICALITY_SCORE, SEVERITY_SCORE
from .evidence import build_evidence_index, supporting_reports

logger = logging.getLogger(__name__)

try:
    import networkx as nx
except ImportError:
    nx = None  # type: ignore


@dataclass
class AttackStep:
    from_node: str
    to_node: str
    relationship: str
    evidence: str
    technique_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPath:
    path_id: str
    title: str
    entry_point: str
    target: str
    steps: list[AttackStep]
    severity: str
    criticality: str
    risk_score: float
    explanation: str
    mitigations: list[str]
    techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["steps"] = [s.to_dict() if hasattr(s, "to_dict") else s for s in self.steps]
        return d


def build_resource_graph(cfg: dict[str, Any]) -> Any:
    """Construct a directed graph of resources and relationships using NetworkX."""
    if nx is not None:
        g = nx.DiGraph()
    else:
        # Fallback simple graph representation if networkx is missing
        class SimpleGraph:
            def __init__(self):
                self.nodes = {}
                self.edges = []
            def add_node(self, node_id, **attrs):
                self.nodes[node_id] = attrs
            def add_edge(self, u, v, **attrs):
                self.edges.append((u, v, attrs))
        g = SimpleGraph()

    g.add_node("internet:external", type="entry_point", label="Internet / External Attacker")

    # 1. Security Groups
    for sg in cfg.get("security_groups", []):
        if not isinstance(sg, dict) or "name" not in sg:
            continue
        sg_id = f"security_group:{sg['name']}"
        g.add_node(sg_id, type="security_group", name=sg["name"], criticality=sg.get("criticality", "medium"))
        for rule in sg.get("ingress", []):
            if not isinstance(rule, dict):
                continue
            cidr = str(rule.get("cidr", ""))
            proto = str(rule.get("protocol", "tcp")).lower()
            try:
                p_from = int(rule.get("port_from", 0))
                p_to = int(rule.get("port_to", 65535))
            except (ValueError, TypeError):
                p_from, p_to = 0, 65535

            if cidr in ("0.0.0.0/0", "::/0"):
                g.add_edge(
                    "internet:external",
                    sg_id,
                    relationship="EXPOSES_PORT",
                    protocol=proto,
                    ports=f"{p_from}-{p_to}",
                    evidence=f"Ingress from {cidr} on {proto}:{p_from}-{p_to}",
                )

    # 2. EC2 Instances
    for inst in cfg.get("ec2_instances", []):
        if not isinstance(inst, dict) or "name" not in inst:
            continue
        inst_id = f"ec2_instance:{inst['name']}"
        g.add_node(
            inst_id,
            type="ec2_instance",
            name=inst["name"],
            criticality=inst.get("criticality", "medium"),
            imds_v2_required=inst.get("imds_v2_required", True),
        )
        for sg_name in inst.get("security_groups", []):
            sg_id = f"security_group:{sg_name}"
            g.add_edge(sg_id, inst_id, relationship="APPLIES_TO", evidence=f"Instance {inst['name']} in {sg_name}")

    # 3. S3 Buckets
    for b in cfg.get("s3_buckets", []):
        if not isinstance(b, dict) or "name" not in b:
            continue
        bucket_id = f"s3_bucket:{b['name']}"
        g.add_node(
            bucket_id,
            type="s3_bucket",
            name=b["name"],
            criticality=b.get("criticality", "medium"),
            public_read=bool(b.get("public_read")),
            public_write=bool(b.get("public_write")),
        )
        if b.get("public_read") or b.get("public_write"):
            rel = "PUBLIC_READ_WRITE" if (b.get("public_read") and b.get("public_write")) else ("PUBLIC_READ" if b.get("public_read") else "PUBLIC_WRITE")
            g.add_edge(
                "internet:external",
                bucket_id,
                relationship=rel,
                evidence=f"Bucket {b['name']} has public_read={b.get('public_read')}, public_write={b.get('public_write')}",
            )

    # 4. IAM Policies & Users
    for pol in cfg.get("iam_policies", []):
        if not isinstance(pol, dict) or "name" not in pol:
            continue
        pol_id = f"iam_policy:{pol['name']}"
        g.add_node(pol_id, type="iam_policy", name=pol["name"], criticality=pol.get("criticality", "high"))

    for u in cfg.get("iam_users", []):
        if not isinstance(u, dict) or "name" not in u:
            continue
        user_id = f"iam_user:{u['name']}"
        g.add_node(
            user_id,
            type="iam_user",
            name=u["name"],
            criticality=u.get("criticality", "medium"),
            mfa_enabled=bool(u.get("mfa_enabled")),
            console_access=bool(u.get("console_access")),
        )
        for p_name in u.get("attached_policies", []):
            pol_id = f"iam_policy:{p_name}"
            g.add_edge(user_id, pol_id, relationship="ATTACHED_POLICY", evidence=f"User {u['name']} has policy {p_name}")

    return g


def analyze_attack_paths(cfg: dict[str, Any], cti_reports: list[dict] | None = None) -> list[AttackPath]:
    """Identify and rank exploitable attack paths supported by actual configuration evidence."""
    paths: list[AttackPath] = []
    cti = cti_reports or []
    valid_reports = [r for r in cti if isinstance(r, dict) and "techniques" in r]
    evidence_idx = build_evidence_index(valid_reports) if valid_reports else {}

    def _cti_boost(tids: list[str]) -> float:
        if not cti:
            return 0.0
        reps = set()
        for t in tids:
            for r in supporting_reports(t, evidence_idx):
                reps.add(r["report_id"])
        return len(reps) / len(cti)

    # -------------------------------------------------------------------------
    # Path Pattern 1: Public Exposure -> Compute -> IMDSv1 Credential Theft
    # -------------------------------------------------------------------------
    sgs = {sg["name"]: sg for sg in cfg.get("security_groups", []) if isinstance(sg, dict) and "name" in sg}
    for inst in cfg.get("ec2_instances", []):
        if not isinstance(inst, dict) or "name" not in inst:
            continue
        inst_name = inst["name"]
        imds_v1 = (inst.get("imds_v2_required") is False)
        if not imds_v1:
            continue

        for sg_name in inst.get("security_groups", []):
            sg = sgs.get(sg_name)
            if not sg:
                continue
            for r in sg.get("ingress", []):
                if not isinstance(r, dict):
                    continue
                cidr = str(r.get("cidr", ""))
                if cidr in ("0.0.0.0/0", "::/0"):
                    p_from = r.get("port_from", 0)
                    p_to = r.get("port_to", 65535)
                    proto = r.get("protocol", "tcp")

                    tids = ["T1190", "T1552.005", "T1078.004"]
                    weight = _cti_boost(tids)
                    raw_score = 9.0 * CRITICALITY_SCORE.get(str(inst.get("criticality", "high")).lower(), 2) * (1.0 + weight)
                    norm_score = min(99.0, round(raw_score / 60.0 * 100, 1))

                    steps = [
                        AttackStep(
                            from_node="Internet",
                            to_node=f"Security Group '{sg_name}'",
                            relationship="INBOUND_EXPOSURE",
                            evidence=f"Ingress rule allows 0.0.0.0/0 on {proto}:{p_from}-{p_to}",
                            technique_id="T1190",
                        ),
                        AttackStep(
                            from_node=f"Security Group '{sg_name}'",
                            to_node=f"EC2 Instance '{inst_name}'",
                            relationship="NETWORK_ACCESS",
                            evidence=f"Security group '{sg_name}' protects instance '{inst_name}'",
                            technique_id="T1190",
                        ),
                        AttackStep(
                            from_node=f"EC2 Instance '{inst_name}'",
                            to_node="AWS Instance Metadata Service (IMDSv1)",
                            relationship="CREDENTIAL_THEFT",
                            evidence=f"imds_v2_required is false on instance '{inst_name}', allowing tokenless SSRF/credential exfiltration",
                            technique_id="T1552.005",
                        ),
                        AttackStep(
                            from_node="IMDSv1",
                            to_node="Cloud Account Access Keys",
                            relationship="PRIVILEGE_ACQUISITION",
                            evidence="Adversary retrieves temporary instance profile security credentials via HTTP GET /latest/meta-data/iam/security-credentials/",
                            technique_id="T1078.004",
                        ),
                    ]

                    paths.append(
                        AttackPath(
                            path_id=f"AP-IMDS-{inst_name}-{sg_name}",
                            title=f"Remote Network Exposure to IMDSv1 Credential Exfiltration on '{inst_name}'",
                            entry_point="Internet (0.0.0.0/0)",
                            target=f"EC2 Instance Profile Credentials ('{inst_name}')",
                            steps=steps,
                            severity="Critical",
                            criticality=str(inst.get("criticality", "high")).capitalize(),
                            risk_score=norm_score,
                            explanation=(
                                f"Instance '{inst_name}' is accessible from the internet through security group '{sg_name}' "
                                f"and allows legacy IMDSv1. An external attacker exploiting an application vulnerability or exposed port "
                                f"can issue server-side requests to retrieve AWS IAM instance role credentials without token authentication."
                            ),
                            mitigations=[
                                f"Enforce IMDSv2 on instance '{inst_name}' by setting HttpTokens to required.",
                                f"Restrict ingress rules on security group '{sg_name}' to trusted CIDR blocks instead of 0.0.0.0/0.",
                                "Ensure instance profile role adheres to strict least-privilege permissions.",
                            ],
                            techniques=tids,
                        )
                    )
                    break

    # -------------------------------------------------------------------------
    # Path Pattern 2: Public S3 Storage Containing Sensitive Business Data
    # -------------------------------------------------------------------------
    for b in cfg.get("s3_buckets", []):
        if not isinstance(b, dict) or "name" not in b:
            continue
        b_name = b["name"]
        pub_read = bool(b.get("public_read"))
        pub_write = bool(b.get("public_write"))
        crit = str(b.get("criticality", "medium")).lower()

        if pub_read or pub_write:
            tids = ["T1530"]
            if pub_write:
                tids.extend(["T1485", "T1486"])
            weight = _cti_boost(tids)
            base_sev = 10.0 if (pub_write or crit == "high") else 8.0
            raw_score = base_sev * CRITICALITY_SCORE.get(crit, 2) * (1.0 + weight)
            norm_score = min(99.0, round(raw_score / 60.0 * 100, 1))

            action_type = "Public Read & Tamper" if (pub_read and pub_write) else ("Public Data Read" if pub_read else "Public Data Write")
            steps = [
                AttackStep(
                    from_node="Internet (Anonymous Attacker)",
                    to_node=f"S3 Bucket '{b_name}'",
                    relationship="DIRECT_ANONYMOUS_ACCESS",
                    evidence=f"public_read={pub_read}, public_write={pub_write}, block_public_access={b.get('block_public_access')}",
                    technique_id="T1530",
                ),
                AttackStep(
                    from_node=f"S3 Bucket '{b_name}'",
                    to_node="Protected Cloud Storage Data",
                    relationship="UNAUTHENTICATED_EXFILTRATION",
                    evidence=f"Asset criticality '{crit}'. S3 API allows anonymous GetObject / PutObject over HTTPS.",
                    technique_id="T1530" if pub_read else "T1485",
                ),
            ]

            paths.append(
                AttackPath(
                    path_id=f"AP-S3-{b_name}",
                    title=f"Direct Anonymous Cloud Data Breach on '{b_name}'",
                    entry_point="Internet (Anonymous Request)",
                    target=f"S3 Bucket Asset '{b_name}' ({crit} criticality)",
                    steps=steps,
                    severity="Critical" if (crit == "high" or pub_write) else "High",
                    criticality=crit.capitalize(),
                    risk_score=norm_score,
                    explanation=(
                        f"Bucket '{b_name}' permits unrestricted {action_type.lower()} from anonymous internet callers without authentication. "
                        f"An attacker can directly exfiltrate or tamper with stored cloud objects without breaching perimeter defenses."
                    ),
                    mitigations=[
                        f"Enable S3 Block Public Access on bucket '{b_name}' and account-wide.",
                        f"Remove public Principal ('*') grants from bucket policies and Access Control Lists (ACLs).",
                        "Audit S3 access logs and CloudTrail data events for unauthorized data access.",
                    ],
                    techniques=tids,
                )
            )

    # -------------------------------------------------------------------------
    # Path Pattern 3: Stale Credentials / No-MFA User -> Admin Privilege Escalation
    # -------------------------------------------------------------------------
    for u in cfg.get("iam_users", []):
        if not isinstance(u, dict) or "name" not in u:
            continue
        u_name = u["name"]
        no_mfa = (u.get("console_access") and not u.get("mfa_enabled"))
        old_keys = [k for k in u.get("access_keys", []) if isinstance(k, dict) and k.get("age_days", 0) > 90]
        has_stale_key = bool(old_keys)

        if no_mfa or has_stale_key:
            # Check if attached to admin wildcard policy
            for pol in cfg.get("iam_policies", []):
                if not isinstance(pol, dict) or "name" not in pol:
                    continue
                pol_name = pol["name"]
                if pol_name in u.get("attached_policies", []):
                    doc = pol.get("document", {})
                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    
                    is_admin = False
                    for st in statements:
                        if isinstance(st, dict) and st.get("Effect") == "Allow":
                            act = st.get("Action", [])
                            res = st.get("Resource", [])
                            act_list = [act] if isinstance(act, str) else list(act)
                            res_list = [res] if isinstance(res, str) else list(res)
                            if "*" in act_list and "*" in res_list:
                                is_admin = True
                                break

                    if is_admin:
                        tids = ["T1552.001", "T1078.004", "T1098"]
                        weight = _cti_boost(tids)
                        crit = str(u.get("criticality", "high")).lower()
                        raw_score = 10.0 * CRITICALITY_SCORE.get(crit, 3) * (1.0 + weight)
                        norm_score = min(99.0, round(raw_score / 60.0 * 100, 1))

                        entry_reason = f"Console login without MFA" if no_mfa else f"Unrotated access key ({old_keys[0].get('age_days')} days old)"
                        steps = [
                            AttackStep(
                                from_node="Adversary Foothold",
                                to_node=f"IAM User '{u_name}'",
                                relationship="CREDENTIAL_ACCESS",
                                evidence=f"User '{u_name}' vulnerability: {entry_reason}",
                                technique_id="T1078.004",
                            ),
                            AttackStep(
                                from_node=f"IAM User '{u_name}'",
                                to_node=f"IAM Policy '{pol_name}'",
                                relationship="POLICY_ATTACHMENT",
                                evidence=f"Policy '{pol_name}' is attached to user '{u_name}'",
                                technique_id="T1098",
                            ),
                            AttackStep(
                                from_node=f"IAM Policy '{pol_name}'",
                                to_node="AWS Account Administrator Control",
                                relationship="FULL_CLOUD_TAKEOVER",
                                evidence=f"Statement allows Action='*' on Resource='*', giving full administrative rights",
                                technique_id="T1098",
                            ),
                        ]

                        paths.append(
                            AttackPath(
                                path_id=f"AP-IAM-ADMIN-{u_name}",
                                title=f"Compromised IAM Identity to Full Account Takeover via '{pol_name}'",
                                entry_point=f"Compromised User '{u_name}' ({entry_reason})",
                                target="AWS Account Root/Administrator Scope",
                                steps=steps,
                                severity="Critical",
                                criticality=crit.capitalize(),
                                risk_score=norm_score,
                                explanation=(
                                    f"IAM user '{u_name}' possesses weak credential security ({entry_reason}) while holding "
                                    f"administrator policy '{pol_name}'. Once this user's credentials are leaked or sprayed, "
                                    f"an adversary gains immediate full administrative sovereignty over the entire cloud infrastructure."
                                ),
                                mitigations=[
                                    f"Enforce Multi-Factor Authentication (MFA) immediately on user '{u_name}'.",
                                    f"Detach wildcard policy '{pol_name}' and scope permissions down to specific needed services.",
                                    "Rotate and disable stale access keys older than 90 days.",
                                ],
                                techniques=tids,
                            )
                        )

    # Sort attack paths by risk score descending
    paths.sort(key=lambda p: p.risk_score, reverse=True)
    return paths
