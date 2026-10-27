import pytest
from cspm.attack_path import (
    build_resource_graph,
    analyze_attack_paths,
    AttackPath,
    AttackStep,
)


def test_build_resource_graph():
    cfg = {
        "s3_buckets": [{"name": "my-vault", "public_read": True, "criticality": "high"}],
        "security_groups": [
            {
                "name": "sg-open",
                "ingress": [{"cidr": "0.0.0.0/0", "protocol": "tcp", "port_from": 22, "port_to": 22}],
            }
        ],
        "ec2_instances": [{"name": "bastion", "security_groups": ["sg-open"], "imds_v2_required": False}],
    }
    g = build_resource_graph(cfg)
    # Check nodes exist
    if hasattr(g, "has_node"):
        assert g.has_node("internet:external")
        assert g.has_node("s3_bucket:my-vault")
        assert g.has_node("security_group:sg-open")
        assert g.has_node("ec2_instance:bastion")


def test_detect_s3_public_attack_path():
    cfg = {
        "s3_buckets": [
            {"name": "customer-pii", "public_read": True, "public_write": False, "criticality": "high"}
        ]
    }
    paths = analyze_attack_paths(cfg)
    assert len(paths) >= 1
    s3_path = paths[0]
    assert "customer-pii" in s3_path.title
    assert s3_path.severity == "Critical"
    assert s3_path.risk_score > 0
    assert "T1530" in s3_path.techniques
    assert len(s3_path.steps) >= 2
    assert len(s3_path.mitigations) >= 1


def test_detect_imds_credential_theft_path():
    cfg = {
        "security_groups": [
            {
                "name": "sg-ssh-open",
                "ingress": [{"cidr": "0.0.0.0/0", "protocol": "tcp", "port_from": 22, "port_to": 22}],
            }
        ],
        "ec2_instances": [
            {
                "name": "prod-app-server",
                "security_groups": ["sg-ssh-open"],
                "imds_v2_required": False,
                "criticality": "high",
            }
        ],
    }
    paths = analyze_attack_paths(cfg)
    assert len(paths) >= 1
    imds_path = next(p for p in paths if "IMDS" in p.path_id or "prod-app-server" in p.title)
    assert imds_path.entry_point.startswith("Internet")
    assert "IMDSv1" in imds_path.target or "Credentials" in imds_path.target
    assert "T1190" in imds_path.techniques
    assert "T1552.005" in imds_path.techniques


def test_detect_iam_privilege_escalation_path():
    cfg = {
        "iam_users": [
            {
                "name": "developer-bob",
                "console_access": True,
                "mfa_enabled": False,
                "attached_policies": ["FullAdministrator"],
                "criticality": "high",
            }
        ],
        "iam_policies": [
            {
                "name": "FullAdministrator",
                "document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            }
        ],
    }
    paths = analyze_attack_paths(cfg)
    assert len(paths) >= 1
    admin_path = next(p for p in paths if "developer-bob" in p.path_id)
    assert admin_path.severity == "Critical"
    assert "FullAdministrator" in admin_path.title
    assert "T1098" in admin_path.techniques


def test_clean_config_yields_zero_attack_paths():
    # Secure environment: closed SGs, IMDSv2 enabled, MFA enabled, private S3
    secure_cfg = {
        "s3_buckets": [{"name": "private-data", "public_read": False, "public_write": False}],
        "security_groups": [
            {
                "name": "sg-internal",
                "ingress": [{"cidr": "10.0.0.0/16", "protocol": "tcp", "port_from": 443, "port_to": 443}],
            }
        ],
        "ec2_instances": [
            {"name": "secure-app", "security_groups": ["sg-internal"], "imds_v2_required": True}
        ],
        "iam_users": [
            {"name": "alice", "console_access": True, "mfa_enabled": True, "attached_policies": []}
        ],
    }
    paths = analyze_attack_paths(secure_cfg)
    assert paths == []


def test_malformed_input_attack_path_handling():
    # Must not crash on invalid or empty configurations
    assert analyze_attack_paths({}) == []
    assert analyze_attack_paths({"s3_buckets": "not-a-list"}) == []
    assert analyze_attack_paths({"ec2_instances": [{"missing_name": 1}]}) == []
    assert analyze_attack_paths({"security_groups": [None, 123, {}]}) == []
