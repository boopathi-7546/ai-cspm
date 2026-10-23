from cspm.config import CONFIG_DIR
from cspm.rules import RULES
from cspm.scanner import load_config, scan_config


def ids(cfg):
    return {(f.resource, f.check_id) for f in scan_config(cfg)}


def test_rule_ids_unique_and_count():
    assert len({r.check_id for r in RULES}) == len(RULES) == 18


def test_admin_wildcard_detected_and_scoped_policy_not():
    cfg = {"iam_policies": [
        {"name": "A", "document": {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}},
        {"name": "B", "document": {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:x"}]}},
        {"name": "C", "document": {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}}]}
    assert ids(cfg) == {("A", "IAM-01")}


def test_service_wildcard_not_double_counted_with_admin():
    cfg = {"iam_policies": [{"name": "S", "document": {"Statement": [
        {"Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"]}]}}]}
    assert ids(cfg) == {("S", "IAM-02")}


def test_thresholds_are_strict():
    cfg = {"account": {"root_last_used_days": 31, "password_policy": {"min_length": 14}},
           "iam_users": [{"name": "u", "console_access": False,
                          "access_keys": [{"age_days": 90, "last_used_days": 45}]}]}
    assert ids(cfg) == set()
    cfg["account"]["root_last_used_days"] = 30
    cfg["account"]["password_policy"]["min_length"] = 13
    cfg["iam_users"][0]["access_keys"] = [{"age_days": 91, "last_used_days": 46}]
    assert ids(cfg) == {("root-account", "IAM-04"), ("password-policy", "IAM-08"),
                        ("u", "IAM-06"), ("u", "IAM-07")}


def test_missing_fields_are_not_flagged():
    assert ids({"account": {}, "s3_buckets": [{"name": "b"}]}) == set()


def sg(*rules):
    return {"security_groups": [{"name": "g", "ingress": [
        {"protocol": p, "port_from": a, "port_to": b, "cidr": c} for p, a, b, c in rules]}]}


def test_security_group_rules():
    assert ids(sg(("tcp", 22, 22, "0.0.0.0/0"))) == {("g", "NET-01")}
    assert ids(sg(("tcp", 3389, 3389, "::/0"))) == {("g", "NET-02")}
    assert ids(sg(("tcp", 5432, 5432, "0.0.0.0/0"))) == {("g", "NET-03")}
    assert ids(sg(("tcp", 20, 25, "0.0.0.0/0"))) == {("g", "NET-01")}  # port range containing 22


def test_all_traffic_reported_once_as_net04():
    assert ids(sg(("-1", 0, 65535, "0.0.0.0/0"))) == {("g", "NET-04")}


def test_safe_security_groups_not_flagged():
    assert ids(sg(("tcp", 443, 443, "0.0.0.0/0"), ("tcp", 22, 22, "10.0.0.0/8"),
                  ("tcp", 22, 22, "203.0.113.0/24"), ("udp", 22, 22, "0.0.0.0/0"))) == set()


def test_s3_rules():
    b = {"name": "b", "public_read": True, "public_write": True, "block_public_access": False,
         "encryption_enabled": False, "logging_enabled": False, "versioning_enabled": False}
    assert {c for _, c in ids({"s3_buckets": [b]})} == {f"S3-0{i}" for i in range(1, 7)}
    good = {"name": "g", "public_read": False, "public_write": False, "block_public_access": True,
            "encryption_enabled": True, "logging_enabled": True, "versioning_enabled": True}
    assert ids({"s3_buckets": [good]}) == set()


def test_sample_environments():
    assert ids(load_config(CONFIG_DIR / "secure_env.json")) == set()
    assert ids(load_config(CONFIG_DIR / "ambiguous_env.json")) == {("legacy-reports", "S3-03")}
