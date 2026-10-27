from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from conftest import FIXTURES
from cspm.compliance import (
    CIS_AWS_CONTROLS,
    NIST_800_53_CONTROLS,
    evaluate_compliance_framework,
    generate_full_compliance_report,
)
from cspm.providers import AWSLiveProvider, AzureProvider, GCPProvider
from cspm.scanner import Finding
from cspm.terraform_scanner import scan_terraform_file, scan_terraform_text

TF_DIR = FIXTURES / "terraform"


# -----------------------------------------------------------------------------
# A. Terraform Scanning Tests
# -----------------------------------------------------------------------------
def test_terraform_scan_insecure():
    insecure_tf = TF_DIR / "insecure.tf"
    findings = scan_terraform_file(insecure_tf)
    assert len(findings) >= 3

    check_ids = {f.check_id for f in findings}
    assert "S3-01" in check_ids  # public-read S3
    assert "NET-01" in check_ids  # port 22 open
    assert "IAM-01" in check_ids  # admin * on *
    assert "EC2-01" in check_ids  # IMDSv1 allowed

    # Ensure format matches normalized Finding
    f = next(f for f in findings if f.check_id == "S3-01")
    assert f.severity == "Critical"
    assert f.category == "Storage"
    assert len(f.remediation) > 0


def test_terraform_scan_secure():
    secure_tf = TF_DIR / "secure.tf"
    findings = scan_terraform_file(secure_tf)
    # Hardened infrastructure has zero findings
    assert len(findings) == 0


def test_terraform_json_support():
    tf_json = """
    {
      "resource": {
        "aws_s3_bucket": {
          "public_data": {
            "acl": "public-read"
          }
        },
        "aws_security_group": {
          "open_ssh": {
            "ingress": [
              {
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["0.0.0.0/0"]
              }
            ]
          }
        }
      }
    }
    """
    findings = scan_terraform_text(tf_json, filename="infra.tf.json")
    assert len(findings) == 2
    assert {f.check_id for f in findings} == {"S3-01", "NET-01"}


# -----------------------------------------------------------------------------
# B. Compliance Framework Mapping Tests
# -----------------------------------------------------------------------------
def test_compliance_evaluation_cis_and_nist():
    findings = [
        Finding(
            resource="data-bucket",
            resource_type="s3_bucket",
            check_id="S3-01",
            title="S3 bucket is publicly readable",
            severity="Critical",
            criticality="high",
            detail="public_read = true",
            category="Storage",
            remediation="Fix it",
        ),
        Finding(
            resource="open-sg",
            resource_type="security_group",
            check_id="NET-01",
            title="SSH from world",
            severity="High",
            criticality="high",
            detail="port 22 open",
            category="Network",
            remediation="Fix it",
        ),
    ]

    report = generate_full_compliance_report(findings)
    assert "cis_aws" in report["benchmarks"]
    assert "nist_800_53" in report["benchmarks"]

    cis = report["benchmarks"]["cis_aws"]
    s = cis["summary"]
    # Both passed, failed, and unassessed must be separated
    assert s["failed"] >= 2
    assert s["passed"] >= 1
    assert s["unassessed"] >= 1
    assert "assessment_disclaimer" in cis
    assert "coverage_rate_percent" in s

    # Check that failed control contains evidence
    failed_ctrl = next(c for c in cis["failed_controls"] if c["control_id"] == "5.1")
    assert failed_ctrl["status"] == "FAILED"
    assert len(failed_ctrl["evidence"]) > 0


# -----------------------------------------------------------------------------
# C & D. Cloud Providers Architecture & Live AWS Tests
# -----------------------------------------------------------------------------
def test_azure_and_gcp_planned_interfaces():
    azure = AzureProvider(subscription_id="sub-123", tenant_id="tenant-456")
    assert azure.name == "azure"
    conn_a = azure.test_connection()
    assert conn_a["connected"] is False
    assert conn_a["status"] == "planned"

    gcp = GCPProvider(project_id="my-gcp-project")
    assert gcp.name == "gcp"
    conn_g = gcp.test_connection()
    assert conn_g["connected"] is False
    assert conn_g["status"] == "planned"


@patch("cspm.providers.aws.boto3")
def test_aws_live_provider_mocked_scan(mock_boto3):
    # Mock boto3 session and clients
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {
        "Account": "112233445566",
        "Arn": "arn:aws:iam::112233445566:user/security-audit",
        "UserId": "AIDAXAMPLE",
    }

    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "prod-customer-archive"}]}
    mock_s3.get_public_access_block.side_effect = Exception("NoSuchPublicAccessBlockConfiguration")
    mock_s3.get_bucket_encryption.side_effect = Exception("ServerSideEncryptionConfigurationNotFoundError")

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-12345",
                "GroupName": "open-ssh",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
    }

    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {"trailList": []}

    def client_factory(service_name):
        if service_name == "sts":
            return mock_sts
        elif service_name == "s3":
            return mock_s3
        elif service_name == "ec2":
            return mock_ec2
        elif service_name == "cloudtrail":
            return mock_ct
        return MagicMock()

    mock_session.client.side_effect = client_factory

    provider = AWSLiveProvider(region_name="us-east-1")
    conn = provider.test_connection()
    assert conn["connected"] is True
    assert conn["account_id"] == "112233445566"

    # Scan live configuration in read-only mode
    findings = provider.scan_live()
    assert len(findings) >= 1
    check_ids = {f.check_id for f in findings}
    assert "NET-01" in check_ids  # Discovered open SSH port 22 from mocked describe_security_groups
