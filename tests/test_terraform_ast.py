"""Tests for Terraform AST parser and multi-file configuration scanning."""
from pathlib import Path
import pytest

from cspm.terraform_scanner import (
    parse_hcl_ast,
    parse_hcl_blocks,
    scan_terraform_directory,
    scan_terraform_file,
    scan_terraform_path,
    scan_terraform_text,
)

FIXTURES_TF = Path(__file__).resolve().parent / "fixtures" / "terraform"


def test_hcl_ast_parser_clean_nodes():
    hcl = '''
    variable "acl" {
      default = "public-read"
    }
    resource "aws_s3_bucket" "test_b" {
      bucket = "demo-bucket"
      acl    = var.acl
    }
    '''
    ast = parse_hcl_ast(hcl)
    assert isinstance(ast, dict)
    assert "resource" in ast or "variable" in ast


def test_single_file_ast_scan_insecure():
    path = FIXTURES_TF / "insecure.tf"
    findings = scan_terraform_file(path)
    assert len(findings) >= 4
    check_ids = {f.check_id for f in findings}
    assert "S3-01" in check_ids  # Public bucket
    assert "NET-01" in check_ids  # Open SSH
    assert "IAM-01" in check_ids  # Wildcard admin
    assert "EC2-01" in check_ids  # IMDSv1


def test_single_file_ast_scan_secure():
    path = FIXTURES_TF / "secure.tf"
    findings = scan_terraform_file(path)
    # Secure fixture should have 0 violations
    assert findings == []


def test_multi_file_directory_scan_insecure():
    dir_path = FIXTURES_TF / "multi_file_insecure"
    findings = scan_terraform_directory(dir_path)
    assert len(findings) >= 4

    check_map = {f.check_id: f for f in findings}
    # Variable resolution across files: acl = var.bucket_acl ("public-read")
    assert "S3-01" in check_map
    assert check_map["S3-01"].resource == "multi_vault"

    # Standalone security group rule in security.tf attached to multi_web_sg in main.tf
    assert "NET-01" in check_map
    assert check_map["NET-01"].resource == "multi_web_sg"

    # Cross-file IAM wildcard
    assert "IAM-01" in check_map
    assert check_map["IAM-01"].resource == "multi_wildcard"

    # Missing IMDSv2
    assert "EC2-01" in check_map
    assert check_map["EC2-01"].resource == "multi_worker"


def test_multi_file_directory_scan_secure():
    dir_path = FIXTURES_TF / "multi_file_secure"
    findings = scan_terraform_directory(dir_path)
    # Strict variables, encryption, private ACL, IMDSv2 required
    assert findings == []


def test_scan_terraform_path_dispatcher():
    # File dispatch
    f_res = scan_terraform_path(FIXTURES_TF / "insecure.tf")
    assert len(f_res) >= 4

    # Directory dispatch
    d_res = scan_terraform_path(FIXTURES_TF / "multi_file_insecure")
    assert len(d_res) >= 4


def test_empty_and_malformed_terraform_resilience():
    assert scan_terraform_text("") == []
    assert scan_terraform_text("   \n\t  ") == []
    # Broken syntax should not raise unhandled exception
    broken = "resource { broken invalid %%%% }]["
    res = scan_terraform_text(broken)
    assert isinstance(res, list)
