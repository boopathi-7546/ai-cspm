"""Versioned, traceable compliance mapping engine.

Maps AI-CSPM scanner rules to recognized security frameworks:
- CIS AWS Foundations Benchmark v1.4.0
- NIST SP 800-53 Rev 5

Separates controls into PASSED, FAILED, and UNASSESSED to prevent misleading
claims of full compliance based on partial automated coverage.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .scanner import Finding


@dataclass
class ComplianceControl:
    framework: str
    version: str
    control_id: str
    title: str
    check_ids: list[str]
    level: str = "Level 1"
    assessment_type: str = "Automated"
    limitations: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Comprehensive registry of CIS AWS Foundations Benchmark controls
CIS_AWS_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="1.5",
        title="Ensure MFA is enabled for the 'root' user account",
        check_ids=["IAM-03"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Checks root_mfa_enabled flag in account configuration export.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="1.7",
        title="Eliminate use of the 'root' user account for administrative activities",
        check_ids=["IAM-04"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Evaluates root account last_used_days threshold (30 days).",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="1.8",
        title="Ensure IAM password policy requires minimum length of 14 or greater",
        check_ids=["IAM-08"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Evaluates min_length field in password_policy block.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="1.10",
        title="Ensure multi-factor authentication (MFA) is enabled for all IAM users with console passwords",
        check_ids=["IAM-05"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Assesses users with console_access=True for mfa_enabled flag.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="1.14",
        title="Ensure access keys are rotated every 90 days or less",
        check_ids=["IAM-06"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Calculates age_days on each active IAM user access key.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="1.16",
        title="Ensure IAM policies that allow full '*:*' administrative privileges are not created",
        check_ids=["IAM-01", "IAM-02"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Inspects policy documents for Effect=Allow with wildcard Action and Resource.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="2.1.1",
        title="Ensure all S3 buckets employ encryption-at-rest",
        check_ids=["S3-04"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Checks encryption_enabled attribute on S3 bucket definitions.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="2.1.4",
        title="Ensure that S3 Buckets are configured with 'Block Public Access'",
        check_ids=["S3-01", "S3-02", "S3-03"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Evaluates block_public_access, public_read, and public_write flags.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="2.1.3",
        title="Ensure MFA Delete is enabled on S3 buckets",
        check_ids=["S3-06"],
        level="Level 2",
        assessment_type="Automated",
        limitations="Evaluates bucket versioning; does not assess hardware token requirement.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="3.1",
        title="Ensure CloudTrail is enabled in all regions",
        check_ids=["LOG-01"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Assesses cloudtrail.enabled flag in configuration.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="5.1",
        title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (SSH)",
        check_ids=["NET-01", "NET-04"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Evaluates security group ingress rules for CIDR 0.0.0.0/0 covering port 22.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="5.2",
        title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (RDP)",
        check_ids=["NET-02", "NET-04"],
        level="Level 1",
        assessment_type="Automated",
        limitations="Evaluates security group ingress rules for CIDR 0.0.0.0/0 covering port 3389.",
    ),
    # Unassessed Controls (Manual / Architecture / Operational)
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="1.1",
        title="Maintain current contact details in AWS account settings",
        check_ids=[],
        level="Level 1",
        assessment_type="Manual / External API",
        limitations="Requires AWS Account Management API; not assessable via static IAM/resource exports.",
    ),
    ComplianceControl(
        framework="CIS AWS Foundations Benchmark",
        version="v1.4.0",
        control_id="2.2.1",
        title="Ensure EBS volume encryption is enabled",
        check_ids=[],
        level="Level 1",
        assessment_type="Unassessed",
        limitations="EBS default encryption settings require EC2 regional configuration export.",
    ),
]


NIST_800_53_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        framework="NIST SP 800-53",
        version="Rev 5",
        control_id="AC-2",
        title="Account Management",
        check_ids=["IAM-05", "IAM-06", "IAM-07"],
        level="Moderate",
        assessment_type="Partially Automated",
        limitations="Covers inactive credentials, rotation, and MFA enforcement.",
    ),
    ComplianceControl(
        framework="NIST SP 800-53",
        version="Rev 5",
        control_id="AC-3",
        title="Access Enforcement",
        check_ids=["IAM-01", "IAM-02", "S3-01", "S3-02"],
        level="Moderate",
        assessment_type="Automated",
        limitations="Evaluates IAM wildcards and public S3 bucket policies.",
    ),
    ComplianceControl(
        framework="NIST SP 800-53",
        version="Rev 5",
        control_id="AC-6",
        title="Least Privilege",
        check_ids=["IAM-01", "IAM-02"],
        level="Moderate",
        assessment_type="Automated",
        limitations="Focuses on administrative wildcard assignments (*:*).",
    ),
    ComplianceControl(
        framework="NIST SP 800-53",
        version="Rev 5",
        control_id="SC-7",
        title="Boundary Protection",
        check_ids=["NET-01", "NET-02", "NET-03", "NET-04", "NET-05", "NET-06"],
        level="Moderate",
        assessment_type="Automated",
        limitations="Assesses public ingress on sensitive administration and application ports.",
    ),
    ComplianceControl(
        framework="NIST SP 800-53",
        version="Rev 5",
        control_id="SC-8",
        title="Transmission Confidentiality and Integrity",
        check_ids=["S3-04"],
        level="Moderate",
        assessment_type="Partially Automated",
        limitations="Covers default storage encryption at rest.",
    ),
    ComplianceControl(
        framework="NIST SP 800-53",
        version="Rev 5",
        control_id="AU-2",
        title="Event Logging",
        check_ids=["LOG-01", "S3-05"],
        level="Moderate",
        assessment_type="Automated",
        limitations="Verifies CloudTrail and S3 access logging activation.",
    ),
]


def evaluate_compliance_framework(
    findings: list[Finding | dict],
    controls: list[ComplianceControl],
    has_evaluated_data: bool = True,
) -> dict[str, Any]:
    """Evaluate compliance against a control list, separating passed, failed, and unassessed."""
    failed_controls = []
    passed_controls = []
    unassessed_controls = []

    # Map check_id to list of failing findings
    finding_map: dict[str, list[dict]] = {}
    for f in findings:
        f_dict = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        cid = f_dict.get("check_id", "")
        finding_map.setdefault(cid, []).append(f_dict)

    for ctrl in controls:
        ctrl_dict = ctrl.to_dict()
        if not ctrl.check_ids or ctrl.assessment_type == "Unassessed":
            ctrl_dict["status"] = "UNASSESSED"
            ctrl_dict["reason"] = ctrl.limitations or "Requires manual inspection or external API access."
            unassessed_controls.append(ctrl_dict)
            continue

        matched_findings = []
        for cid in ctrl.check_ids:
            if cid in finding_map:
                matched_findings.extend(finding_map[cid])

        if matched_findings:
            ctrl_dict["status"] = "FAILED"
            ctrl_dict["failing_findings_count"] = len(matched_findings)
            ctrl_dict["evidence"] = [
                f"{item.get('resource')} ({item.get('check_id')}): {item.get('detail')}"
                for item in matched_findings[:4]
            ]
            failed_controls.append(ctrl_dict)
        else:
            if has_evaluated_data:
                ctrl_dict["status"] = "PASSED"
                ctrl_dict["evidence"] = "No compliance violations detected during rule evaluation."
                passed_controls.append(ctrl_dict)
            else:
                ctrl_dict["status"] = "UNASSESSED"
                ctrl_dict["reason"] = "No configuration data provided for assessment."
                unassessed_controls.append(ctrl_dict)

    total_controls = len(controls)
    assessed_count = len(passed_controls) + len(failed_controls)
    compliance_score = (
        round((len(passed_controls) / assessed_count) * 100, 1) if assessed_count else 0.0
    )
    coverage_rate = (
        round((assessed_count / total_controls) * 100, 1) if total_controls else 0.0
    )

    framework_name = controls[0].framework if controls else "Unknown"
    framework_version = controls[0].version if controls else ""

    return {
        "framework": framework_name,
        "version": framework_version,
        "summary": {
            "total_controls": total_controls,
            "passed": len(passed_controls),
            "failed": len(failed_controls),
            "unassessed": len(unassessed_controls),
            "compliance_score_percent": compliance_score,
            "coverage_rate_percent": coverage_rate,
        },
        "passed_controls": passed_controls,
        "failed_controls": failed_controls,
        "unassessed_controls": unassessed_controls,
        "assessment_disclaimer": (
            f"Compliance results represent automated rule coverage ({coverage_rate}% of benchmark). "
            "Passing automated checks does not guarantee complete regulatory or legal compliance. "
            "Unassessed and operational controls require separate organizational verification."
        ),
    }


def generate_full_compliance_report(findings: list[Finding | dict]) -> dict[str, Any]:
    """Generate multi-framework compliance assessment report."""
    cis = evaluate_compliance_framework(findings, CIS_AWS_CONTROLS, has_evaluated_data=bool(findings))
    nist = evaluate_compliance_framework(findings, NIST_800_53_CONTROLS, has_evaluated_data=bool(findings))
    return {
        "benchmarks": {
            "cis_aws": cis,
            "nist_800_53": nist,
        }
    }
