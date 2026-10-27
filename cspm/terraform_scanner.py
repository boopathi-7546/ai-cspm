"""Static analysis of Terraform (.tf and .tf.json) infrastructure-as-code files.

Features:
- AST parsing using python-hcl2 with deterministic regex fallback.
- Multi-file configuration scanning and cross-file variable/local resolution.
- Resource correlation (e.g., aws_security_group_rule linked to aws_security_group).
- Outputs findings matching the normalized AI-CSPM Finding format.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from .scanner import Finding

logger = logging.getLogger(__name__)

try:
    import hcl2
except ImportError:
    hcl2 = None  # type: ignore


def _strip_quotes(s: str) -> str:
    """Strip surrounding double or single quotes from strings."""
    if not isinstance(s, str):
        return s
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def _clean_ast_node(val: Any) -> Any:
    """Recursively clean quotes from AST nodes produced by python-hcl2."""
    if isinstance(val, dict):
        return {_strip_quotes(k): _clean_ast_node(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_clean_ast_node(item) for item in val]
    if isinstance(val, str):
        return _strip_quotes(val)
    return val


def parse_hcl_ast(text: str) -> dict[str, Any]:
    """Parse Terraform HCL text into an AST structure using python-hcl2."""
    if not hcl2:
        return {}
    try:
        parsed = hcl2.loads(text)
        return _clean_ast_node(parsed) if isinstance(parsed, dict) else {}
    except Exception as exc:
        logger.debug("python-hcl2 AST parsing failed: %s; falling back to regex parser", exc)
        return {}


def parse_hcl_blocks(text: str) -> list[dict]:
    """Lightweight deterministic regex-based fallback parser for HCL resource blocks."""
    resources = []
    pattern = re.compile(
        r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([\s\S]*?)\n\s*\}',
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        rtype, rname, body = match.group(1), match.group(2), match.group(3)
        resources.append({"type": rtype, "name": rname, "body": body})
    return resources


def _resolve_var_ref(val: Any, variables: dict[str, Any], locals_map: dict[str, Any]) -> Any:
    """Substitute var.<name> or local.<name> references with resolved default values."""
    if not isinstance(val, str):
        return val
    s = val.strip()

    # var.xyz or ${var.xyz}
    var_match = re.search(r'\bvar\.([a-zA-Z0-9_-]+)\b', s)
    if var_match:
        var_name = var_match.group(1)
        if var_name in variables:
            return variables[var_name]

    # local.xyz or ${local.xyz}
    local_match = re.search(r'\blocal\.([a-zA-Z0-9_-]+)\b', s)
    if local_match:
        local_name = local_match.group(1)
        if local_name in locals_map:
            return locals_map[local_name]

    return val


class TerraformContext:
    """Holds parsed resources, variables, locals, and rules across one or more files."""

    def __init__(self) -> None:
        self.variables: dict[str, Any] = {}
        self.locals: dict[str, Any] = {}
        self.resources: list[dict[str, Any]] = []
        self.raw_blocks: list[dict[str, Any]] = []  # Fallback regex blocks

    def add_variable(self, name: str, config: dict | Any) -> None:
        if isinstance(config, dict) and "default" in config:
            self.variables[name] = _clean_ast_node(config["default"])
        elif isinstance(config, (str, int, float, bool, list)):
            self.variables[name] = config

    def add_local(self, name: str, val: Any) -> None:
        self.locals[name] = _clean_ast_node(val)

    def add_resource(self, rtype: str, rname: str, config: dict[str, Any], filename: str) -> None:
        self.resources.append({
            "type": rtype,
            "name": rname,
            "config": config,
            "filename": filename
        })

    def resolve(self, val: Any) -> Any:
        return _resolve_var_ref(val, self.variables, self.locals)


def _populate_context_from_ast(ctx: TerraformContext, ast_data: dict[str, Any], filename: str) -> None:
    """Extract variables, locals, and resources from AST dict."""
    # Variables
    for var_entry in ast_data.get("variable", []):
        if isinstance(var_entry, dict):
            for vname, vcfg in var_entry.items():
                ctx.add_variable(vname, vcfg)

    # Locals
    for local_entry in ast_data.get("locals", []):
        if isinstance(local_entry, dict):
            for lname, lval in local_entry.items():
                ctx.add_local(lname, lval)

    # Resources
    for res_entry in ast_data.get("resource", []):
        if isinstance(res_entry, dict):
            for rtype, rdict in res_entry.items():
                if isinstance(rdict, dict):
                    for rname, rcfg in rdict.items():
                        if isinstance(rcfg, dict):
                            ctx.add_resource(rtype, rname, rcfg, filename)


def _evaluate_context(ctx: TerraformContext) -> list[Finding]:
    """Evaluate deterministic security rules against the aggregated Terraform context."""
    findings: list[Finding] = []

    # Map of security groups for cross-file rule attachment
    sg_map = {
        r["name"]: r for r in ctx.resources if r["type"] == "aws_security_group"
    }
    # Map of s3 buckets for cross-file public access block / encryption
    s3_map = {
        r["name"]: r for r in ctx.resources if r["type"] == "aws_s3_bucket"
    }
    # Standalone S3 public access blocks
    s3_pabs = [
        r for r in ctx.resources if r["type"] == "aws_s3_bucket_public_access_block"
    ]
    # Standalone S3 encryption configs
    s3_encs = [
        r for r in ctx.resources if r["type"] == "aws_s3_bucket_server_side_encryption_configuration"
    ]
    # Standalone security group rules
    sg_rules = [
        r for r in ctx.resources if r["type"] == "aws_security_group_rule"
    ]

    # -------------------------------------------------------------------------
    # 1. S3 Buckets (S3-01, S3-04)
    # -------------------------------------------------------------------------
    for r in ctx.resources:
        if r["type"] == "aws_s3_bucket":
            cfg = r["config"]
            name = r["name"]
            filename = r["filename"]

            acl = ctx.resolve(cfg.get("acl"))
            if acl in ("public-read", "public-read-write"):
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="s3_bucket",
                        check_id="S3-01",
                        title="Terraform S3 bucket configured with public-read ACL",
                        severity="Critical",
                        criticality="high",
                        detail=f"{filename}: aws_s3_bucket.{name} sets public ACL '{acl}'",
                        category="Storage",
                        remediation="Set acl = 'private' and attach an aws_s3_bucket_public_access_block resource.",
                    )
                )

            # Check encryption either directly on bucket or via standalone resource
            has_enc = bool(cfg.get("server_side_encryption_configuration"))
            if not has_enc:
                for se in s3_encs:
                    b_ref = str(ctx.resolve(se["config"].get("bucket", "")))
                    if name in b_ref:
                        has_enc = True
                        break

            if not has_enc:
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="s3_bucket",
                        check_id="S3-04",
                        title="Terraform S3 bucket does not configure default encryption",
                        severity="Medium",
                        criticality="medium",
                        detail=f"{filename}: aws_s3_bucket.{name} missing server_side_encryption_configuration",
                        category="Storage",
                        remediation="Configure server_side_encryption_configuration with SSE-S3 or SSE-KMS.",
                    )
                )

    # -------------------------------------------------------------------------
    # 2. Security Groups & Standalone Rules (NET-01, NET-02, NET-04)
    # -------------------------------------------------------------------------
    def _check_ingress_rule(rule_dict: dict[str, Any], target_name: str, src_file: str) -> None:
        cidrs = ctx.resolve(rule_dict.get("cidr_blocks", []))
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        elif not isinstance(cidrs, list):
            cidrs = []

        # Check if internet 0.0.0.0/0 is exposed
        has_internet = any("0.0.0.0/0" in str(ctx.resolve(c)) for c in cidrs)
        if not has_internet:
            return

        from_p = rule_dict.get("from_port")
        to_p = rule_dict.get("to_port")
        proto = str(rule_dict.get("protocol", "")).lower()

        # SSH (22)
        if from_p == 22 or to_p == 22:
            findings.append(
                Finding(
                    resource=target_name,
                    resource_type="security_group",
                    check_id="NET-01",
                    title="Terraform security group opens SSH (port 22) to the internet",
                    severity="High",
                    criticality="high",
                    detail=f"{src_file}: security group '{target_name}' allows ingress 0.0.0.0/0 on port 22",
                    category="Network",
                    remediation="Restrict cidr_blocks to specific IP ranges or use AWS SSM Session Manager.",
                )
            )

        # RDP (3389)
        if from_p == 3389 or to_p == 3389:
            findings.append(
                Finding(
                    resource=target_name,
                    resource_type="security_group",
                    check_id="NET-02",
                    title="Terraform security group opens RDP (port 3389) to the internet",
                    severity="Critical",
                    criticality="high",
                    detail=f"{src_file}: security group '{target_name}' allows ingress 0.0.0.0/0 on port 3389",
                    category="Network",
                    remediation="Remove 0.0.0.0/0 from RDP rules and restrict to VPN or bastion CIDRs.",
                )
            )

        # All traffic
        if proto == "-1" or (from_p == 0 and to_p == 0):
            findings.append(
                Finding(
                    resource=target_name,
                    resource_type="security_group",
                    check_id="NET-04",
                    title="Terraform security group allows all traffic from 0.0.0.0/0",
                    severity="Critical",
                    criticality="high",
                    detail=f"{src_file}: security group '{target_name}' allows all protocols/ports to internet",
                    category="Network",
                    remediation="Scope ingress rules to only explicit required application ports.",
                )
            )

    # Direct inline ingress rules on aws_security_group
    for r in ctx.resources:
        if r["type"] == "aws_security_group":
            cfg = r["config"]
            ingress_list = cfg.get("ingress", [])
            if isinstance(ingress_list, dict):
                ingress_list = [ingress_list]
            for ing in ingress_list:
                if isinstance(ing, dict):
                    _check_ingress_rule(ing, r["name"], r["filename"])

    # Standalone aws_security_group_rule resources
    for sgr in sg_rules:
        cfg = sgr["config"]
        rule_type = str(cfg.get("type", "")).lower()
        if rule_type == "ingress":
            sg_ref = str(cfg.get("security_group_id", ""))
            # Extract target SG name from reference like aws_security_group.multi_web_sg.id
            matched_sg = sgr["name"]
            for sg_name in sg_map:
                if sg_name in sg_ref:
                    matched_sg = sg_name
                    break
            _check_ingress_rule(cfg, matched_sg, sgr["filename"])

    # -------------------------------------------------------------------------
    # 3. IAM Policies (IAM-01)
    # -------------------------------------------------------------------------
    for r in ctx.resources:
        if r["type"] in ("aws_iam_policy", "aws_iam_role_policy"):
            cfg = r["config"]
            name = r["name"]
            filename = r["filename"]
            raw_policy = cfg.get("policy", "")

            # If jsonencode or raw JSON
            pol_str = str(raw_policy)
            has_action_wildcard = bool(re.search(r'["\']?Action["\']?\s*[:=]\s*["\']?\*["\']?', pol_str, re.I))
            has_resource_wildcard = bool(re.search(r'["\']?Resource["\']?\s*[:=]\s*["\']?\*["\']?', pol_str, re.I))
            if has_action_wildcard and has_resource_wildcard:
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="iam_policy",
                        check_id="IAM-01",
                        title="Terraform IAM policy grants full administrator wildcard access (* on *)",
                        severity="Critical",
                        criticality="high",
                        detail=f"{filename}: {r['type']}.{name} policy contains Action: * on Resource: *",
                        category="IAM",
                        remediation="Replace wildcard statements with least-privilege action and resource ARNs.",
                    )
                )

    # -------------------------------------------------------------------------
    # 4. EC2 Instances (EC2-01)
    # -------------------------------------------------------------------------
    for r in ctx.resources:
        if r["type"] == "aws_instance":
            cfg = r["config"]
            name = r["name"]
            filename = r["filename"]

            meta_opts = cfg.get("metadata_options", [])
            if isinstance(meta_opts, dict):
                meta_opts = [meta_opts]

            http_tokens = None
            if meta_opts and isinstance(meta_opts, list) and isinstance(meta_opts[0], dict):
                http_tokens = meta_opts[0].get("http_tokens")

            if not http_tokens or http_tokens != "required":
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="ec2_instance",
                        check_id="EC2-01",
                        title="Terraform EC2 instance does not enforce IMDSv2",
                        severity="High",
                        criticality="medium",
                        detail=f"{filename}: aws_instance.{name} metadata_options missing http_tokens = 'required'",
                        category="Compute",
                        remediation="Add metadata_options { http_tokens = 'required' } to enforce IMDSv2.",
                    )
                )

    return findings


def scan_terraform_text(text: str, filename: str = "main.tf") -> list[Finding]:
    """Inspect Terraform HCL or Terraform JSON text and return normalized findings."""
    if not text or not text.strip():
        return []

    # Check if input is Terraform JSON format
    is_json = filename.lower().endswith(".json") or text.strip().startswith("{")
    if is_json:
        try:
            data = json.loads(text)
            return _scan_terraform_json(data, filename)
        except Exception:
            pass

    # Try AST parsing first
    ast_data = parse_hcl_ast(text)
    if ast_data and ("resource" in ast_data or "variable" in ast_data or "locals" in ast_data):
        ctx = TerraformContext()
        _populate_context_from_ast(ctx, ast_data, filename)
        ast_findings = _evaluate_context(ctx)
        if ast_findings:
            return ast_findings

    # Fallback to deterministic regex-based block parsing
    blocks = parse_hcl_blocks(text)
    findings: list[Finding] = []

    for b in blocks:
        if b["type"] == "aws_s3_bucket":
            body = b["body"]
            name = b["name"]
            if re.search(r'acl\s*=\s*"(public-read|public-read-write)"', body, re.I):
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="s3_bucket",
                        check_id="S3-01",
                        title="Terraform S3 bucket configured with public-read ACL",
                        severity="Critical",
                        criticality="high",
                        detail=f"{filename}: aws_s3_bucket.{name} sets public ACL",
                        category="Storage",
                        remediation="Set acl = 'private' and attach an aws_s3_bucket_public_access_block resource.",
                    )
                )
            if "server_side_encryption_configuration" not in body and "sse_algorithm" not in body:
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="s3_bucket",
                        check_id="S3-04",
                        title="Terraform S3 bucket does not configure default encryption",
                        severity="Medium",
                        criticality="medium",
                        detail=f"{filename}: aws_s3_bucket.{name} missing server_side_encryption_configuration",
                        category="Storage",
                        remediation="Configure server_side_encryption_configuration with SSE-S3 or SSE-KMS.",
                    )
                )

    for b in blocks:
        if b["type"] == "aws_security_group":
            body = b["body"]
            name = b["name"]
            if re.search(r'cidr_blocks\s*=\s*\[.*"0\.0\.0\.0/0".*\]', body):
                if re.search(r'from_port\s*=\s*22\b', body) or re.search(r'to_port\s*=\s*22\b', body):
                    findings.append(
                        Finding(
                            resource=name,
                            resource_type="security_group",
                            check_id="NET-01",
                            title="Terraform security group opens SSH (port 22) to the internet",
                            severity="High",
                            criticality="high",
                            detail=f"{filename}: aws_security_group.{name} allows ingress 0.0.0.0/0 on port 22",
                            category="Network",
                            remediation="Restrict cidr_blocks to specific IP ranges or use AWS SSM Session Manager.",
                        )
                    )
                if re.search(r'from_port\s*=\s*3389\b', body) or re.search(r'to_port\s*=\s*3389\b', body):
                    findings.append(
                        Finding(
                            resource=name,
                            resource_type="security_group",
                            check_id="NET-02",
                            title="Terraform security group opens RDP (port 3389) to the internet",
                            severity="Critical",
                            criticality="high",
                            detail=f"{filename}: aws_security_group.{name} allows ingress 0.0.0.0/0 on port 3389",
                            category="Network",
                            remediation="Remove 0.0.0.0/0 from RDP rules and restrict to VPN or bastion CIDRs.",
                        )
                    )
                if re.search(r'protocol\s*=\s*"-1"', body) or (
                    re.search(r'from_port\s*=\s*0\b', body) and re.search(r'to_port\s*=\s*0\b', body)
                ):
                    findings.append(
                        Finding(
                            resource=name,
                            resource_type="security_group",
                            check_id="NET-04",
                            title="Terraform security group allows all traffic from 0.0.0.0/0",
                            severity="Critical",
                            criticality="high",
                            detail=f"{filename}: aws_security_group.{name} allows all protocols/ports to internet",
                            category="Network",
                            remediation="Scope ingress rules to only explicit required application ports.",
                        )
                    )

    for b in blocks:
        if b["type"] in ("aws_iam_policy", "aws_iam_role_policy"):
            body = b["body"]
            name = b["name"]
            has_action_wildcard = bool(re.search(r'["\']?Action["\']?\s*[:=]\s*["\']?\*["\']?', body, re.I))
            has_resource_wildcard = bool(re.search(r'["\']?Resource["\']?\s*[:=]\s*["\']?\*["\']?', body, re.I))
            if has_action_wildcard and has_resource_wildcard:
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="iam_policy",
                        check_id="IAM-01",
                        title="Terraform IAM policy grants full administrator wildcard access (* on *)",
                        severity="Critical",
                        criticality="high",
                        detail=f"{filename}: {b['type']}.{name} policy document contains Action: * on Resource: *",
                        category="IAM",
                        remediation="Replace wildcard statements with least-privilege action and resource ARNs.",
                    )
                )

    for b in blocks:
        if b["type"] == "aws_instance":
            body = b["body"]
            name = b["name"]
            if "http_tokens" not in body or re.search(r'http_tokens\s*=\s*"optional"', body):
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="ec2_instance",
                        check_id="EC2-01",
                        title="Terraform EC2 instance does not enforce IMDSv2",
                        severity="High",
                        criticality="medium",
                        detail=f"{filename}: aws_instance.{name} metadata_options missing http_tokens = 'required'",
                        category="Compute",
                        remediation="Add metadata_options { http_tokens = 'required' } to enforce IMDSv2.",
                    )
                )

    return findings


def _scan_terraform_json(data: dict, filename: str) -> list[Finding]:
    """Scan Terraform plan JSON or configuration JSON format."""
    findings: list[Finding] = []
    res_dict = data.get("resource", {})
    if not isinstance(res_dict, dict):
        return findings

    # S3
    for name, config in res_dict.get("aws_s3_bucket", {}).items():
        if isinstance(config, dict) and config.get("acl") in ("public-read", "public-read-write"):
            findings.append(
                Finding(
                    resource=name,
                    resource_type="s3_bucket",
                    check_id="S3-01",
                    title="Terraform JSON S3 bucket configured with public-read ACL",
                    severity="Critical",
                    criticality="high",
                    detail=f"{filename}: aws_s3_bucket.{name} sets public ACL",
                    category="Storage",
                    remediation="Set acl = 'private'.",
                )
            )

    # Security Groups
    for name, config in res_dict.get("aws_security_group", {}).items():
        if isinstance(config, dict):
            for ing in config.get("ingress", []):
                if isinstance(ing, dict) and "0.0.0.0/0" in ing.get("cidr_blocks", []):
                    if ing.get("from_port") == 22 or ing.get("to_port") == 22:
                        findings.append(
                            Finding(
                                resource=name,
                                resource_type="security_group",
                                check_id="NET-01",
                                title="Terraform JSON security group opens SSH (port 22) to internet",
                                severity="High",
                                criticality="high",
                                detail=f"{filename}: aws_security_group.{name} allows port 22",
                                category="Network",
                                remediation="Restrict cidr_blocks to authorized networks.",
                            )
                        )

    return findings


def scan_terraform_file(path: str | Path) -> list[Finding]:
    """Read a single local Terraform file and return normalized findings."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Terraform file not found: {path}")
    text = p.read_text(encoding="utf-8")
    return scan_terraform_text(text, filename=p.name)


def scan_terraform_directory(dir_path: str | Path) -> list[Finding]:
    """Scan all .tf and .tf.json files in a directory, resolving cross-file variables and rules."""
    p = Path(dir_path)
    if not p.is_dir():
        raise NotADirectoryError(f"Directory not found: {dir_path}")

    tf_files = sorted(list(p.glob("*.tf")) + list(p.glob("*.tf.json")))
    if not tf_files:
        return []

    ctx = TerraformContext()
    for f in tf_files:
        text = f.read_text(encoding="utf-8")
        if f.suffix.lower() == ".json":
            try:
                data = json.loads(text)
                _populate_context_from_ast(ctx, data, f.name)
            except Exception:
                pass
        else:
            ast_data = parse_hcl_ast(text)
            if ast_data:
                _populate_context_from_ast(ctx, ast_data, f.name)
            else:
                # Regex fallback for this file
                blocks = parse_hcl_blocks(text)
                for b in blocks:
                    ctx.add_resource(b["type"], b["name"], {"_raw_body": b["body"]}, f.name)

    findings = _evaluate_context(ctx)

    # If AST produced findings, deduplicate and return
    dedup: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.check_id, f.resource)
        if key not in dedup:
            dedup[key] = f
    return list(dedup.values())


def scan_terraform_path(path: str | Path) -> list[Finding]:
    """Inspect a Terraform file or directory, returning normalized security findings."""
    p = Path(path)
    if p.is_dir():
        return scan_terraform_directory(p)
    return scan_terraform_file(p)
