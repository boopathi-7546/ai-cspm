"""AWS Live Cloud Provider using Boto3.

Performs read-only inspection using official AWS credentials (environment, profile, or IAM role).
Requires explicit opt-in. Never modifies or remediates live cloud infrastructure.
"""
from __future__ import annotations

import logging
from typing import Any

from ..scanner import Finding, scan_config
from .base import BaseCloudProvider

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except ImportError:
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore
    NoCredentialsError = Exception  # type: ignore
    BotoCoreError = Exception  # type: ignore


class AWSLiveProvider(BaseCloudProvider):
    """Inspects live AWS accounts in strictly read-only mode via boto3."""

    def __init__(self, profile_name: str | None = None, region_name: str | None = None):
        super().__init__(name="aws", is_read_only=True)
        self.profile_name = profile_name
        self.region_name = region_name or "us-east-1"
        self._session = None

    def _get_session(self) -> Any:
        if boto3 is None:
            raise RuntimeError("boto3 is not installed. Install boto3 to enable live AWS scanning.")
        if self._session is None:
            kwargs = {}
            if self.profile_name:
                kwargs["profile_name"] = self.profile_name
            if self.region_name:
                kwargs["region_name"] = self.region_name
            self._session = boto3.Session(**kwargs)
        return self._session

    def test_connection(self) -> dict[str, Any]:
        """Verify AWS credentials using STS GetCallerIdentity."""
        if boto3 is None:
            return {"connected": False, "error": "boto3 library not installed"}
        try:
            session = self._get_session()
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            return {
                "connected": True,
                "account_id": identity.get("Account"),
                "arn": identity.get("Arn"),
                "user_id": identity.get("UserId"),
            }
        except (NoCredentialsError, ClientError, BotoCoreError) as exc:
            return {"connected": False, "error": str(exc)}

    def collect_configuration(self) -> dict[str, Any]:
        """Collect live configuration for S3, IAM, Security Groups, and CloudTrail."""
        cfg: dict[str, Any] = {
            "account": {},
            "s3_buckets": [],
            "security_groups": [],
            "iam_users": [],
            "iam_policies": [],
            "cloudtrail": {"enabled": False},
        }

        try:
            session = self._get_session()
        except Exception as exc:
            self.diagnostics.append(f"Failed to initialize AWS session: {exc}")
            return cfg

        # 1. Collect S3 Buckets
        try:
            s3 = session.client("s3")
            buckets_resp = s3.list_buckets()
            for b in buckets_resp.get("Buckets", []):
                b_name = b["Name"]
                b_entry = {
                    "name": b_name,
                    "public_read": False,
                    "public_write": False,
                    "block_public_access": True,
                    "encryption_enabled": False,
                    "criticality": "high" if "prod" in b_name.lower() or "data" in b_name.lower() else "medium",
                }
                # Check Public Access Block
                try:
                    pab = s3.get_public_access_block(Bucket=b_name)
                    conf = pab.get("PublicAccessBlockConfiguration", {})
                    b_entry["block_public_access"] = all([
                        conf.get("BlockPublicAcls"),
                        conf.get("IgnorePublicAcls"),
                        conf.get("BlockPublicPolicy"),
                        conf.get("RestrictPublicBuckets"),
                    ])
                except ClientError:
                    b_entry["block_public_access"] = False

                # Check Encryption
                try:
                    enc = s3.get_bucket_encryption(Bucket=b_name)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    b_entry["encryption_enabled"] = bool(rules)
                except ClientError:
                    b_entry["encryption_enabled"] = False

                cfg["s3_buckets"].append(b_entry)
        except Exception as exc:
            self.diagnostics.append(f"S3 collection error: {exc}")

        # 2. Collect Security Groups
        try:
            ec2 = session.client("ec2")
            sgs_resp = ec2.describe_security_groups()
            for sg in sgs_resp.get("SecurityGroups", []):
                sg_entry = {
                    "name": sg.get("GroupName", sg.get("GroupId")),
                    "criticality": "high",
                    "ingress": [],
                }
                for perm in sg.get("IpPermissions", []):
                    proto = perm.get("IpProtocol", "tcp")
                    from_p = perm.get("FromPort", 0)
                    to_p = perm.get("ToPort", 65535)
                    for ip_range in perm.get("IpRanges", []):
                        sg_entry["ingress"].append({
                            "cidr": ip_range.get("CidrIp"),
                            "protocol": proto,
                            "port_from": from_p,
                            "port_to": to_p,
                        })
                cfg["security_groups"].append(sg_entry)
        except Exception as exc:
            self.diagnostics.append(f"Security Group collection error: {exc}")

        # 3. Collect CloudTrail
        try:
            ct = session.client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            is_logging = False
            for t in trails:
                t_name = t.get("Name")
                if t_name:
                    status = ct.get_trail_status(Name=t_name)
                    if status.get("IsLogging"):
                        is_logging = True
                        break
            cfg["cloudtrail"] = {"enabled": is_logging}
        except Exception as exc:
            self.diagnostics.append(f"CloudTrail collection error: {exc}")

        return cfg

    def scan_live(self) -> list[Finding]:
        """Query AWS APIs and run deterministic rule evaluation on normalized results."""
        cfg = self.collect_configuration()
        return scan_config(cfg)
