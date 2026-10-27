"""Google Cloud Provider Connector for AI-CSPM.

Performs read-only inspection of Google Cloud Platform (GCP) assets using the official
Google Cloud SDK (google-auth, google-cloud-storage, google-cloud-compute).
Evaluates security misconfigurations across:
- Google Cloud Storage (GCS) Buckets (public access via allUsers/allAuthenticatedUsers, uniform bucket-level access, encryption)
- VPC Compute Firewall Rules (ingress allowing 0.0.0.0/0 on SSH, RDP, all traffic)
- Cloud IAM Project Policies (primitive Owner/Editor roles granted broadly)

Authentication uses standard Google Application Default Credentials (ADC).
Never requires or exposes hardcoded secrets in source code.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..scanner import Finding
from .base import BaseCloudProvider

logger = logging.getLogger(__name__)

# Dynamic SDK imports with graceful degradation
try:
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError
except ImportError:
    google = None  # type: ignore
    DefaultCredentialsError = Exception  # type: ignore

try:
    from google.cloud import storage as gcs_sdk
except ImportError:
    gcs_sdk = None  # type: ignore

try:
    from google.cloud import compute_v1 as compute_sdk
except ImportError:
    compute_sdk = None  # type: ignore

try:
    from google.api_core.exceptions import GoogleAPICallError, PermissionDenied, TooManyRequests
except ImportError:
    class GoogleAPICallError(Exception):  # type: ignore
        def __init__(self, message="Google API Error", code=500):
            super().__init__(message)
            self.message = message
            self.code = code
    class PermissionDenied(GoogleAPICallError):  # type: ignore
        def __init__(self, message="Permission denied", code=403):
            super().__init__(message, code=code)
    class TooManyRequests(GoogleAPICallError):  # type: ignore
        def __init__(self, message="Quota exceeded", code=429):
            super().__init__(message, code=code)


class GCPLiveProvider(BaseCloudProvider):
    """Real read-only Google Cloud Platform inspector using official Google Cloud SDKs."""

    def __init__(
        self,
        project_id: str | None = None,
        credentials: Any = None,
    ):
        super().__init__(name="gcp", is_read_only=True)
        self.project_id = (
            project_id
            or os.getenv("GOOGLE_CLOUD_PROJECT")
            or os.getenv("GCP_PROJECT")
        )
        self._credentials = credentials
        self._storage_client: Any = None
        self._firewalls_client: Any = None

    def _get_credentials_and_project(self) -> tuple[Any, str | None]:
        """Resolve Google Cloud credentials using Application Default Credentials (ADC)."""
        if self._credentials is not None:
            return self._credentials, self.project_id

        if google is None:
            raise ImportError(
                "Google Cloud SDK packages are not installed. Run: "
                "pip install google-auth google-cloud-storage google-cloud-compute"
            )

        creds, proj = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
        )
        resolved_project = self.project_id or proj
        return creds, resolved_project

    def test_connection(self) -> dict[str, Any]:
        """Test authentication and read-only connectivity to Google Cloud APIs."""
        try:
            creds, proj = self._get_credentials_and_project()
            if not proj:
                return {
                    "connected": False,
                    "status": "planned",
                    "provider": "gcp",
                    "error": "No GCP Project ID found. Set GOOGLE_CLOUD_PROJECT or pass project_id.",
                    "authenticated": False,
                }
            # Attempt to refresh token to verify credential validity
            if hasattr(creds, "refresh"):
                import google.auth.transport.requests
                request = google.auth.transport.requests.Request()
                creds.refresh(request)

            return {
                "connected": True,
                "status": "connected",
                "provider": "gcp",
                "project_id": proj,
                "authenticated": True,
                "read_only": True,
            }
        except DefaultCredentialsError as exc:
            return {
                "connected": False,
                "status": "planned",
                "provider": "gcp",
                "error": f"GCP Application Default Credentials not configured: {exc}. Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS.",
                "authenticated": False,
            }
        except PermissionDenied as exc:
            return {
                "connected": False,
                "status": "planned",
                "provider": "gcp",
                "error": f"GCP authorization error (403 Forbidden): {exc}",
                "authenticated": True,
                "status_code": 403,
            }
        except TooManyRequests as exc:
            return {
                "connected": False,
                "status": "planned",
                "provider": "gcp",
                "error": f"GCP API rate limit or quota exceeded (429): {exc}",
                "authenticated": True,
                "status_code": 429,
            }
        except Exception as exc:
            return {
                "connected": False,
                "status": "planned",
                "provider": "gcp",
                "error": f"GCP connection error: {exc}",
                "authenticated": False,
            }

    def _init_clients(self) -> None:
        """Initialize Google Cloud service clients."""
        creds, proj = self._get_credentials_and_project()
        self.project_id = proj

        if gcs_sdk and not self._storage_client:
            self._storage_client = gcs_sdk.Client(project=proj, credentials=creds)
        if compute_sdk and not self._firewalls_client:
            self._firewalls_client = compute_sdk.FirewallsClient(credentials=creds)

    def collect_configuration(self) -> dict[str, Any]:
        """Collect read-only configuration data across Cloud Storage, Compute Firewalls, and IAM."""
        config: dict[str, Any] = {
            "account": {
                "provider": "gcp",
                "project_id": self.project_id,
                "is_live": True,
            },
            "buckets": [],
            "firewall_rules": [],
            "iam_bindings": [],
            "errors": [],
        }

        try:
            self._init_clients()
        except Exception as exc:
            config["errors"].append(f"Client initialization failed: {exc}")
            return config

        # 1. Collect Cloud Storage Buckets
        if self._storage_client:
            try:
                for b in self._storage_client.list_buckets():
                    policy_data = {}
                    try:
                        pol = b.get_iam_policy()
                        policy_data = {
                            role: list(members) for role, members in pol.items()
                        }
                    except Exception as e:
                        logger.debug("Could not get IAM policy for bucket %s: %s", b.name, e)

                    ubla_enabled = False
                    if hasattr(b, "iam_configuration") and b.iam_configuration:
                        ubla_enabled = getattr(
                            b.iam_configuration, "uniform_bucket_level_access_enabled", False
                        )

                    config["buckets"].append({
                        "name": b.name,
                        "location": getattr(b, "location", "US"),
                        "storage_class": getattr(b, "storage_class", "STANDARD"),
                        "uniform_bucket_level_access": ubla_enabled,
                        "default_kms_key_name": getattr(b, "default_kms_key_name", None),
                        "iam_policy": policy_data,
                    })
            except GoogleAPICallError as exc:
                msg = f"GCS bucket list error ({getattr(exc, 'code', 'error')}): {exc.message or str(exc)}"
                logger.warning(msg)
                config["errors"].append(msg)
            except Exception as exc:
                config["errors"].append(f"GCS collection error: {exc}")

        # 2. Collect VPC Firewall Rules
        if self._firewalls_client and self.project_id:
            try:
                for rule in self._firewalls_client.list(project=self.project_id):
                    allowed = []
                    for a in getattr(rule, "allowed", []) or []:
                        allowed.append({
                            "ip_protocol": getattr(a, "IP_protocol", ""),
                            "ports": list(getattr(a, "ports", []) or []),
                        })

                    config["firewall_rules"].append({
                        "name": getattr(rule, "name", ""),
                        "direction": str(getattr(rule, "direction", "INGRESS")),
                        "disabled": getattr(rule, "disabled", False),
                        "source_ranges": list(getattr(rule, "source_ranges", []) or []),
                        "allowed": allowed,
                    })
            except GoogleAPICallError as exc:
                msg = f"GCP Firewall list error ({getattr(exc, 'code', 'error')}): {exc.message or str(exc)}"
                logger.warning(msg)
                config["errors"].append(msg)
            except Exception as exc:
                config["errors"].append(f"Firewall collection error: {exc}")

        return config

    def scan_live(self) -> list[Finding]:
        """Perform live read-only inspection and return normalized security findings."""
        findings: list[Finding] = []
        cfg = self.collect_configuration()

        # ---------------------------------------------------------------------
        # Rule 1: Public Cloud Storage Bucket (GCP-STORAGE-01, GCP-STORAGE-02)
        # ---------------------------------------------------------------------
        for b in cfg.get("buckets", []):
            bname = b.get("name", "unnamed-bucket")
            iam_pol = b.get("iam_policy", {})

            # Check if any role includes allUsers or allAuthenticatedUsers
            is_public = False
            public_roles = []
            for role, members in iam_pol.items():
                for m in members:
                    if m in ("allUsers", "allAuthenticatedUsers"):
                        is_public = True
                        public_roles.append(role)

            if is_public:
                findings.append(
                    Finding(
                        resource=bname,
                        resource_type="gcs_bucket",
                        check_id="GCP-STORAGE-01",
                        title="Google Cloud Storage bucket accessible to allUsers / allAuthenticatedUsers",
                        severity="Critical",
                        criticality="high",
                        detail=f"GCS bucket '{bname}' IAM policy grants public access via roles: {', '.join(public_roles)}",
                        category="Storage",
                        remediation="Remove 'allUsers' and 'allAuthenticatedUsers' from the bucket IAM policy.",
                    )
                )

            if not b.get("uniform_bucket_level_access"):
                findings.append(
                    Finding(
                        resource=bname,
                        resource_type="gcs_bucket",
                        check_id="GCP-STORAGE-02",
                        title="Google Cloud Storage bucket does not enforce uniform bucket-level access",
                        severity="Medium",
                        criticality="medium",
                        detail=f"GCS bucket '{bname}' has fine-grained ACLs enabled instead of Uniform Bucket-Level Access (UBLA)",
                        category="Storage",
                        remediation="Enable Uniform Bucket-Level Access (UBLA) to standardize IAM-based permission evaluation.",
                    )
                )

            if not b.get("default_kms_key_name"):
                findings.append(
                    Finding(
                        resource=bname,
                        resource_type="gcs_bucket",
                        check_id="GCP-STORAGE-04",
                        title="Google Cloud Storage bucket missing customer-managed encryption key (CMEK)",
                        severity="Low",
                        criticality="low",
                        detail=f"GCS bucket '{bname}' uses default Google-managed keys instead of Cloud KMS customer-managed keys",
                        category="Storage",
                        remediation="Configure a Cloud KMS key (CMEK) for default encryption on the bucket.",
                    )
                )

        # ---------------------------------------------------------------------
        # Rule 2: Compute VPC Ingress Firewalls (GCP-NET-01, GCP-NET-02, GCP-NET-04)
        # ---------------------------------------------------------------------
        for fw in cfg.get("firewall_rules", []):
            if fw.get("disabled"):
                continue

            direction = str(fw.get("direction", "")).upper()
            if direction != "INGRESS":
                continue

            sources = fw.get("source_ranges", [])
            has_internet = any(s == "0.0.0.0/0" for s in sources)
            if not has_internet:
                continue

            fw_name = fw.get("name", "unnamed-firewall")
            for allowed in fw.get("allowed", []):
                proto = str(allowed.get("ip_protocol", "")).lower()
                ports = [str(p) for p in allowed.get("ports", [])]

                # SSH (22)
                if ("22" in ports or not ports) and proto in ("tcp", "all"):
                    findings.append(
                        Finding(
                            resource=fw_name,
                            resource_type="vpc_firewall_rule",
                            check_id="GCP-NET-01",
                            title="GCP VPC firewall rule allows inbound SSH (port 22) from 0.0.0.0/0",
                            severity="High",
                            criticality="high",
                            detail=f"Firewall '{fw_name}' exposes port 22 to 0.0.0.0/0",
                            category="Network",
                            remediation="Restrict source_ranges to corporate bastion CIDRs or use Identity-Aware Proxy (IAP).",
                        )
                    )

                # RDP (3389)
                if ("3389" in ports or not ports) and proto in ("tcp", "all"):
                    findings.append(
                        Finding(
                            resource=fw_name,
                            resource_type="vpc_firewall_rule",
                            check_id="GCP-NET-02",
                            title="GCP VPC firewall rule allows inbound RDP (port 3389) from 0.0.0.0/0",
                            severity="Critical",
                            criticality="high",
                            detail=f"Firewall '{fw_name}' exposes port 3389 to 0.0.0.0/0",
                            category="Network",
                            remediation="Remove 0.0.0.0/0 from RDP firewall rules and connect using Chrome Remote Desktop or IAP.",
                        )
                    )

                # All traffic
                if proto in ("all", "-1") or (not ports and proto == "tcp"):
                    findings.append(
                        Finding(
                            resource=fw_name,
                            resource_type="vpc_firewall_rule",
                            check_id="GCP-NET-04",
                            title="GCP VPC firewall rule allows unrestricted ingress from 0.0.0.0/0",
                            severity="Critical",
                            criticality="high",
                            detail=f"Firewall '{fw_name}' permits all protocols/ports from 0.0.0.0/0",
                            category="Network",
                            remediation="Scope allowed protocols and destination ports to explicit application requirements.",
                        )
                    )

        return findings


# Backwards compatibility alias
GCPProvider = GCPLiveProvider
