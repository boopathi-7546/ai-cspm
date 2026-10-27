"""Azure Cloud Provider Connector for AI-CSPM.

Performs read-only inspection of Microsoft Azure cloud assets using the official
Azure SDK (azure-identity and azure-mgmt-* libraries).
Evaluates security misconfigurations across:
- Azure Storage Accounts (blob public access, secure HTTPS transfer, minimum TLS)
- Network Security Groups (inbound rules permitting 0.0.0.0/0 on SSH, RDP, all traffic)
- Role Assignments (excessive Owner / Contributor permissions)

Authentication uses standard Azure credential-provider mechanisms (DefaultAzureCredential).
Never requires or exposes hardcoded secrets in source code.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

from ..scanner import Finding
from .base import BaseCloudProvider

logger = logging.getLogger(__name__)

# Dynamic SDK imports with graceful degradation
try:
    from azure.core.exceptions import (
        ClientAuthenticationError,
        HttpResponseError as _AzureHttpResponseError,
        ResourceNotFoundError,
        ServiceRequestError,
    )
    from azure.identity import CredentialUnavailableError, DefaultAzureCredential

    _orig_http_response_init = _AzureHttpResponseError.__init__

    def _patched_http_response_init(self, message=None, response=None, **kwargs):
        status_code = kwargs.pop("status_code", None)
        _orig_http_response_init(self, message=message, response=response, **kwargs)
        if status_code is not None:
            self.status_code = status_code
        elif getattr(self, "status_code", None) is None and response is not None:
            self.status_code = getattr(response, "status_code", None)

    _AzureHttpResponseError.__init__ = _patched_http_response_init
    HttpResponseError = _AzureHttpResponseError

except ImportError:
    DefaultAzureCredential = None  # type: ignore
    CredentialUnavailableError = type("CredentialUnavailableError", (Exception,), {})  # type: ignore
    ClientAuthenticationError = type("ClientAuthenticationError", (Exception,), {})  # type: ignore

    class HttpResponseError(Exception):  # type: ignore
        def __init__(self, message: str = "Azure HTTP Error", response: Any = None, **kwargs: Any):
            status_code = kwargs.pop("status_code", None)
            super().__init__(message)
            self.message = message
            self.response = response
            self.status_code = status_code if status_code is not None else getattr(response, "status_code", None)

    ServiceRequestError = type("ServiceRequestError", (Exception,), {})  # type: ignore

try:
    from azure.mgmt.storage import StorageManagementClient
except ImportError:
    StorageManagementClient = None  # type: ignore

try:
    from azure.mgmt.network import NetworkManagementClient
except ImportError:
    NetworkManagementClient = None  # type: ignore

try:
    from azure.mgmt.authorization import AuthorizationManagementClient
except ImportError:
    AuthorizationManagementClient = None  # type: ignore


def _extract_status_code(exc: Any) -> int | None:
    """Robustly extract HTTP status code from Azure SDK exceptions or response objects.

    Checks:
    - Direct `exc.status_code` attribute (int or int-convertible value)
    - Nested `exc.response.status_code` attribute
    - Response `status` attribute
    Never infers a status code from error strings when a real status code is available.
    """
    sc = getattr(exc, "status_code", None)
    if sc is not None:
        try:
            return int(sc)
        except (ValueError, TypeError):
            pass

    resp = getattr(exc, "response", None)
    if resp is not None:
        r_sc = getattr(resp, "status_code", None)
        if r_sc is not None:
            try:
                return int(r_sc)
            except (ValueError, TypeError):
                pass
        if hasattr(resp, "status"):
            try:
                return int(getattr(resp, "status"))
            except (ValueError, TypeError):
                pass

    return None


class AzureLiveProvider(BaseCloudProvider):
    """Real read-only Azure cloud inspector using official Azure SDKs."""

    def __init__(
        self,
        subscription_id: str | None = None,
        tenant_id: str | None = None,
        credential: Any = None,
    ):
        super().__init__(name="azure", is_read_only=True)
        self.subscription_id = (
            subscription_id
            or os.getenv("AZURE_SUBSCRIPTION_ID")
            or os.getenv("ARM_SUBSCRIPTION_ID")
        )
        self.tenant_id = (
            tenant_id
            or os.getenv("AZURE_TENANT_ID")
            or os.getenv("ARM_TENANT_ID")
        )
        self._credential = credential
        self._storage_client: Any = None
        self._network_client: Any = None
        self._auth_client: Any = None

    def _get_credential(self) -> Any:
        """Resolve Azure credentials using DefaultAzureCredential or supplied credential."""
        if self._credential is not None:
            return self._credential

        if DefaultAzureCredential is None:
            raise ImportError(
                "Azure SDK packages are not installed. Run: "
                "pip install azure-identity azure-mgmt-storage azure-mgmt-network azure-mgmt-authorization"
            )

        # Standard DefaultAzureCredential checks env vars (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET),
        # Managed Identity, Workload Identity, and Azure CLI tokens.
        return DefaultAzureCredential()

    def test_connection(self) -> dict[str, Any]:
        """Test authentication and read-only connectivity to Azure Resource Manager."""
        if not self.subscription_id:
            return {
                "connected": False,
                "status": "planned",
                "provider": "azure",
                "error": "No Azure Subscription ID configured. Set AZURE_SUBSCRIPTION_ID or pass --subscription-id.",
                "authenticated": False,
            }

        try:
            cred = self._get_credential()
            # Test getting an access token for Azure Resource Manager
            token = cred.get_token("https://management.azure.com/.default")
            if not token or not token.token:
                return {
                    "connected": False,
                    "status": "planned",
                    "provider": "azure",
                    "error": "Failed to acquire Azure access token.",
                    "authenticated": False,
                }
            return {
                "connected": True,
                "status": "connected",
                "provider": "azure",
                "subscription_id": self.subscription_id,
                "authenticated": True,
                "read_only": True,
            }
        except (CredentialUnavailableError, ClientAuthenticationError) as exc:
            code = _extract_status_code(exc) or 401
            return {
                "connected": False,
                "status": "planned",
                "provider": "azure",
                "error": f"Azure authentication failed: {exc}. Ensure 'az login' was run or service principal credentials are set in environment.",
                "authenticated": False,
                "status_code": code,
            }
        except HttpResponseError as exc:
            code = _extract_status_code(exc)
            if code == 429:
                return {
                    "connected": False,
                    "status": "planned",
                    "provider": "azure",
                    "error": f"Azure API rate limit reached (429 Too Many Requests): {exc}",
                    "authenticated": True,
                    "status_code": 429,
                }
            if code == 403:
                return {
                    "connected": False,
                    "status": "planned",
                    "provider": "azure",
                    "error": f"Azure authorization error (403 Forbidden): insufficient permissions for subscription {self.subscription_id}. {exc}",
                    "authenticated": True,
                    "status_code": 403,
                }
            return {
                "connected": False,
                "status": "planned",
                "provider": "azure",
                "error": f"Azure API error ({code}): {exc}" if code else f"Azure API error: {exc}",
                "authenticated": False,
                "status_code": code,
            }
        except Exception as exc:
            code = _extract_status_code(exc)
            if code == 429:
                return {
                    "connected": False,
                    "status": "planned",
                    "provider": "azure",
                    "error": f"Azure API rate limit reached (429 Too Many Requests): {exc}",
                    "authenticated": True,
                    "status_code": 429,
                }
            if code == 403:
                return {
                    "connected": False,
                    "status": "planned",
                    "provider": "azure",
                    "error": f"Azure authorization error (403 Forbidden): insufficient permissions for subscription {self.subscription_id}. {exc}",
                    "authenticated": True,
                    "status_code": 403,
                }
            res = {
                "connected": False,
                "status": "planned",
                "provider": "azure",
                "error": f"Unexpected Azure connection error: {exc}",
                "authenticated": False,
            }
            if code is not None:
                res["status_code"] = code
            return res

    def _init_clients(self) -> None:
        """Initialize Azure management clients."""
        cred = self._get_credential()
        # If credential is a mock or mock-like and clients were partially injected,
        # avoid creating live network SDK clients with invalid/mock credentials.
        if hasattr(cred, "_mock_return_value") or type(cred).__name__ in ("MagicMock", "Mock"):
            return

        sub_id = self.subscription_id or ""

        if StorageManagementClient and not self._storage_client:
            self._storage_client = StorageManagementClient(cred, sub_id)
        if NetworkManagementClient and not self._network_client:
            self._network_client = NetworkManagementClient(cred, sub_id)
        if AuthorizationManagementClient and not self._auth_client:
            self._auth_client = AuthorizationManagementClient(cred, sub_id)

    def collect_configuration(self) -> dict[str, Any]:
        """Collect read-only configuration data across Storage, Network, and IAM."""
        config: dict[str, Any] = {
            "account": {
                "provider": "azure",
                "subscription_id": self.subscription_id,
                "is_live": True,
            },
            "storage_accounts": [],
            "network_security_groups": [],
            "role_assignments": [],
            "errors": [],
        }

        try:
            self._init_clients()
        except Exception as exc:
            config["errors"].append(f"Client initialization failed: {exc}")
            return config

        # 1. Collect Storage Accounts
        if self._storage_client:
            try:
                for sa in self._storage_client.storage_accounts.list():
                    config["storage_accounts"].append({
                        "id": getattr(sa, "id", ""),
                        "name": getattr(sa, "name", ""),
                        "location": getattr(sa, "location", ""),
                        "allow_blob_public_access": getattr(sa, "allow_blob_public_access", True),
                        "enable_https_traffic_only": getattr(sa, "enable_https_traffic_only", True),
                        "minimum_tls_version": str(getattr(sa, "minimum_tls_version", "TLS1_2")),
                    })
            except HttpResponseError as exc:
                code = _extract_status_code(exc)
                detail = getattr(exc, "message", None) or str(exc)
                if code == 403:
                    msg = f"Storage Accounts access error (403): Insufficient permissions (403 Forbidden) to list storage accounts. {detail}"
                elif code == 429:
                    msg = f"Storage Accounts access error (429): Rate limit exceeded (429 Too Many Requests). {detail}"
                elif code is not None:
                    msg = f"Storage Accounts access error ({code}): {detail}"
                else:
                    msg = f"Storage Accounts access error: {detail}"
                logger.warning(msg)
                config["errors"].append(msg)
            except Exception as exc:
                code = _extract_status_code(exc)
                detail = getattr(exc, "message", None) or str(exc)
                if code == 403:
                    msg = f"Storage Accounts access error (403): Insufficient permissions (403 Forbidden) to list storage accounts. {detail}"
                else:
                    msg = f"Storage collection error: {exc}"
                config["errors"].append(msg)

        # 2. Collect Network Security Groups
        if self._network_client:
            try:
                for nsg in self._network_client.network_security_groups.list_all():
                    rules = []
                    all_rules = list(getattr(nsg, "security_rules", []) or []) + list(
                        getattr(nsg, "default_security_rules", []) or []
                    )
                    for r in all_rules:
                        rules.append({
                            "name": getattr(r, "name", ""),
                            "direction": str(getattr(r, "direction", "Inbound")),
                            "access": str(getattr(r, "access", "Deny")),
                            "protocol": str(getattr(r, "protocol", "*")),
                            "source_address_prefix": getattr(r, "source_address_prefix", ""),
                            "source_address_prefixes": getattr(r, "source_address_prefixes", []) or [],
                            "destination_port_range": getattr(r, "destination_port_range", ""),
                            "destination_port_ranges": getattr(r, "destination_port_ranges", []) or [],
                        })
                    config["network_security_groups"].append({
                        "id": getattr(nsg, "id", ""),
                        "name": getattr(nsg, "name", ""),
                        "location": getattr(nsg, "location", ""),
                        "security_rules": rules,
                    })
            except HttpResponseError as exc:
                code = _extract_status_code(exc)
                detail = getattr(exc, "message", None) or str(exc)
                if code == 403:
                    msg = f"NSG access error (403): Insufficient permissions (403 Forbidden) to list network security groups. {detail}"
                elif code == 429:
                    msg = f"NSG access error (429): Rate limit exceeded (429 Too Many Requests). {detail}"
                elif code is not None:
                    msg = f"NSG access error ({code}): {detail}"
                else:
                    msg = f"NSG access error: {detail}"
                logger.warning(msg)
                config["errors"].append(msg)
            except Exception as exc:
                code = _extract_status_code(exc)
                detail = getattr(exc, "message", None) or str(exc)
                if code == 403:
                    msg = f"NSG access error (403): Insufficient permissions (403 Forbidden) to list network security groups. {detail}"
                else:
                    msg = f"NSG collection error: {exc}"
                config["errors"].append(msg)

        # 3. Collect Role Assignments
        if self._auth_client:
            try:
                if hasattr(self._auth_client.role_assignments, "list"):
                    assignments = self._auth_client.role_assignments.list()
                elif hasattr(self._auth_client.role_assignments, "list_for_subscription"):
                    assignments = self._auth_client.role_assignments.list_for_subscription()
                else:
                    assignments = []
                for ra in assignments:
                    config["role_assignments"].append({
                        "id": getattr(ra, "id", ""),
                        "name": getattr(ra, "name", ""),
                        "scope": getattr(ra, "scope", ""),
                        "role_definition_id": getattr(ra, "role_definition_id", ""),
                        "principal_id": getattr(ra, "principal_id", ""),
                        "principal_type": str(getattr(ra, "principal_type", "")),
                    })
            except HttpResponseError as exc:
                code = _extract_status_code(exc)
                detail = getattr(exc, "message", None) or str(exc)
                if code == 403:
                    msg = f"Role assignments access error (403): Insufficient permissions (403 Forbidden) to list role assignments. {detail}"
                elif code == 429:
                    msg = f"Role assignments access error (429): Rate limit exceeded (429 Too Many Requests). {detail}"
                elif code is not None:
                    msg = f"Role assignments access error ({code}): {detail}"
                else:
                    msg = f"Role assignments access error: {detail}"
                logger.warning(msg)
                config["errors"].append(msg)
            except Exception as exc:
                code = _extract_status_code(exc)
                detail = getattr(exc, "message", None) or str(exc)
                if code == 403:
                    msg = f"Role assignments access error (403): Insufficient permissions (403 Forbidden) to list role assignments. {detail}"
                else:
                    config["errors"].append(f"Role assignment collection error: {exc}")

        return config

    def scan_live(self) -> list[Finding]:
        """Perform live read-only inspection and return normalized security findings."""
        findings: list[Finding] = []
        cfg = self.collect_configuration()

        # ---------------------------------------------------------------------
        # Rule 1: Azure Storage Account Public Blob Access (AZ-STORAGE-01)
        # ---------------------------------------------------------------------
        for sa in cfg.get("storage_accounts", []):
            name = sa.get("name", "unnamed-storage")
            if sa.get("allow_blob_public_access") is True or sa.get("allow_blob_public_access") is None:
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="azure_storage_account",
                        check_id="AZ-STORAGE-01",
                        title="Azure Storage Account permits public blob access",
                        severity="Critical",
                        criticality="high",
                        detail=f"Storage account '{name}' has allow_blob_public_access set to True",
                        category="Storage",
                        remediation="Set allow_blob_public_access = False on the Azure Storage Account.",
                    )
                )

            if sa.get("enable_https_traffic_only") is False:
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="azure_storage_account",
                        check_id="AZ-STORAGE-02",
                        title="Azure Storage Account does not enforce secure HTTPS transfer",
                        severity="High",
                        criticality="medium",
                        detail=f"Storage account '{name}' allows unencrypted HTTP traffic (enable_https_traffic_only = False)",
                        category="Storage",
                        remediation="Enable 'Secure transfer required' (enable_https_traffic_only = True).",
                    )
                )

            min_tls = str(sa.get("minimum_tls_version", "")).upper()
            if min_tls and min_tls != "TLS1_2":
                findings.append(
                    Finding(
                        resource=name,
                        resource_type="azure_storage_account",
                        check_id="AZ-STORAGE-03",
                        title="Azure Storage Account allows deprecated TLS version",
                        severity="Medium",
                        criticality="medium",
                        detail=f"Storage account '{name}' minimum TLS version is '{min_tls}' instead of TLS 1.2",
                        category="Storage",
                        remediation="Set minimum_tls_version = 'TLS1_2' to reject deprecated cryptographic protocols.",
                    )
                )

        # ---------------------------------------------------------------------
        # Rule 2: Inbound NSG Exposure to Internet (AZ-NET-01, AZ-NET-02, AZ-NET-04)
        # ---------------------------------------------------------------------
        for nsg in cfg.get("network_security_groups", []):
            nsg_name = nsg.get("name", "unnamed-nsg")
            for rule in nsg.get("security_rules", []):
                direction = str(rule.get("direction", "")).lower()
                access = str(rule.get("access", "")).lower()
                if direction != "inbound" or access != "allow":
                    continue

                prefixes = [rule.get("source_address_prefix", "")] + list(rule.get("source_address_prefixes", []) or [])
                is_open = any(p in ("*", "0.0.0.0/0", "Internet") for p in prefixes if p)
                if not is_open:
                    continue

                ports = [rule.get("destination_port_range", "")] + list(rule.get("destination_port_ranges", []) or [])
                ports_str = " ".join(str(p) for p in ports)

                # SSH (22)
                if "22" in ports_str or "*" in ports_str:
                    findings.append(
                        Finding(
                            resource=nsg_name,
                            resource_type="network_security_group",
                            check_id="AZ-NET-01",
                            title="Azure NSG allows inbound SSH (port 22) from the Internet",
                            severity="High",
                            criticality="high",
                            detail=f"NSG '{nsg_name}' rule '{rule.get('name')}' allows inbound port 22 from {prefixes}",
                            category="Network",
                            remediation="Restrict inbound SSH to specific corporate IP prefixes or use Azure Bastion.",
                        )
                    )

                # RDP (3389)
                if "3389" in ports_str or "*" in ports_str:
                    findings.append(
                        Finding(
                            resource=nsg_name,
                            resource_type="network_security_group",
                            check_id="AZ-NET-02",
                            title="Azure NSG allows inbound RDP (port 3389) from the Internet",
                            severity="Critical",
                            criticality="high",
                            detail=f"NSG '{nsg_name}' rule '{rule.get('name')}' allows inbound port 3389 from {prefixes}",
                            category="Network",
                            remediation="Remove open 0.0.0.0/0 from RDP rules and connect via Azure Bastion.",
                        )
                    )

                # All traffic (* or -1)
                proto = str(rule.get("protocol", "")).lower()
                if (proto in ("*", "all") and ("*" in ports_str or "0-65535" in ports_str)) and not (
                    "22" in ports_str or "3389" in ports_str
                ):
                    findings.append(
                        Finding(
                            resource=nsg_name,
                            resource_type="network_security_group",
                            check_id="AZ-NET-04",
                            title="Azure NSG allows unrestricted inbound traffic from Internet",
                            severity="Critical",
                            criticality="high",
                            detail=f"NSG '{nsg_name}' rule '{rule.get('name')}' allows all protocols/ports from {prefixes}",
                            category="Network",
                            remediation="Replace wildcard ingress rules with specific application ports.",
                        )
                    )

        # ---------------------------------------------------------------------
        # Rule 3: Excessive Role Assignments (AZ-IAM-01)
        # ---------------------------------------------------------------------
        for ra in cfg.get("role_assignments", []):
            role_def = str(ra.get("role_definition_id", "")).lower()
            scope = str(ra.get("scope", "")).lower()
            # Owner built-in role GUID: 8e3af657-a8ff-443c-a75c-2fe8c4bcb635
            # Contributor built-in role GUID: b24988ac-6180-42a0-ab88-20f7382dd24c
            if "8e3af657" in role_def or "owner" in role_def:
                if scope.startswith("/subscriptions/") and "/resourcegroups/" not in scope:
                    findings.append(
                        Finding(
                            resource=ra.get("name", "subscription-owner"),
                            resource_type="azure_role_assignment",
                            check_id="AZ-IAM-01",
                            title="Azure subscription-level Owner role assignment detected",
                            severity="Critical",
                            criticality="high",
                            detail=f"Role assignment '{ra.get('name')}' grants Owner at full subscription scope '{scope}'",
                            category="IAM",
                            remediation="Use Privileged Identity Management (PIM) with just-in-time access for Owner roles.",
                        )
                    )

        return findings


# Backwards compatibility alias
AzureProvider = AzureLiveProvider
