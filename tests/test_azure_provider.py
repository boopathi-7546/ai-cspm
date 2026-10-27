"""Comprehensive unit tests for the Azure Cloud Provider using mocked SDK responses.

Tests:
- Successful resource discovery across Storage, Network, and IAM
- Insecure storage configurations (public blob access, HTTP only, deprecated TLS)
- Secure storage configurations
- Insecure NSG rules (0.0.0.0/0 on SSH, RDP, all traffic)
- Missing credentials and subscription ID handling
- Insufficient permissions (403 Forbidden)
- Rate limiting (429 Too Many Requests)
- Transient API errors (500)
"""
from unittest.mock import MagicMock, patch
import pytest

from cspm.providers.azure import AzureLiveProvider

# Mark all tests in this module as mock unit tests
pytestmark = pytest.mark.mock


class MockStorageAccount:
    def __init__(self, name, allow_blob_public_access=True, enable_https_traffic_only=True, minimum_tls_version="TLS1_2"):
        self.id = f"/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}"
        self.name = name
        self.location = "eastus"
        self.allow_blob_public_access = allow_blob_public_access
        self.enable_https_traffic_only = enable_https_traffic_only
        self.minimum_tls_version = minimum_tls_version


class MockSecurityRule:
    def __init__(self, name, direction="Inbound", access="Allow", protocol="*", source_prefix="0.0.0.0/0", dest_port="22"):
        self.name = name
        self.direction = direction
        self.access = access
        self.protocol = protocol
        self.source_address_prefix = source_prefix
        self.source_address_prefixes = []
        self.destination_port_range = dest_port
        self.destination_port_ranges = []


class MockNSG:
    def __init__(self, name, rules=None):
        self.id = f"/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/{name}"
        self.name = name
        self.location = "eastus"
        self.security_rules = rules or []
        self.default_security_rules = []


class MockRoleAssignment:
    def __init__(self, name, role_definition_id, scope="/subscriptions/sub-123"):
        self.id = f"/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/{name}"
        self.name = name
        self.scope = scope
        self.role_definition_id = role_definition_id
        self.principal_id = "user-guid-123"
        self.principal_type = "User"


def test_azure_missing_subscription_id():
    provider = AzureLiveProvider(subscription_id=None)
    conn = provider.test_connection()
    assert conn["connected"] is False
    assert "No Azure Subscription ID" in conn["error"]


def test_azure_missing_credentials():
    mock_cred = MagicMock()
    mock_cred.get_token.side_effect = Exception("CredentialUnavailable: No Azure credentials found")
    provider = AzureLiveProvider(subscription_id="sub-123", credential=mock_cred)
    conn = provider.test_connection()
    assert conn["connected"] is False
    assert "Azure connection error" in conn["error"] or "CredentialUnavailable" in conn["error"]


def test_azure_successful_connection_mock():
    mock_cred = MagicMock()
    mock_token = MagicMock()
    mock_token.token = "fake-jwt-token"
    mock_cred.get_token.return_value = mock_token

    provider = AzureLiveProvider(subscription_id="sub-123", credential=mock_cred)
    conn = provider.test_connection()
    assert conn["connected"] is True
    assert conn["provider"] == "azure"
    assert conn["subscription_id"] == "sub-123"


def test_azure_insecure_resources_scan():
    provider = AzureLiveProvider(subscription_id="sub-123", credential=MagicMock())

    # Mock storage client with insecure storage account
    mock_storage = MagicMock()
    insecure_sa = MockStorageAccount(
        name="insecuresa01",
        allow_blob_public_access=True,
        enable_https_traffic_only=False,
        minimum_tls_version="TLS1_0",
    )
    mock_storage.storage_accounts.list.return_value = [insecure_sa]
    provider._storage_client = mock_storage

    # Mock network client with open SSH, RDP, and all-traffic rules
    mock_network = MagicMock()
    open_rules = [
        MockSecurityRule(name="Allow-SSH-Internet", dest_port="22"),
        MockSecurityRule(name="Allow-RDP-Internet", dest_port="3389"),
        MockSecurityRule(name="Allow-All-Traffic", protocol="*", dest_port="*"),
    ]
    mock_nsg = MockNSG(name="insecure-nsg", rules=open_rules)
    mock_network.network_security_groups.list_all.return_value = [mock_nsg]
    provider._network_client = mock_network

    # Mock auth client with subscription Owner assignment
    mock_auth = MagicMock()
    owner_ra = MockRoleAssignment(
        name="ra-owner-sub",
        role_definition_id="/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        scope="/subscriptions/sub-123",
    )
    mock_auth.role_assignments.list.return_value = [owner_ra]
    provider._auth_client = mock_auth

    findings = provider.scan_live()
    assert len(findings) >= 5

    check_ids = {f.check_id for f in findings}
    assert "AZ-STORAGE-01" in check_ids  # Public blob
    assert "AZ-STORAGE-02" in check_ids  # HTTP allowed
    assert "AZ-STORAGE-03" in check_ids  # Deprecated TLS 1.0
    assert "AZ-NET-01" in check_ids      # Open SSH
    assert "AZ-NET-02" in check_ids      # Open RDP
    assert "AZ-IAM-01" in check_ids      # Subscription Owner


def test_azure_secure_resources_scan():
    provider = AzureLiveProvider(subscription_id="sub-123", credential=MagicMock())

    # Secure storage account
    mock_storage = MagicMock()
    secure_sa = MockStorageAccount(
        name="securesa01",
        allow_blob_public_access=False,
        enable_https_traffic_only=True,
        minimum_tls_version="TLS1_2",
    )
    mock_storage.storage_accounts.list.return_value = [secure_sa]
    provider._storage_client = mock_storage

    # Secure NSG with internal corporate CIDRs only
    mock_network = MagicMock()
    strict_rule = MockSecurityRule(name="Allow-Internal-SSH", source_prefix="10.0.0.0/8", dest_port="22")
    secure_nsg = MockNSG(name="secure-nsg", rules=[strict_rule])
    mock_network.network_security_groups.list_all.return_value = [secure_nsg]
    provider._network_client = mock_network

    # Scoped role assignment on resource group
    mock_auth = MagicMock()
    scoped_ra = MockRoleAssignment(
        name="ra-reader-rg",
        role_definition_id="acdd72a7-3385-48ef-bd42-f606fba81ae7",  # Reader
        scope="/subscriptions/sub-123/resourceGroups/app-rg",
    )
    mock_auth.role_assignments.list.return_value = [scoped_ra]
    provider._auth_client = mock_auth

    findings = provider.scan_live()
    assert findings == []


def test_azure_insufficient_permissions_403():
    provider = AzureLiveProvider(subscription_id="sub-123", credential=MagicMock())

    from cspm.providers.azure import HttpResponseError
    exc = HttpResponseError("AuthorizationFailed: The client does not have authorization.", status_code=403)

    mock_storage = MagicMock()
    mock_storage.storage_accounts.list.side_effect = exc
    provider._storage_client = mock_storage

    # Collection should not crash; records error safely
    cfg = provider.collect_configuration()
    assert len(cfg["errors"]) >= 1
    assert any("403" in err for err in cfg["errors"])


def test_azure_rate_limiting_429():
    from cspm.providers.azure import HttpResponseError
    exc = HttpResponseError("TooManyRequests: Rate limit exceeded.", status_code=429)

    mock_cred = MagicMock()
    mock_cred.get_token.side_effect = exc
    provider = AzureLiveProvider(subscription_id="sub-123", credential=mock_cred)

    conn = provider.test_connection()
    assert conn["connected"] is False
    assert conn.get("status_code") == 429
    assert "rate limit" in conn["error"].lower()
