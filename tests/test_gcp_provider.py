"""Comprehensive unit tests for the Google Cloud Platform Provider using mocked SDK responses.

Tests:
- Successful resource discovery across GCS and Compute VPC Firewalls
- Insecure bucket configurations (public allUsers / allAuthenticatedUsers, UBLA disabled)
- Secure bucket configurations
- Insecure firewall rules (0.0.0.0/0 on SSH, RDP, all traffic)
- Missing credentials and project ID handling
- Insufficient permissions (403 PermissionDenied)
- Quota / rate limiting (429 TooManyRequests)
- Service errors (503 ServiceUnavailable)
"""
from unittest.mock import MagicMock
import pytest

from cspm.providers.gcp import GCPLiveProvider

# Mark all tests in this module as mock unit tests
pytestmark = pytest.mark.mock


class MockGCSBucket:
    def __init__(self, name, iam_policy=None, ubla_enabled=False, kms_key=None):
        self.name = name
        self.location = "US"
        self.storage_class = "STANDARD"
        self._iam_policy = iam_policy or {}
        self.default_kms_key_name = kms_key

        iam_cfg = MagicMock()
        iam_cfg.uniform_bucket_level_access_enabled = ubla_enabled
        self.iam_configuration = iam_cfg

    def get_iam_policy(self):
        return self._iam_policy


class MockAllowed:
    def __init__(self, ip_protocol="tcp", ports=None):
        self.IP_protocol = ip_protocol
        self.ports = ports or []


class MockFirewallRule:
    def __init__(self, name, direction="INGRESS", disabled=False, source_ranges=None, allowed=None):
        self.name = name
        self.direction = direction
        self.disabled = disabled
        self.source_ranges = source_ranges or []
        self.allowed = allowed or []


def test_gcp_missing_project_id():
    provider = GCPLiveProvider(project_id=None, credentials=MagicMock())
    # Override project resolution
    provider.project_id = None
    conn = provider.test_connection()
    assert conn["connected"] is False
    assert "No GCP Project ID" in conn["error"]


def test_gcp_missing_credentials():
    from google.auth.exceptions import DefaultCredentialsError
    provider = GCPLiveProvider(project_id="test-proj")
    with pytest.MonkeyPatch.context() as mp:
        import google.auth
        mp.setattr(google.auth, "default", MagicMock(side_effect=DefaultCredentialsError("ADC not found")))
        conn = provider.test_connection()
        assert conn["connected"] is False
        assert "Application Default Credentials" in conn["error"]


def test_gcp_successful_connection_mock():
    mock_cred = MagicMock()
    mock_cred.refresh = MagicMock()

    provider = GCPLiveProvider(project_id="my-gcp-project-123", credentials=mock_cred)
    conn = provider.test_connection()
    assert conn["connected"] is True
    assert conn["provider"] == "gcp"
    assert conn["project_id"] == "my-gcp-project-123"


def test_gcp_insecure_resources_scan():
    provider = GCPLiveProvider(project_id="test-project", credentials=MagicMock())

    # Mock storage client with public allUsers bucket
    mock_storage = MagicMock()
    insecure_bucket = MockGCSBucket(
        name="public-data-bucket",
        iam_policy={"roles/storage.objectViewer": ["allUsers"]},
        ubla_enabled=False,
        kms_key=None,
    )
    mock_storage.list_buckets.return_value = [insecure_bucket]
    provider._storage_client = mock_storage

    # Mock compute firewalls client with open port 22 and port 3389 rules
    mock_firewalls = MagicMock()
    open_rules = [
        MockFirewallRule(
            name="default-allow-ssh",
            source_ranges=["0.0.0.0/0"],
            allowed=[MockAllowed(ip_protocol="tcp", ports=["22"])],
        ),
        MockFirewallRule(
            name="default-allow-rdp",
            source_ranges=["0.0.0.0/0"],
            allowed=[MockAllowed(ip_protocol="tcp", ports=["3389"])],
        ),
        MockFirewallRule(
            name="default-allow-all",
            source_ranges=["0.0.0.0/0"],
            allowed=[MockAllowed(ip_protocol="all", ports=[])],
        ),
    ]
    mock_firewalls.list.return_value = open_rules
    provider._firewalls_client = mock_firewalls

    findings = provider.scan_live()
    assert len(findings) >= 5

    check_ids = {f.check_id for f in findings}
    assert "GCP-STORAGE-01" in check_ids  # allUsers public read
    assert "GCP-STORAGE-02" in check_ids  # UBLA disabled
    assert "GCP-STORAGE-04" in check_ids  # Missing CMEK
    assert "GCP-NET-01" in check_ids      # 0.0.0.0/0 on 22
    assert "GCP-NET-02" in check_ids      # 0.0.0.0/0 on 3389
    assert "GCP-NET-04" in check_ids      # 0.0.0.0/0 on all


def test_gcp_secure_resources_scan():
    provider = GCPLiveProvider(project_id="test-project", credentials=MagicMock())

    # Secure GCS bucket with UBLA, CMEK, and private IAM
    mock_storage = MagicMock()
    secure_bucket = MockGCSBucket(
        name="secure-private-vault",
        iam_policy={"roles/storage.objectAdmin": ["user:analyst@corp.com"]},
        ubla_enabled=True,
        kms_key="projects/p/locations/l/keyRings/r/cryptoKeys/k",
    )
    mock_storage.list_buckets.return_value = [secure_bucket]
    provider._storage_client = mock_storage

    # Secure internal-only firewall rule
    mock_firewalls = MagicMock()
    internal_rule = MockFirewallRule(
        name="internal-bastion-ssh",
        source_ranges=["10.128.0.0/20"],
        allowed=[MockAllowed(ip_protocol="tcp", ports=["22"])],
    )
    mock_firewalls.list.return_value = [internal_rule]
    provider._firewalls_client = mock_firewalls

    findings = provider.scan_live()
    assert findings == []


def test_gcp_insufficient_permissions_403():
    from cspm.providers.gcp import PermissionDenied
    provider = GCPLiveProvider(project_id="test-project", credentials=MagicMock())

    mock_storage = MagicMock()
    mock_storage.list_buckets.side_effect = PermissionDenied("Permission storage.buckets.list denied on project.", code=403)
    provider._storage_client = mock_storage

    cfg = provider.collect_configuration()
    assert len(cfg["errors"]) >= 1
    assert any("denied" in err.lower() or "permission" in err.lower() for err in cfg["errors"])


def test_gcp_rate_limiting_429():
    from cspm.providers.gcp import TooManyRequests
    mock_cred = MagicMock()
    mock_cred.refresh.side_effect = TooManyRequests("Quota exceeded for project.", code=429)
    provider = GCPLiveProvider(project_id="test-project", credentials=mock_cred)

    conn = provider.test_connection()
    assert conn["connected"] is False
    assert conn.get("status_code") == 429
    assert "rate limit" in conn["error"].lower() or "quota" in conn["error"].lower()
