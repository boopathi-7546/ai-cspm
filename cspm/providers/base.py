"""Base cloud provider interface and normalized cloud resource definitions."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

from ..scanner import Finding


@dataclass
class NormalizedResource:
    provider: str  # aws, azure, gcp
    account_id: str
    region: str
    resource_type: str  # s3_bucket, security_group, iam_user, etc.
    resource_id: str
    resource_name: str
    criticality: str = "medium"
    configuration: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseCloudProvider(ABC):
    """Abstract interface for multi-cloud security assessment providers."""

    def __init__(self, name: str, is_read_only: bool = True):
        self.name = name
        self.is_read_only = is_read_only
        self.diagnostics: list[str] = []

    @abstractmethod
    def test_connection(self) -> dict[str, Any]:
        """Test API connectivity and least-privilege credentials.

        Returns:
            dict containing status, identity/account, and permissions status.
        """
        pass

    @abstractmethod
    def collect_configuration(self) -> dict[str, Any]:
        """Query live cloud APIs in read-only mode and return normalized configuration dict.

        The returned dictionary matches the standard AI-CSPM configuration schema.
        """
        pass

    @abstractmethod
    def scan_live(self) -> list[Finding]:
        """Execute read-only live cloud inspection and return normalized findings."""
        pass
