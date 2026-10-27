import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLE_REPORTS = FIXTURES / "cti_samples"
SAMPLE_LABELS = FIXTURES / "cti_labels_sample.json"


@pytest.fixture(autouse=True)
def _zero_test_delays(monkeypatch):
    monkeypatch.setenv("CTI_LLM_DELAY_SECONDS", "0")
    monkeypatch.setenv("CSPM_RETRY_BACKOFF", "0.0001")
    monkeypatch.setenv("CSPM_REQUIRE_AUTH", "false")
    monkeypatch.setenv("CSPM_ADMIN_USER", "admin")
    monkeypatch.setenv("CSPM_ADMIN_PASSWORD", "admin123")

