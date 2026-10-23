import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLE_REPORTS = FIXTURES / "cti_samples"
SAMPLE_LABELS = FIXTURES / "cti_labels_sample.json"
