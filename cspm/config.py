"""Central configuration: paths, scoring scales and priority bands."""
import os
from pathlib import Path

from .env import load_dotenv

load_dotenv()  # reads <project>/.env; real environment variables take priority

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CONFIG_DIR = DATA / "configs"
CTI_DIR = DATA / "cti_reports"
MAPPING_CSV = DATA / "mapping" / "misconfig_ttp.csv"
GROUND_TRUTH_DIR = DATA / "ground_truth"
EXTRACTED_JSON = DATA / "cti_extracted.json"
RESULTS_DIR = ROOT / "results"
DB_PATH = Path(os.getenv("CSPM_DB", ROOT / "cspm.db"))

# LLM used for CTI extraction / explanation (optional). Override with CTI_LLM_MODEL.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic").strip().lower()
LLM_MODEL = os.getenv("CTI_LLM_MODEL", "" if LLM_PROVIDER == "gemini" else "claude-sonnet-5-5").strip()

# ---- Risk fusion -----------------------------------------------------------
# Risk = Severity x AssetCriticality x (1 + CTI relevance weight)
# CTI weight is in [0, 1] (share of loaded CTI reports referencing the technique),
# so CTI evidence boosts a finding (x1 .. x2) but can never zero it out.
SEVERITY_SCORE = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2}
CRITICALITY_SCORE = {"high": 3, "medium": 2, "low": 1}
MAX_RAW_SCORE = max(SEVERITY_SCORE.values()) * max(CRITICALITY_SCORE.values()) * 2  # 60

# (minimum normalised score 0-100, label) checked top-down
PRIORITY_BANDS = [(50, "Critical"), (30, "High"), (15, "Medium"), (0, "Low")]
