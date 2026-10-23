"""CTI extraction: MITRE ATT&CK techniques, actors and IOCs from report text.

Two interchangeable extractors produce the same output schema:
  * extract_llm      - uses an LLM, then VALIDATES the answer (ID format + evidence check)
  * extract_offline  - regex + keyword rules; needs no API key (also the fallback)

Output per report:
  {report_id, title, source, published, method, actors[], iocs{}, rejected[],
   techniques: [{id, evidence, evidence_verified}]}
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .config import CTI_DIR, EXTRACTED_JSON

TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
VALID_TID = re.compile(r"^T\d{4}(\.\d{3})?$")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|xyz|ru|info|top|cc)\b", re.I)
ACTOR_RE = re.compile(r"(?:actor|group|operators?|attacker)s?\s+(?:known as|called|named|tracked as)\s+([A-Z][\w-]+)")

# Plain-language phrases -> technique, used when a report names no T-codes.
KEYWORD_MAP: list[tuple[str, str]] = [
    ("stolen credentials", "T1078.004"),
    ("compromised credentials", "T1078.004"),
    ("valid cloud account", "T1078.004"),
    ("credential files", "T1552.001"),
    ("publicly accessible bucket", "T1530"),
    ("exposed storage bucket", "T1530"),
    ("data from cloud storage", "T1530"),
    ("public-facing application", "T1190"),
    ("exposed docker api", "T1190"),
    ("brute force", "T1110"),
    ("remote desktop port", "T1021.001"),
    ("external remote service", "T1133"),
    ("disabled cloudtrail", "T1562.008"),
    ("disable cloudtrail", "T1562.008"),
    ("deleted objects and backups", "T1485"),
    ("cryptocurrency miner", "T1496"),
    ("phishing", "T1566"),
]


# ------------------------------------------------------------ report parsing
def parse_report(path: Path) -> dict:
    raw = Path(path).read_text(encoding="utf-8")
    meta: dict[str, str] = {}
    body = raw
    first = raw.lstrip().lower()
    if first.startswith(("title:", "source:")):
        header, _, body = raw.partition("\n\n")
        for line in header.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip().lower()] = v.strip()
    return {
        "report_id": Path(path).stem,
        "title": meta.get("title", Path(path).stem),
        "source": meta.get("source", ""),
        "published": meta.get("published", ""),
        "meta_actors": [a.strip() for a in meta.get("actors", "").split(",") if a.strip()],
        "text": body.strip(),
    }


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text.replace("\n", " ")) if s.strip()]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def extract_iocs(text: str) -> dict[str, list[str]]:
    ips = sorted({i for i in IPV4_RE.findall(text)
                  if all(0 <= int(p) <= 255 for p in i.split("."))})
    sha = sorted({h.lower() for h in SHA256_RE.findall(text)})
    md5 = sorted({h.lower() for h in MD5_RE.findall(text)})
    doms = sorted({d.lower() for d in DOMAIN_RE.findall(text)})
    return {"ipv4": ips, "domains": doms, "sha256": sha, "md5": md5}


def _result(report: dict, method: str, techniques: list[dict], actors: list[str],
            iocs: dict, rejected: list[str] | None = None) -> dict:
    return {
        "report_id": report["report_id"], "title": report["title"],
        "source": report["source"], "published": report["published"],
        "method": method, "actors": actors, "iocs": iocs,
        "techniques": techniques, "rejected": rejected or [],
    }


# ---------------------------------------------------------- offline extractor
def extract_offline(report: dict, method: str = "offline") -> dict:
    text = report["text"]
    sents = _sentences(text)
    found: dict[str, str] = {}
    for s in sents:
        for tid in TID_RE.findall(s):
            found.setdefault(tid, s)
    low_sents = [(s, s.lower()) for s in sents]
    for phrase, tid in KEYWORD_MAP:
        for s, ls in low_sents:
            if phrase in ls:
                found.setdefault(tid, s)
                break
    techniques = [{"id": t, "evidence": ev, "evidence_verified": True} for t, ev in sorted(found.items())]
    actors = list(report["meta_actors"])
    for a in ACTOR_RE.findall(text):
        if a not in actors:
            actors.append(a)
    return _result(report, method, techniques, actors, extract_iocs(text))


# ------------------------------------------------------------- LLM extractor
LLM_SYSTEM = (
    "You are a cyber threat intelligence analyst. Read the report and extract the MITRE ATT&CK "
    "techniques the report actually describes, plus named threat actors and indicators of compromise. "
    "Return ONLY a JSON object, no markdown fences, with this shape: "
    '{"techniques":[{"id":"T1078.004","evidence":"<one sentence copied EXACTLY from the report>"}],'
    '"actors":["..."],"iocs":["..."]}. '
    "Never invent technique IDs. If the report only describes behaviour in plain language, map it to the "
    "closest ATT&CK technique and still quote the supporting sentence exactly."
)


def _chunks(text: str, size: int = 6000) -> list[str]:
    out, cur = [], ""
    for para in text.split("\n\n"):
        if cur and len(cur) + len(para) > size:
            out.append(cur)
            cur = ""
        cur += para + "\n\n"
    if cur.strip():
        out.append(cur)
    return out


def _parse_json(raw: str) -> dict:
    start, end = raw.find("{"), raw.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("no JSON object in LLM output")
    return json.loads(raw[start:end + 1])


def validate_llm_payload(payload: dict, text: str) -> tuple[list[dict], list[str], dict, list[str]]:
    """Never trust raw LLM output. Keep a technique only if its ID is well-formed AND
    (its evidence sentence really occurs in the report OR the ID literally appears in the text)."""
    norm_text = _norm(text)
    kept: dict[str, dict] = {}
    rejected: list[str] = []
    for t in payload.get("techniques", []):
        if not isinstance(t, dict):
            continue
        tid = str(t.get("id", "")).strip().upper()
        evidence = str(t.get("evidence", "")).strip()
        if not VALID_TID.match(tid):
            rejected.append(f"{tid or '?'}: malformed id")
            continue
        verified = bool(evidence) and _norm(evidence) in norm_text
        if not verified and tid not in text:
            rejected.append(f"{tid}: evidence not found in report")
            continue
        if tid not in kept or (verified and not kept[tid]["evidence_verified"]):
            kept[tid] = {"id": tid, "evidence": evidence, "evidence_verified": verified}
    actors = [a.strip() for a in payload.get("actors", [])
              if isinstance(a, str) and 0 < len(a.strip()) <= 60]
    iocs = extract_iocs(" ".join(str(i) for i in payload.get("iocs", [])))
    return sorted(kept.values(), key=lambda x: x["id"]), actors, iocs, rejected


def extract_llm(report: dict, client) -> dict:
    from .llm import complete
    techniques: dict[str, dict] = {}
    actors: list[str] = []
    rejected: list[str] = []
    for chunk in _chunks(report["text"]):
        payload = _parse_json(complete(client, LLM_SYSTEM, f"REPORT:\n{chunk}"))
        t, a, _, rej = validate_llm_payload(payload, chunk)
        for item in t:
            techniques.setdefault(item["id"], item)
        actors += [x for x in a if x not in actors]
        rejected += rej
    for a in report["meta_actors"]:
        if a not in actors:
            actors.append(a)
    # IOCs are always taken with regexes (deterministic, no hallucination risk)
    return _result(report, "llm", sorted(techniques.values(), key=lambda x: x["id"]),
                   actors, extract_iocs(report["text"]), rejected)


def extract_report(report: dict, client=None) -> dict:
    if client is not None:
        try:
            return extract_llm(report, client)
        except Exception as exc:  # network error, bad JSON, quota ... -> fall back safely
            res = extract_offline(report, method="offline (llm fallback)")
            res["rejected"].append(f"llm failed: {type(exc).__name__}")
            return res
    return extract_offline(report)


def extract_corpus(cti_dir: Path = CTI_DIR, client=None, out_json: Path | None = EXTRACTED_JSON) -> list[dict]:
    reports = [parse_report(p) for p in sorted(Path(cti_dir).glob("*.txt"))]
    results = [extract_report(r, client) for r in reports]
    if out_json:
        Path(out_json).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return results


def load_extracted(path: Path = EXTRACTED_JSON) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
