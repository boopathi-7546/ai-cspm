# AI-Driven Cloud Security Posture Management (AI-CSPM)

Mini project: scan AWS configuration exports for misconfigurations, map each to a MITRE ATT&CK
technique, weight it by how often that technique appears in threat-intelligence reports, and produce an
**explainable** risk score with a dashboard.

```
AWS config (JSON/YAML) -> rule engine (18 checks) -> misconfig->ATT&CK mapping ──┐
CTI reports (.txt) -> extractor (LLM optional, validated) -> evidence index ─────┴-> risk fusion -> SQLite -> Flask API -> HTML/CSS/JS dashboard
```

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest -q                     # 36 tests
python run.py demo            # extract CTI, scan 3 sample envs, evaluate
python run.py dashboard       # http://127.0.0.1:5000  (click "Run demo scan")
```
Docker: `docker build -t ai-cspm . && docker run -p 5000:5000 ai-cspm`

Optional LLM extraction (otherwise a regex/keyword extractor is used):
```bash
cp .env.example .env   # add ANTHROPIC_API_KEY, then: export $(cat .env | xargs)
python run.py extract --llm
python run.py scan --llm-explain
```

## Project layout
```
cspm/        scanner, rules, mapping, CTI extractor, fusion, db, evaluation (pure Python, no web code)
web/app.py   Flask JSON API  (/api/runs, /api/runs/<id>, /api/cti, /api/scan, /api/scan/demo, /api/evaluation)
web/static/  index.html + style.css + app.js  (the dashboard; plain HTML/CSS/JS, no build step)
data/        sample configs, CTI reports, ATT&CK mapping CSV, ground-truth labels
tests/       36 pytest tests (rules, fusion, extractor, pipeline, web API)
```
Dashboard security notes: the page is served with a strict Content-Security-Policy, all data is inserted with
`textContent` (a resource named `<img onerror=...>` stays text), uploads are limited to 1 MB `.json/.yaml/.yml`,
YAML is parsed with `safe_load`, and nothing is written to disk from an upload. It uses Flask's development
server and has no login: run it locally or behind your own auth, do not expose it to the internet.

## Risk formula
`Risk = Severity x AssetCriticality x (1 + CTIWeight)` normalised to 0-100.
- Severity: Critical 10, High 7, Medium 4, Low 2. Asset criticality: high 3, medium 2, low 1.
- `CTIWeight` = share of loaded CTI reports that reference the mapped technique (exact or parent/child
  match, e.g. T1552 <-> T1552.001). It is a **relevance weight, not an attack probability**.
- The `(1 + w)` form means CTI boosts a finding (x1 to x2) but a technique missing from a small corpus can
  never zero out a Critical finding (a plain product would; see `tests/test_fusion.py`).
- Priority bands on the 0-100 score: >=50 Critical, >=30 High, >=15 Medium, else Low.

## Rules (data/mapping/misconfig_ttp.csv holds the ATT&CK mapping)
IAM-01..08 (admin/service wildcards, root MFA/use, console MFA, key age, unused keys, password length),
S3-01..06 (public read/write, Block Public Access, encryption, logging, versioning),
NET-01..04 (SSH, RDP, DB ports, all-traffic open to the internet). Add a rule by writing one function with
the `@rule(...)` decorator in `cspm/rules.py` and a row in the mapping CSV.

## Evaluation (`python run.py evaluate` -> results/evaluation_results.json)
Reports detection precision/recall and false-positive resource rate against hand-labelled sample configs,
CTI extraction precision/recall on a labelled subset, and baseline (severity-only) vs fused ranking.

## Results on the shipped data (`python run.py demo`)
| Measure | Value | How to read it |
|---|---|---|
| Detection precision / recall | 1.0 / 1.0 | Only shows the rules match the hand-written labels for the 3 sample configs. Not real-world accuracy. |
| CTI extraction (offline), all labelled techniques | precision 0.889, recall 0.615 | 8 reports, 26 labelled techniques. |
| CTI extraction (offline), techniques the risk score can use | precision 1.0, recall 0.588 | Parent/child IDs count as a match (as in fusion). |
| Ranking on `vulnerable_env` | top-5 overlap 4/5, mean rank change 3.25 | CTI + criticality reorders the severity-only list. |
| Findings with CTI support | 18 of 24 | S3-01, S3-03, S3-04 get no CTI boost because the offline extractor missed T1530. |

The last row is a real limitation, not a bug: reports R01 and R06 do describe theft from S3, but the offline
keyword extractor does not recognise that wording, so public-bucket findings lose their CTI boost. Run
`python run.py extract --llm` (needs `ANTHROPIC_API_KEY`; this path could not be tested without a key) and
compare. "Offline vs LLM extraction" is a good experiment for your report. The keyword map in
`cspm/cti_extractor.py` was written from ATT&CK technique names and was NOT tuned after seeing these results.

## Data provenance
- `data/cti_reports/R01..R08`: **paraphrased summaries written by the project team in their own words** from
  public reporting on AWS/cloud intrusions (SCARLETEEL x2, LLMjacking, EmeraldWhale, Codefinger, Sisense,
  Redis/SSH honeypots, Docker Swarm cryptojacking). The source URLs are in each file header. They are not
  verbatim copies; open the originals to verify facts before quoting them.
- `data/ground_truth/cti_labels.json`: ATT&CK labels written by one reader from those summaries before the
  extractor was run. Verify against the originals and have a teammate label independently; report agreement.
- `tests/fixtures/`: synthetic sample reports used only by unit tests.
- `S3-02` and `S3-06` are also mapped to T1486 (Data Encrypted for Impact) after the Codefinger report.

## Honest limitations
- The labelled set is small (8 reports, 26 labels), so the metrics are indicative only, and CTI weights are
  coarse (each report moves the weight by 0.125).
- Reports describe different incidents, not a statistical sample of attacks; the CTI weight is a relevance
  signal, not an attack probability.
- Scans static JSON/YAML exports only: no live AWS calls, no Terraform parsing, no auto-remediation.
- Rules are a CIS-inspired subset and are not mapped to specific CIS benchmark numbers; map them to your
  benchmark version before citing.
- LLM output is never trusted blindly: technique IDs must be well-formed and backed by an evidence sentence
  found in the report (or the ID must appear in the text), else they are rejected. IOCs always use regexes.
- The dashboard uses Flask's development server with no login: run it locally only.
