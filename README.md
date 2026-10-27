# AI-Driven Cloud Security Posture Management (AI-CSPM)

An enterprise-grade, explainable Cloud Security Posture Management (CSPM) platform that evaluates multi-cloud configurations and Infrastructure-as-Code (Terraform AST & multi-file projects), maps exposures directly to the MITRE ATT&CK Matrix, fuses real-world Cyber Threat Intelligence (CTI), reconstructs multi-stage attack paths with graph topology, audits compliance against CIS and NIST frameworks, and dispatches real-time webhook alerts to Slack and Microsoft Teams.

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │               Multi-Source Cloud Configuration              │
                    │   JSON / YAML Configs   |   Terraform HCL AST (.tf / .tf.json)
                    │   Read-Only Live Connectors: AWS (boto3), Azure, GCP (ADC)  │
                    └──────────────────────────────┬──────────────────────────────┘
                                                   │
                                                   ▼
                    ┌─────────────────────────────────────────────────────────────┐
                    │                  Deterministic Rule Engine                  │
                    │   22 Core Rules (IAM, S3, EC2, Network, Logging, IMDSv2)    │
                    │   Azure Rules (Storage, NSG, Role) | GCP Rules (GCS, FW)    │
                    │   Input Hardening | Deduplication | Error Isolation         │
                    └──────────────────────────────┬──────────────────────────────┘
                                                   │
                ┌──────────────────────────────────┴──────────────────────────────────┐
                ▼                                                                     ▼
┌───────────────────────────────┐                                     ┌───────────────────────────────┐
│       Graph Attack-Path       │                                     │     Threat Intelligence       │
│        Analysis Engine        │                                     │         Fusion Engine         │
│  Topology / Identity / Assets │                                     │  Keyword & LLM (Gemini/Claude)│
│  NetworkX Exploit Chaining    │                                     │  Prompt-Injection Defense     │
│  Chained Risk Scoring         │                                     │  ATT&CK v14 Catalog Validation│
└───────────────┬───────────────┘                                     └───────────────┬───────────────┘
                │                                                                     │
                └──────────────────────────────────┬──────────────────────────────────┘
                                                   │
                                                   ▼
                    ┌─────────────────────────────────────────────────────────────┐
                    │               Unified Risk Scoring & Explainability         │
                    │   Risk = Severity × AssetCriticality × (1 + CTI Weight)     │
                    │   Plain-English Technical Explanations & Evidence           │
                    │   CIS AWS v1.4.0 & NIST SP 800-53 Compliance Auditing       │
                    └──────────────────────────────┬──────────────────────────────┘
                                                   │
                ┌──────────────────────────────────┴──────────────────────────────────┐
                ▼                                                                     ▼
┌───────────────────────────────┐                                     ┌───────────────────────────────┐
│     Real-Time Alert Engine    │                                     │    Secure Flask Web App & UI  │
│  Slack Block Kit Alerting     │                                     │  Framer-Inspired SaaS UI      │
│  Microsoft Teams MessageCard  │                                     │  Role-Based Auth (scrypt)     │
│  Generic JSON Webhook         │                                     │  Kill-Chain Graph Flowchart   │
│  Secret Redaction & Dedup     │                                     │  Compliance Matrices & SQLite │
└───────────────────────────────┘                                     └───────────────────────────────┘
```

---

## Core Capabilities

### 1. Terraform AST Parser & Multi-File Engine
- **AST Parsing**: Parses Terraform HCL into an Abstract Syntax Tree using `python-hcl2` with deterministic regex fallback.
- **Cross-File Resolution**: Resolves cross-file variables (`var.<name>`) and local values (`local.<name>`) across distributed configuration files.
- **Resource Correlation**: Accurately links standalone resources (e.g. `aws_security_group_rule` or `aws_s3_bucket_public_access_block`) defined in separate files to their parent resources.
- **Directory Scanning**: Scans single files or entire directory trees (`python run.py terraform <PATH>`).

### 2. Multi-Cloud Live Connectors (AWS, Azure, GCP)
- **Safe Read-Only**: All cloud collectors use strictly read-only API calls. Never requests `write`, `delete`, or `modify` permissions.
- **Standard Authentication**:
  - **AWS**: Standard profile and credential chain via `boto3`.
  - **Azure**: `DefaultAzureCredential` via `azure-identity` (Managed Identity, Azure CLI `az login`, or Service Principal).
  - **GCP**: Application Default Credentials (ADC) via `google.auth.default()`.
- **Zero Hardcoded Secrets**: Secrets are never pasted into source code. If credentials are missing, returns clear actionable errors without breaking offline scanning.
- **Offline Simulation Fixtures**: Local demonstration fixtures provided in `data/cloud_samples/` labeled explicitly as `offline_fixture` (never claiming live scan results).

### 3. Real-Time Webhook Alerting
- **Multi-Platform Support**: Configurable Slack, Microsoft Teams, and Generic Webhook endpoints.
- **Sensitive Data Redaction**: Automatically scrubs AWS access keys, private keys, authorization tokens, passwords, and client secrets from alert payloads.
- **Alert Deduplication**: In-memory caching prevents alert fatigue by suppressing duplicate notifications within a configurable TTL window.
- **Test CLI**: Test your webhook configuration instantly with `python run.py webhook-test`.

### 4. Graph Attack-Path Analysis Engine
- **NetworkX Topology Graph**: Chains multi-stage exploits (e.g. Public Network Ingress $\rightarrow$ EC2 IMDSv1 Credential Theft $\rightarrow$ Target Asset Compromise).
- **Interactive Visualization**: Kill-chain sequence flowchart, risk factors, and actionable remediation rendered in the dashboard.

### 5. Compliance Framework Audits
- **CIS AWS Foundations Benchmark v1.4.0** & **NIST SP 800-53 Rev 5**.
- Explicitly separates **Passed**, **Failed**, and **Unassessed** controls with rule coverage disclaimers.

---

## Quick Start

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/boopathi-7546/ai-cspm.git
cd ai-cspm

# Create and activate virtual environment
# Windows (PowerShell):
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Test Suite
```bash
# Run all tests (including AST, mock cloud connectors, and alerts)
pytest -q
# Output: 124 passed in ~12s (100% pass rate)

# Run only unit/mock tests (excluding live cloud integrations)
pytest -m mock
```

### 3. Run Demo Scan
```bash
python run.py demo
```

### 4. Start Web Dashboard
```bash
python run.py dashboard
# Open http://127.0.0.1:5000 in your browser
```

---

## CLI Commands Reference

| Command | Description |
|---|---|
| `python run.py demo` | Runs end-to-end extraction, scans 4 canonical sample environments, evaluates rankings. |
| `python run.py scan [CONFIG ...]` | Scans specific JSON, YAML, or directory configurations (e.g. `data/cloud_samples/`). |
| `python run.py terraform <PATH>` | Statically scans Terraform file or multi-file directory with AST parser. |
| `python run.py attack-paths [CONFIG ...]` | Analyzes graph topology and triggers webhook alerts for critical paths. |
| `python run.py compliance [--run-id ID]` | Generates CIS AWS Foundations Benchmark and NIST SP 800-53 compliance audits. |
| `python run.py evaluate [--compare]` | Runs evaluation metrics against ground truth (with optional side-by-side LLM comparison). |
| `python run.py webhook-test [--type all]` | Tests configured Slack/Teams/Generic webhook with sample alert payload. |
| `python run.py aws-scan [--region R]` | Read-only live AWS inspection (requires AWS credentials; opt-in only). |
| `python run.py azure-scan [--subscription-id ID]` | Read-only live Azure inspection via Azure SDK (requires Azure login; opt-in only). |
| `python run.py gcp-scan [--project-id PROJECT]` | Read-only live GCP inspection via Google Cloud SDK (requires ADC; opt-in only). |
| `python run.py llm-check` | Verifies your configured LLM API key, model name, and SDK connection safely. |
| `python run.py dashboard [--host H] [--port P]` | Launches the Flask SaaS dashboard (default: `127.0.0.1:5000`). |

---

## Environment Variables (.env)

Copy `.env.example` to `.env` to configure your settings:
```bash
cp .env.example .env    # Linux / macOS
copy .env.example .env  # Windows
```

| Variable | Default | Purpose |
|---|---|---|
| `CSPM_REQUIRE_AUTH` | `false` | Set to `true` to require login for dashboard and upload endpoints. |
| `CSPM_ADMIN_USER` | `admin` | Initial administrator username. |
| `CSPM_ADMIN_PASSWORD` | *(empty)* | Initial admin password (hashed with scrypt upon creation). |
| `CSPM_SECRET_KEY` | *(random)* | Secret key for Flask session signing. |
| `CSPM_SLACK_WEBHOOK_URL` | *(empty)* | Slack Incoming Webhook URL for real-time attack path alerts. |
| `CSPM_TEAMS_WEBHOOK_URL` | *(empty)* | Microsoft Teams Incoming Webhook URL. |
| `CSPM_WEBHOOK_URL` | *(empty)* | Generic JSON Webhook URL. |
| `LLM_PROVIDER` | `anthropic` | LLM provider: `anthropic` or `gemini`. |
| `ANTHROPIC_API_KEY` | *(empty)* | API key for Anthropic Claude. |
| `GEMINI_API_KEY` | *(empty)* | API key for Google Gemini. |
| `CTI_LLM_MODEL` | `claude-sonnet-5-5` | LLM model identifier. (For Gemini, e.g. `gemini-2.0-flash`). |
| `AWS_PROFILE` | `default` | Optional AWS profile for live read-only inspection. |
| `AWS_REGION` | `us-east-1` | Target AWS region for live scanning. |
| `AZURE_SUBSCRIPTION_ID` | *(empty)* | Azure Subscription ID for live Azure inspection. |
| `GOOGLE_CLOUD_PROJECT` | *(empty)* | Google Cloud Project ID for live GCP inspection. |

---

## Testing & Mock Architecture

All cloud SDK tests and webhook tests are designed to execute completely offline during development and CI/CD without requiring real cloud credentials:
- **Mock Tests (`@pytest.mark.mock`)**: Utilize `unittest.mock` to simulate successful resource discovery, insecure configurations, permission denials (403), quota limits (429), and transient API errors.
- **Live Tests (`@pytest.mark.integration`)**: Explicitly separated and intended only for environments configured with verified read-only credentials. Live Azure/GCP scanning is not claimed to pass without valid credentials and an active cloud session.

---

## License

This project is licensed under the Apache 2.0 License.
