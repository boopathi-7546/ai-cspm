#!/usr/bin/env python3
"""Command-line entry point.

  python run.py demo                       # extract CTI, scan all sample configs, evaluate
  python run.py extract [--llm]            # (re)extract CTI from data/cti_reports
  python run.py scan [CONFIG ...]          # scan configs (default: all in data/configs)
  python run.py evaluate                   # accuracy + ranking comparison -> results/
  python run.py llm-check                  # verify API key, SDK and model name
  python run.py dashboard                  # launch the Flask dashboard on http://127.0.0.1:5000
  python run.py terraform <FILE>           # static security analysis of .tf / .tf.json files
  python run.py compliance                 # CIS AWS and NIST compliance evaluation
  python run.py attack-paths [CONFIG ...]  # graph-based multi-hop attack path analysis
  python run.py aws-scan                   # opt-in live read-only AWS inspection via boto3
"""
import argparse
import json
import os
import sys
from pathlib import Path

from cspm import db, pipeline
from cspm.config import CONFIG_DIR, DB_PATH
from cspm.evaluate import run_evaluation


def print_findings(name: str, run_id: str, scored: list, top: int = 8) -> None:
    print(f"\n== {name}  (run {run_id}): {len(scored)} finding(s)")
    for s in scored[:top]:
        print(f"  #{s.fused_rank:<2} {s.risk_score:>5}  {s.priority:<8} {s.check_id:<7} {s.resource}"
              f"   [CTI {s.cti_report_count}/{s.total_reports}, baseline #{s.baseline_rank}]")
    if len(scored) > top:
        print(f"  ... {len(scored) - top} more")


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-CSPM - AI-Driven Cloud Security Posture Management")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("demo", "extract", "scan"):
        p = sub.add_parser(name)
        p.add_argument("--llm", action="store_true", help="use the Anthropic/Gemini API for CTI extraction")
        p.add_argument("--llm-explain", action="store_true", help="LLM-polish finding explanations")
        if name == "scan":
            p.add_argument("configs", nargs="*")

    eval_p = sub.add_parser("evaluate", help="run evaluation benchmarks")
    eval_p.add_argument("--compare", action="store_true", help="run side-by-side comparison of keyword vs LLM CTI extraction")
    sub.add_parser("llm-check", help="verify the LLM API key, SDK and model name (one tiny request)")

    d = sub.add_parser("dashboard", help="start the Flask web dashboard")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=5000)

    # Phase 3 & 4 Subparsers
    tf_p = sub.add_parser("terraform", help="static security scan of Terraform files or directories (.tf or .tf.json)")
    tf_p.add_argument("path", help="path to Terraform file or directory")

    comp_p = sub.add_parser("compliance", help="CIS AWS and NIST framework compliance mapping")
    comp_p.add_argument("--run-id", help="optional run ID to assess (default: latest run)")

    ap_p = sub.add_parser("attack-paths", help="graph-based multi-stage attack path analysis")
    ap_p.add_argument("configs", nargs="*", help="optional paths to config files (default: all sample configs)")

    aws_p = sub.add_parser("aws-scan", help="read-only live AWS inspection via boto3 (explicit opt-in)")
    aws_p.add_argument("--profile", help="AWS CLI profile name (optional)")
    aws_p.add_argument("--region", default="us-east-1", help="AWS region name (default: us-east-1)")

    az_p = sub.add_parser("azure-scan", help="read-only live Azure inspection via Azure SDK (explicit opt-in)")
    az_p.add_argument("--subscription-id", help="Azure Subscription ID (or set AZURE_SUBSCRIPTION_ID)")
    az_p.add_argument("--tenant-id", help="Azure Tenant ID (or set AZURE_TENANT_ID)")

    gcp_p = sub.add_parser("gcp-scan", help="read-only live GCP inspection via Google Cloud SDK (explicit opt-in)")
    gcp_p.add_argument("--project-id", help="GCP Project ID (or set GOOGLE_CLOUD_PROJECT)")

    wh_p = sub.add_parser("webhook-test", help="test configured Slack/Teams/Generic webhook with sample alert")
    wh_p.add_argument("--type", choices=["slack", "teams", "generic", "all"], default="all", help="target webhook type")

    args = ap.parse_args()

    if args.cmd == "dashboard":
        from cspm.env import load_dotenv
        load_dotenv()
        from web.app import create_app
        print(f"AI-CSPM Web Service Active:")
        print(f"  Landing Page / Dashboard: http://{args.host}:{args.port}")
        print(f"  Dedicated Login Page:     http://{args.host}:{args.port}/login")
        create_app().run(host=args.host, port=args.port, debug=False)
        return 0

    if args.cmd == "terraform":
        from cspm.terraform_scanner import scan_terraform_path
        try:
            findings = scan_terraform_path(args.path)
            print(f"\n== Terraform Static Scan: {args.path} ({len(findings)} findings)")
            for f in findings:
                print(f"  [{f.severity:<8}] {f.check_id:<7} {f.resource:<24} {f.title}")
            return 0
        except Exception as exc:
            print(f"Error scanning Terraform: {exc}")
            return 1

    if args.cmd == "compliance":
        from cspm.compliance import generate_full_compliance_report
        conn = db.connect(DB_PATH)
        runs = db.list_runs(conn)
        if not runs:
            print("No scan runs found. Run 'python run.py demo' first.")
            return 1
        target_run = args.run_id or runs[0]["run_id"]
        findings = db.load_findings(conn, target_run)
        conn.close()

        report = generate_full_compliance_report(findings)
        print(f"\n== Compliance Report for Run '{target_run}' ({len(findings)} findings)")
        for fw_key, fw_data in report["benchmarks"].items():
            s = fw_data["summary"]
            print(f"\n-- {fw_data['framework']} {fw_data['version']} --")
            print(f"  Compliance Score: {s['compliance_score_percent']}% | Rule Coverage: {s['coverage_rate_percent']}%")
            print(f"  Passed: {s['passed']} | Failed: {s['failed']} | Unassessed: {s['unassessed']} (Total {s['total_controls']})")
            if fw_data["failed_controls"]:
                print("  Failed Controls:")
                for fc in fw_data["failed_controls"][:5]:
                    print(f"    * [{fc['control_id']}] {fc['title']} ({fc.get('failing_findings_count', 1)} violations)")
        return 0

    if args.cmd == "attack-paths":
        from cspm.alerts import notify_critical_attack_paths
        from cspm.attack_path import analyze_attack_paths
        from cspm.scanner import load_config
        conn = db.connect(DB_PATH)
        cti = pipeline.get_cti()
        paths = [Path(c) for c in getattr(args, "configs", [])] or sorted(CONFIG_DIR.glob("*.json"))
        for p in paths:
            cfg = load_config(p)
            ap_results = analyze_attack_paths(cfg, cti_reports=cti)
            print(f"\n== Attack Paths: {p.stem} ({len(ap_results)} paths detected)")
            for ap_item in ap_results:
                print(f"  [{ap_item.severity:<8}] Risk {ap_item.risk_score:>5.1f} | {ap_item.title}")
                print(f"    Entry: {ap_item.entry_point} -> Target: {ap_item.target}")
                for s in ap_item.steps:
                    print(f"      * {s.from_node} --[{s.relationship}]--> {s.to_node} ({s.technique_id or 'chain'})")
            # Auto-notify configured webhooks for critical attack paths
            alert_res = notify_critical_attack_paths(ap_results, p.stem, p.stem)
            if alert_res.get("sent", 0) > 0:
                print(f"  [+] Dispatched {alert_res['sent']} webhook notification(s) for critical paths.")
        conn.close()
        return 0

    if args.cmd == "aws-scan":
        from cspm.providers.aws import AWSLiveProvider
        print(f"Starting read-only live AWS inspection (region: {args.region}, profile: {args.profile or 'default'})...")
        provider = AWSLiveProvider(profile_name=args.profile, region_name=args.region)
        conn_test = provider.test_connection()
        if not conn_test.get("connected"):
            print(f"AWS connection failed: {conn_test.get('error')}")
            return 1
        print(f"Connected to AWS Account {conn_test.get('account_id')} as {conn_test.get('arn')}")
        findings = provider.scan_live()
        print(f"Scan complete. Discovered {len(findings)} finding(s).")
        for f in findings:
            print(f"  [{f.severity:<8}] {f.check_id:<7} {f.resource:<24} {f.title}")
        return 0

    if args.cmd == "azure-scan":
        from cspm.providers.azure import AzureLiveProvider
        print(f"Starting read-only live Azure inspection (subscription: {args.subscription_id or 'from environment'})...")
        provider = AzureLiveProvider(subscription_id=args.subscription_id, tenant_id=args.tenant_id)
        conn_test = provider.test_connection()
        if not conn_test.get("connected"):
            print(f"Azure connection failed: {conn_test.get('error')}")
            return 1
        print(f"Connected to Azure Subscription {conn_test.get('subscription_id')}")
        findings = provider.scan_live()
        print(f"Scan complete. Discovered {len(findings)} finding(s).")
        for f in findings:
            print(f"  [{f.severity:<8}] {f.check_id:<14} {f.resource:<24} {f.title}")
        return 0

    if args.cmd == "gcp-scan":
        from cspm.providers.gcp import GCPLiveProvider
        print(f"Starting read-only live GCP inspection (project: {args.project_id or 'from environment'})...")
        provider = GCPLiveProvider(project_id=args.project_id)
        conn_test = provider.test_connection()
        if not conn_test.get("connected"):
            print(f"GCP connection failed: {conn_test.get('error')}")
            return 1
        print(f"Connected to GCP Project {conn_test.get('project_id')}")
        findings = provider.scan_live()
        print(f"Scan complete. Discovered {len(findings)} finding(s).")
        for f in findings:
            print(f"  [{f.severity:<8}] {f.check_id:<14} {f.resource:<24} {f.title}")
        return 0

    if args.cmd == "webhook-test":
        from cspm.alerts import notify_critical_attack_paths
        from cspm.attack_path import AttackPath, AttackStep
        print("Dispatching test alert for simulated critical attack path...")
        sample_path = AttackPath(
            path_id="ap-test-01",
            title="[TEST] Unauthenticated Cloud Compromise Simulation",
            entry_point="Internet (0.0.0.0/0)",
            target="Database Asset 'customer-vault-prod'",
            steps=[
                AttackStep("Internet (0.0.0.0/0)", "Security Group 'sg-web'", "PUBLIC_INGRESS", "Port 22 open", "T1190"),
                AttackStep("Security Group 'sg-web'", "EC2 Instance 'web-srv-01'", "HOST_COMPROMISE", "IMDSv1 enabled", "T1552.005"),
                AttackStep("EC2 Instance 'web-srv-01'", "Database Asset 'customer-vault-prod'", "DATA_EXFILTRATION", "Admin role", "T1530"),
            ],
            severity="Critical",
            criticality="high",
            risk_score=95.0,
            explanation="Adversary chains open SSH with IMDSv1 credential theft to exfiltrate database data.",
            mitigations=["Enforce IMDSv2", "Remove 0.0.0.0/0 from security groups", "Isolate the database"],
            techniques=["T1190", "T1552.005", "T1530"],
        )
        res = notify_critical_attack_paths([sample_path], run_id="test-run-001", config_name="test_environment", force=True)
        if not res.get("configured"):
            print(f"[!] {res.get('message')}")
            print("To enable, set CSPM_SLACK_WEBHOOK_URL, CSPM_TEAMS_WEBHOOK_URL, or CSPM_WEBHOOK_URL in .env.")
            return 0
        print(f"Alert test results: {res.get('sent')} sent, {len(res.get('results', []))} delivered.")
        for r in res.get("results", []):
            st = "SUCCESS" if r["result"].get("success") else f"FAILED ({r['result'].get('error')})"
            print(f"  * {r['type'].upper()} Webhook: {st}")
        return 0

    if args.cmd == "llm-check":
        from cspm.config import LLM_MODEL
        from cspm.llm import complete, get_client, get_provider
        provider = get_provider()
        model = os.getenv("CTI_LLM_MODEL", "").strip() or (LLM_MODEL if provider == "anthropic" else "")

        if provider == "gemini" and not model:
            print(f"Provider: {provider} | Model: (not set)")
            print("No model set: for Gemini, CTI_LLM_MODEL must be set (e.g. gemini-2.0-flash).")
            return 1

        client = get_client()
        if client is None:
            key_var = "GEMINI_API_KEY" if provider == "gemini" else "ANTHROPIC_API_KEY"
            pkg = "google-genai" if provider == "gemini" else "anthropic"
            print(f"Provider: {provider} | Model: {model or '(none)'}")
            print(f"No LLM client: set {key_var} (environment variable or .env file) and run "
                  f"`pip install {pkg}`. The key itself is never printed.")
            return 1

        try:
            tok = 256 if provider == "gemini" else 10
            reply = complete(client, "Reply with the single word OK.", "ping", max_tokens=tok)
        except Exception as exc:
            err_msg = str(exc)[:200]
            for key in (os.getenv("GEMINI_API_KEY"), os.getenv("ANTHROPIC_API_KEY")):
                if key and len(key) >= 6:
                    err_msg = err_msg.replace(key, "[REDACTED]")
            print(f"Provider: {provider} | Model: {model}")
            print(f"LLM call failed with model '{model}': {type(exc).__name__}: {err_msg}")
            return 1

        print(f"Provider: {provider} | Model: {model}")
        print(f"LLM OK with model '{model}': {reply.strip()[:40]!r}")
        return 0

    if args.cmd == "extract":
        cti = pipeline.get_cti(refresh=True, use_llm=args.llm)
        print(f"Extracted {sum(len(r['techniques']) for r in cti)} technique mentions from {len(cti)} reports "
              f"(method: {', '.join(sorted({r['method'] for r in cti}))})")
        return 0

    if args.cmd == "evaluate":
        if getattr(args, "compare", False):
            from cspm.evaluate import compare_extractors
            from cspm.config import CTI_DIR, GROUND_TRUTH_DIR
            labels_path = GROUND_TRUTH_DIR / "cti_labels.json"
            if not labels_path.exists():
                labels_path = Path("tests/fixtures/cti_labels_expanded.json")
            res = compare_extractors(CTI_DIR, labels_path)
            print(json.dumps(res, indent=2))
            return 0
        cti = pipeline.get_cti()
        print(json.dumps(run_evaluation(cti), indent=2))
        return 0

    conn = db.connect(DB_PATH)
    cti = pipeline.get_cti(refresh=(args.cmd == "demo"), use_llm=args.llm)
    db.save_cti(conn, cti)
    paths = [Path(c) for c in getattr(args, "configs", [])] or sorted(CONFIG_DIR.glob("*.json"))
    for p in paths:
        run_id, scored = pipeline.run_scan(p, cti, conn, use_llm_explain=args.llm_explain)
        print_findings(p.stem, run_id, scored)
    if args.cmd == "demo":
        res = run_evaluation(cti)
        d, e = res["detection"]["overall"], res["extraction"]["overall"]
        print(f"\nDetection on sample set: precision {d['precision']}, recall {d['recall']}, "
              f"FP-resource rate {res['detection']['false_positive_resource_rate']}")
        print(f"CTI extraction on labelled subset: precision {e['precision']}, recall {e['recall']}")
        print("Full results: results/evaluation_results.json   |   dashboard: python run.py dashboard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
