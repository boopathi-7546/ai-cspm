#!/usr/bin/env python3
"""Command-line entry point.

  python run.py demo                 # extract CTI, scan all sample configs, evaluate
  python run.py extract [--llm]      # (re)extract CTI from data/cti_reports
  python run.py scan [CONFIG ...]    # scan configs (default: all in data/configs)
  python run.py evaluate             # accuracy + ranking comparison -> results/
  python run.py llm-check            # verify API key, SDK and model name
  python run.py dashboard            # launch the Flask dashboard on http://127.0.0.1:5000
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
    ap = argparse.ArgumentParser(description="AI-CSPM")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("demo", "extract", "scan"):
        p = sub.add_parser(name)
        p.add_argument("--llm", action="store_true", help="use the Anthropic API for CTI extraction")
        p.add_argument("--llm-explain", action="store_true", help="LLM-polish finding explanations")
        if name == "scan":
            p.add_argument("configs", nargs="*")
    sub.add_parser("evaluate")
    sub.add_parser("llm-check", help="verify the Anthropic API key, SDK and model name (one tiny request)")
    d = sub.add_parser("dashboard", help="start the Flask web dashboard")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    if args.cmd == "dashboard":
        from web.app import create_app
        print(f"Dashboard: http://{args.host}:{args.port}")
        create_app().run(host=args.host, port=args.port, debug=False)
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
            reply = complete(client, "Reply with the single word OK.", "ping", max_tokens=10)
        except Exception as exc:  # report the problem, never the key
            err_msg = str(exc)[:200]
            for key in (os.getenv("GEMINI_API_KEY"), os.getenv("ANTHROPIC_API_KEY")):
                if key and len(key) >= 6:
                    err_msg = err_msg.replace(key, "[REDACTED]")
            print(f"Provider: {provider} | Model: {model}")
            print(f"LLM call failed with model '{model}': {type(exc).__name__}: {err_msg}")
            print("If the model name is wrong, set CTI_LLM_MODEL to a valid model.")
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
