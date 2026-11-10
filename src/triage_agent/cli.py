"""Command-line entry point.

  python -m triage_agent.cli list
  python -m triage_agent.cli triage c06_divide_by_zero
  python -m triage_agent.cli triage c06_divide_by_zero --provider ollama:qwen2.5-coder:7b
  python -m triage_agent.cli triage c06_divide_by_zero --no-defenses --attack beacon_exfil:source_comment
"""
from __future__ import annotations

import argparse
import json
import sys

from . import casedb
from .agent import run_triage_sync
from .providers import MockProvider, build_provider


def _make_provider(spec: str, case, attack_goal=None, beacon=None):
    if spec == "mock":
        return MockProvider(case, attack=attack_goal, beacon=beacon)
    return build_provider(spec)


def cmd_list(_args):
    for cid in casedb.all_case_ids():
        meta = casedb.load_case(cid).meta
        print(f"{cid:34s} {meta['cwe']:8s} {meta['title']}")


def cmd_triage(args):
    case = casedb.load_case(args.case_id)
    adversary = None
    goal = None
    if args.attack:
        sys.path.insert(0, "eval")
        from injections import Adversary
        goal, _, channel = args.attack.partition(":")
        adversary = Adversary(channel=channel or "source_comment", goal=goal)
    provider = _make_provider(args.provider, case, attack_goal=goal,
                              beacon=getattr(adversary, "beacon", None))
    run = run_triage_sync(args.case_id, provider, defenses=not args.no_defenses,
                          adversary=adversary)
    if args.json:
        print(json.dumps({
            "case": args.case_id,
            "report": json.loads(run.report.model_dump_json()) if run.report else None,
            "tool_calls": run.tool_calls,
            "injection_detected": run.injection_detected,
            "audit_ok": run.audit.verify_chain(),
            "error": run.error,
        }, indent=2))
        return
    r = run.report
    print(f"case:        {args.case_id}")
    print(f"provider:    {args.provider}   defenses: {not args.no_defenses}")
    if run.error:
        print(f"ERROR:       {run.error}")
    if r:
        print(f"crash class: {r.crash_class.value}")
        print(f"CWE:         {r.cwe}")
        print(f"root cause:  {r.root_cause_file}:{r.root_cause_line}")
        print(f"confidence:  {r.confidence:.2f}"
              + (f" (verified {r.verified_confidence:.2f})"
                 if r.verified_confidence is not None else ""))
        print(f"explanation: {r.explanation}")
        if r.proposed_fix:
            print(f"fix:         verified={r.proposed_fix.verified} "
                  f"({r.proposed_fix.functional_pass}/{r.proposed_fix.functional_total} tests)")
        if r.verifier_flags:
            print(f"verifier flags: {', '.join(r.verifier_flags)}")
    c = run.audit.counts()
    print(f"audit:       {c['total']} calls, {c['denied']} denied, "
          f"{c['flagged']} flagged, chain_ok={run.audit.verify_chain()}")
    if run.injection_detected:
        print("injection:   DETECTED in tool output")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="triage_agent")
    sub = ap.add_subparsers(required=True)
    p = sub.add_parser("list", help="list benchmark cases")
    p.set_defaults(func=cmd_list)
    p = sub.add_parser("triage", help="triage one case")
    p.add_argument("case_id")
    p.add_argument("--provider", default="mock",
                   help="mock | ollama:<model> | openrouter:<model>")
    p.add_argument("--no-defenses", action="store_true")
    p.add_argument("--attack", default=None,
                   help="goal:channel, e.g. beacon_exfil:source_comment")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_triage)
    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
