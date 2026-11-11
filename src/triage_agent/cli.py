"""Command-line entry point.

  triage list
  triage triage c06 [--provider mock | --provider openrouter:<model> | --model <model>]
                    [--no-defenses] [--attack goal:channel] [--json]

  triage eval   [--model <m> | --provider <spec>] [--security] [--security-cases N]
                [--max-cost-usd X] [--db PATH] [--notes TEXT]
  triage attack [--model <m> | --provider <spec>] [--cases N]
                [--max-cost-usd X] [--db PATH] [--notes TEXT]
  triage report [--db PATH] [--run RUN_ID] [-o OUT]

`--model X` is sugar for `--provider openrouter:X`. `eval`/`attack`/`report`
wrap the harness and report renderer under eval/; the benchmark is generated on
demand if it is missing. The default provider is the offline `mock` double, so
every command runs with no model and no network unless you pass one.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

from . import casedb
from .agent import run_triage_sync
from .config import ROOT
from .providers import MockProvider, build_provider

EVAL_DIR = ROOT / "eval"


def _ensure_eval_importable() -> None:
    """Put eval/ on sys.path (harness/report/metrics/injections live there) and
    generate the benchmark if it has not been built yet."""
    p = str(EVAL_DIR)
    if p not in sys.path:
        sys.path.insert(0, p)
    if not casedb.all_case_ids():
        subprocess.run([sys.executable, str(ROOT / "benchmark" / "gen_cases.py")],
                       check=True)


def _spec(args) -> str:
    """Resolve the provider spec. `--model X` is sugar for openrouter:X."""
    if getattr(args, "model", None):
        return f"openrouter:{args.model}"
    return getattr(args, "provider", None) or "mock"


# --------------------------------------------------------------------------- #
# list / triage (single case)                                                 #
# --------------------------------------------------------------------------- #
def cmd_list(_args):
    for cid in casedb.all_case_ids():
        meta = casedb.load_case(cid).meta
        print(f"{cid:6s} {meta['cwe']:8s} {meta['title']}")


def cmd_triage(args):
    spec = _spec(args)
    case = casedb.load_case(args.case_id)
    adversary = None
    goal = None
    if args.attack:
        _ensure_eval_importable()
        from injections import Adversary
        goal, _, channel = args.attack.partition(":")
        adversary = Adversary(channel=channel or "source_comment", goal=goal)
    if spec == "mock":
        provider = MockProvider(case, attack=goal, beacon=getattr(adversary, "beacon", None))
    else:
        provider = build_provider(spec)
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
    print(f"provider:    {spec}   defenses: {not args.no_defenses}")
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


# --------------------------------------------------------------------------- #
# eval / attack / report (wrap the harness + report renderer)                 #
# --------------------------------------------------------------------------- #
def cmd_eval(args):
    _ensure_eval_importable()
    from harness import Harness, EvalScope
    cases = casedb.all_case_ids()
    scope = EvalScope(provider_spec=_spec(args),
                      run_capability=True,
                      run_security=args.security,
                      security_cases=cases[:args.security_cases],
                      max_cost_usd=args.max_cost_usd)
    h = Harness(args.db)
    rid = h.run(scope, notes=args.notes or "eval")
    h.close()
    print(f"\nrun_id = {rid}")
    print(f"render it with:  triage report --db {args.db} --run {rid}")


def cmd_attack(args):
    _ensure_eval_importable()
    from harness import Harness, EvalScope
    cases = casedb.all_case_ids()
    scope = EvalScope(provider_spec=_spec(args),
                      run_capability=False,
                      run_security=True,
                      security_cases=cases[:args.cases],
                      max_cost_usd=args.max_cost_usd)
    h = Harness(args.db)
    rid = h.run(scope, notes=args.notes or "attack")
    h.close()
    print(f"\nrun_id = {rid}")


def cmd_report(args):
    _ensure_eval_importable()
    import sqlite3
    import report as report_mod
    db = sqlite3.connect(args.db)
    run_id = args.run or report_mod.latest_run(db)
    if not run_id:
        raise SystemExit("no runs found; run `triage eval` first")
    md = report_mod.build(db, run_id)
    if args.out:
        import pathlib
        pathlib.Path(args.out).write_text(md)
        print(f"wrote {args.out}")
    else:
        print(md)


# --------------------------------------------------------------------------- #
def _add_provider_flags(p):
    p.add_argument("--provider", default="mock",
                   help="mock | ollama:<model> | openrouter:<model> (default: mock)")
    p.add_argument("--model", default=None,
                   help="sugar for --provider openrouter:<model>, e.g. anthropic/claude-sonnet-5.5")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="triage")
    sub = ap.add_subparsers(required=True)

    p = sub.add_parser("list", help="list benchmark cases")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("triage", help="triage one case")
    p.add_argument("case_id")
    _add_provider_flags(p)
    p.add_argument("--no-defenses", action="store_true")
    p.add_argument("--attack", default=None, help="goal:channel, e.g. beacon_exfil:source_comment")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("eval", help="run the capability evaluation over the benchmark")
    _add_provider_flags(p)
    p.add_argument("--security", action="store_true",
                   help="also run the prompt-injection ablation (defenses on/off)")
    p.add_argument("--security-cases", type=int, default=3,
                   help="how many cases in the security grid when --security is set")
    p.add_argument("--max-cost-usd", type=float, default=None,
                   help="soft budget guard for real providers (estimate; stops between cases)")
    p.add_argument("--db", default="eval/results.db")
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("attack", help="run the prompt-injection ablation only (defenses on/off)")
    _add_provider_flags(p)
    p.add_argument("--cases", type=int, default=3, help="how many cases in the attack grid")
    p.add_argument("--max-cost-usd", type=float, default=None,
                   help="soft budget guard for real providers (estimate; stops between cases)")
    p.add_argument("--db", default="eval/results.db")
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_attack)

    p = sub.add_parser("report", help="render the Markdown report from a run")
    p.add_argument("--db", default="eval/results.db")
    p.add_argument("--run", default=None, help="run id (default: latest)")
    p.add_argument("-o", "--out", default=None, help="output file (default: stdout)")
    p.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
