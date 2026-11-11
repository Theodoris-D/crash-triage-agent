"""Render a Markdown evaluation report from the results database.

Usage:  python eval/report.py [--db eval/results.db] [--run <run_id>] [-o report.md]
Defaults to the most recent run. Baseline numbers are computed live for the same
benchmark so the agent's lift is visible in one table.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from triage_agent import casedb, baseline
import metrics


def latest_run(db) -> str | None:
    row = db.execute("SELECT run_id FROM runs ORDER BY created DESC LIMIT 1").fetchone()
    return row[0] if row else None


def _rows(db, run_id, kind):
    cols = [c[1] for c in db.execute("PRAGMA table_info(results)")]
    out = []
    for r in db.execute("SELECT * FROM results WHERE run_id=? AND kind=?",
                        (run_id, kind)):
        out.append(dict(zip(cols, r)))
    return out


def _cap_counts(rows, key):
    k = sum(1 for r in rows if r[key] == 1)
    return k, len(rows)


def build(db, run_id) -> str:
    meta = db.execute("SELECT provider, created, notes FROM runs WHERE run_id=?",
                      (run_id,)).fetchone()
    provider, created, notes = meta
    import time
    cap = _rows(db, run_id, "capability")
    sec = _rows(db, run_id, "security")

    L = []
    L.append(f"# Crash-triage evaluation — `{run_id}`\n")
    L.append(f"- provider: **{provider}**")
    L.append(f"- generated: {time.strftime('%Y-%m-%d %H:%M', time.localtime(created))}")
    if notes:
        L.append(f"- notes: {notes}")
    L.append("")

    # Capability vs baseline
    L.append("## Capability (defended, no attack)\n")
    if provider == "mock":
        L.append("> _The `mock` provider is a deterministic CI test double, not a "
                 "model: it classifies by parsing sanitizer output (so it scores "
                 "like the heuristic baseline) and proposes no fix. These numbers "
                 "test the harness, not an agent. Run with `--provider ollama:<model>` "
                 "or `openrouter:<model>` for a real capability measurement._\n")
    base = baseline.run_all()
    base_scores = [metrics.score_capability(r, casedb.load_case(cid).meta)
                   for cid, r in base]
    bagg = metrics.aggregate_capability(base_scores)

    def line(name, counts_agent):
        ka, na = counts_agent
        return (f"| {name} | {metrics.fmt_ci(ka, na)} |")

    L.append("| metric | agent |")
    L.append("|---|---|")
    for label, key in [("crash-class exact", "crash_class_correct"),
                       ("CWE exact", "cwe_correct"),
                       ("CWE family", "cwe_family_correct"),
                       ("root-cause line (±1)", "root_line_correct"),
                       ("fix verified", "fix_verified")]:
        L.append(line(label, _cap_counts(cap, key)))
    L.append("")
    L.append("Baseline (heuristic parser, no LLM, no fix) on the same cases:\n")
    L.append("| metric | baseline |")
    L.append("|---|---|")
    L.append(f"| CWE exact | {metrics.fmt_ci(*_agg_k(bagg.cwe_exact))} |")
    L.append(f"| CWE family | {metrics.fmt_ci(*_agg_k(bagg.cwe_family))} |")
    L.append(f"| root-cause line (±1) | {metrics.fmt_ci(*_agg_k(bagg.root_line))} |")
    L.append(f"| fix verified | {metrics.fmt_ci(*_agg_k(bagg.fix_verified))} |")
    L.append("")

    # Security
    L.append("## Security — prompt-injection attack success rate\n")
    if sec:
        asr = metrics.attack_success_rate(
            [{"defenses": bool(r["defenses"]),
              "attack_succeeded": bool(r["attack_succeeded"])} for r in sec])
        det = {}
        for d in (False, True):
            sub = [r for r in sec if bool(r["defenses"]) == d]
            det[d] = sum(1 for r in sub if r["injection_detected"] == 1), len(sub)
        L.append("| condition | attack success rate | injection detected |")
        L.append("|---|---|---|")
        for d, label in [(False, "defenses OFF"), (True, "defenses ON")]:
            p, lo, hi, k, n = asr[d]
            L.append(f"| {label} | {metrics.fmt_ci(k, n)} | "
                     f"{metrics.fmt_ci(*det[d])} |")
        L.append("")
        # per-goal breakdown
        L.append("### Attack success by goal\n")
        L.append("| goal | defenses OFF | defenses ON |")
        L.append("|---|---|---|")
        goals = sorted({r["attack_goal"] for r in sec})
        for g in goals:
            off = [r for r in sec if r["attack_goal"] == g and r["defenses"] == 0]
            on = [r for r in sec if r["attack_goal"] == g and r["defenses"] == 1]
            ko = sum(1 for r in off if r["attack_succeeded"] == 1)
            kn = sum(1 for r in on if r["attack_succeeded"] == 1)
            L.append(f"| {g} | {metrics.fmt_ci(ko, len(off))} | "
                     f"{metrics.fmt_ci(kn, len(on))} |")
        L.append("")
    else:
        L.append("_No security runs in this run._\n")

    # Integrity
    audit_ok = all(r["audit_ok"] == 1 for r in cap + sec) if (cap + sec) else True
    errs = [r for r in cap + sec if r["error"]]
    L.append("## Integrity\n")
    L.append(f"- audit hash-chain intact on every run: **{audit_ok}**")
    L.append(f"- runs with errors: **{len(errs)}**")
    L.append("")

    # Per-case detail
    L.append("## Per-case capability\n")
    L.append("| case | CWE (pred/true) | line ok | fix verified |")
    L.append("|---|---|---|---|")
    for r in cap:
        rep = json.loads(r["report_json"]) if r["report_json"] else {}
        true = casedb.load_case(r["case_id"]).meta
        L.append(f"| {r['case_id']} | {rep.get('cwe','?')}/{true['cwe']} | "
                 f"{'Y' if r['root_line_correct'] else 'n'} | "
                 f"{'Y' if r['fix_verified'] else 'n'} |")
    L.append("")
    return "\n".join(L)


def _agg_k(agg_tuple):
    # agg tuples are (p, lo, hi, k, n)
    return agg_tuple[3], agg_tuple[4]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="eval/results.db")
    ap.add_argument("--run", default=None)
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()
    db = sqlite3.connect(args.db)
    run_id = args.run or latest_run(db)
    if not run_id:
        raise SystemExit("no runs found")
    md = build(db, run_id)
    if args.out:
        pathlib.Path(args.out).write_text(md)
        print(f"wrote {args.out}")
    else:
        print(md)


if __name__ == "__main__":
    main()
