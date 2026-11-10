"""Compare two evaluation runs and flag regressions.

Usage:  python eval/compare.py <baseline_run_id> <candidate_run_id> [--db ...]
Exit status is non-zero if the candidate regressed on any guarded metric, so it
can gate CI (a model or prompt change must not quietly raise attack success or
lower accuracy).
"""
from __future__ import annotations

import argparse
import sqlite3
import sys


def _rows(db, run_id, kind):
    cols = [c[1] for c in db.execute("PRAGMA table_info(results)")]
    return [dict(zip(cols, r)) for r in
            db.execute("SELECT * FROM results WHERE run_id=? AND kind=?", (run_id, kind))]


def _rate(rows, key):
    rows = [r for r in rows if r[key] is not None]
    if not rows:
        return None
    return sum(1 for r in rows if r[key] == 1) / len(rows)


def _cap(db, run):
    rows = _rows(db, run, "capability")
    return {k: _rate(rows, k) for k in
            ("cwe_correct", "cwe_family_correct", "root_line_correct", "fix_verified")}


def _asr(db, run, defenses):
    rows = [r for r in _rows(db, run, "security") if r["defenses"] == int(defenses)]
    return _rate(rows, "attack_succeeded")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline")
    ap.add_argument("candidate")
    ap.add_argument("--db", default="eval/results.db")
    ap.add_argument("--tol", type=float, default=0.02,
                    help="allowed drop before a capability change counts as a regression")
    args = ap.parse_args()
    db = sqlite3.connect(args.db)

    cap_b, cap_c = _cap(db, args.baseline), _cap(db, args.candidate)
    regressions = []
    improvements = []

    print(f"{'metric':22s} {'baseline':>10s} {'candidate':>10s}  verdict")
    for k in cap_b:
        b, c = cap_b[k], cap_c[k]
        if b is None or c is None:
            continue
        delta = c - b
        verdict = "ok"
        if delta < -args.tol:
            verdict = "REGRESSION"
            regressions.append((k, b, c))
        elif delta > args.tol:
            verdict = "improved"
            improvements.append((k, b, c))
        print(f"{k:22s} {b*100:9.1f}% {c*100:9.1f}%  {verdict}  ({delta*100:+.1f})")

    for defenses in (True, False):
        b, c = _asr(db, args.baseline, defenses), _asr(db, args.candidate, defenses)
        if b is None or c is None:
            continue
        delta = c - b
        label = f"ASR defenses={'ON' if defenses else 'OFF'}"
        # Higher attack success is a regression.
        verdict = "ok"
        if delta > args.tol:
            verdict = "REGRESSION"
            regressions.append((label, b, c))
        print(f"{label:22s} {b*100:9.1f}% {c*100:9.1f}%  {verdict}  ({delta*100:+.1f})")

    print()
    if regressions:
        print(f"FAIL: {len(regressions)} regression(s)")
        return 1
    print("OK: no regressions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
