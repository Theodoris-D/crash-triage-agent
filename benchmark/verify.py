#!/usr/bin/env python3
"""Compile and validate the benchmark.

For every case we check two invariants that the whole project relies on:
  1. bug.c, built with ASan+UBSan, crashes (non-zero / killed) on crashing_stdin.
  2. fix.c survives crashing_stdin AND passes every functional test.

This is a self-check of the ground truth, not part of the agent. Run it after
gen_cases.py whenever you touch a case.

Exit status is non-zero if any invariant fails.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CASES_DIR = HERE / "cases"
CC = "cc"
ASAN_FLAGS = ["-g", "-O0", "-fno-omit-frame-pointer",
              "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
# ASan needs a predictable environment; halt on the first error.
ASAN_ENV = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:exitcode=99",
            "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1"}


def compile_one(src: pathlib.Path, out: pathlib.Path) -> tuple[bool, str]:
    p = subprocess.run([CC, *ASAN_FLAGS, str(src), "-o", str(out)],
                       capture_output=True, text=True)
    return p.returncode == 0, p.stderr


def run_one(binary: pathlib.Path, stdin: str, timeout: float = 10.0):
    import os
    env = dict(os.environ)
    env.update(ASAN_ENV)
    try:
        p = subprocess.run([str(binary)], input=stdin, capture_output=True,
                           text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, "", "<timeout>"
    return p.returncode, p.stdout, p.stderr


def main() -> int:
    cases = sorted(p for p in CASES_DIR.iterdir() if p.is_dir())
    if not cases:
        print("no cases; run gen_cases.py first", file=sys.stderr)
        return 2
    build = HERE / "_build"
    build.mkdir(exist_ok=True)
    failures = []
    for d in cases:
        meta = json.loads((d / "meta.json").read_text())
        cid = meta["id"]
        # bug must crash
        bug_bin = build / f"{cid}.bug"
        ok, err = compile_one(d / "bug.c", bug_bin)
        if not ok:
            failures.append(f"{cid}: bug.c did not compile\n{err}")
            continue
        rc, _out, serr = run_one(bug_bin, meta["crashing_stdin"])
        crashed = rc is None or rc != 0
        if not crashed:
            failures.append(f"{cid}: bug.c did NOT crash on crashing_stdin (rc={rc})")
        # fix must survive + pass functional tests
        fix_bin = build / f"{cid}.fix"
        ok, err = compile_one(d / "fix.c", fix_bin)
        if not ok:
            failures.append(f"{cid}: fix.c did not compile\n{err}")
            continue
        rc, _out, _serr = run_one(fix_bin, meta["crashing_stdin"])
        if rc != 0:
            failures.append(f"{cid}: fix.c crashed on crashing_stdin (rc={rc})")
        for t in meta["functional_tests"]:
            rc, out, _serr = run_one(fix_bin, t["stdin"])
            if rc != 0 or t["expect_substr"] not in out:
                failures.append(
                    f"{cid}: fix.c functional test failed for {t['stdin']!r}: "
                    f"rc={rc} out={out!r} want~{t['expect_substr']!r}")
        tag = "OK " if not any(cid in f for f in failures) else "FAIL"
        print(f"[{tag}] {cid:34s} {meta['cwe']:8s} {meta['crash_class']}")
    print()
    if failures:
        print(f"{len(failures)} failure(s):", file=sys.stderr)
        for f in failures:
            print("  - " + f, file=sys.stderr)
        return 1
    print(f"all {len(cases)} cases valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
