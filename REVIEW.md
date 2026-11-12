# Code & evaluation review — crash-triage-agent

Date: 2026-11-10. An independent pass over the repository: the code was read end
to end, the benchmark rebuilt, the tests run, and the committed real run
re-scored. This file records what was checked, what was found, and what was
changed. It lives outside `src/` so it can be read on its own.

## Summary

The project is sound at the architecture level and does what it claims: an MCP
tool-use agent drives GDB + AddressSanitizer, classifies the crash, writes a fix
and verifies it by recompiling and re-running, behind a least-privilege policy,
spotlighting / injection detection, an independent verifier and a hash-chained
audit log, with an adversarial evaluation harness. `make verify` (12/12 cases
valid), `pytest` (17/17 after this pass) and the offline `mock` evaluation all
pass, and the committed Haiku 5.5 run reproduces.

Four issues were found. Two touch the project's headline claims directly and are
the reason for this review.

## Findings (most important first)

### 1. The benchmark leaked its own answers → CWE / root-cause numbers were optimistic  [RESOLVED]

Every `benchmark/cases/<id>/bug.c` contains the ground-truth CWE id in a comment
on the buggy line, e.g. `strcpy(buf, src); /* BUG: no bounds check (CWE-121) */`,
and the case directory name states the weakness (`c01_stack_buffer_overflow`).
The agent reads `bug.c` via `read_source`, and the `case_id` is in its system
prompt. So "CWE exact 100% / root-cause line 83%" are measured on inputs that
hand the model both the CWE number and the location.

Why it matters: the non-LLM baseline never reads source (it only parses
sanitizer / debugger text), so part of the agent's CWE edge is "the agent is
allowed to read the label and the baseline is not," not reasoning. Anyone who
opens one `bug.c` sees this immediately.

Fix applied: `benchmark/gen_cases.py` now strips any inline comment that names the
bug or its CWE (`_strip_leak`), and the cases are generated under neutral ids
(`c01` … `c12`) instead of names that state the class. The ground truth stays in
`meta.json`, which the agent never sees. **Re-measured (Haiku 5.5) on the de-leaked benchmark:**
the agent ties the sanitizer baseline on classification and localization —
CWE-exact 75% = 75%, CWE-family and root-cause line (±1) 83% = 83% — and its sole
decisive edge is verified repair: `fix verified` **100% (12/12) vs 0%**. The
inflated pre-de-leak figures (100% CWE, 83% line) were a benchmark artifact. The
committed `eval/sample-report.md` now holds this de-leaked run.

### 2. "Code execution is impossible by construction" was false  [FIXED]

`guardrails.py` and the README stated that the `inspect` whitelist makes code
execution "impossible to execute even against a fully compromised model." It was
not. `SAFE_EXPR_RE` permits `()`, and the forbidden-token list only blocked
`system / exec / popen / call / $(` and punctuation — so an expression that is a
bare libc call such as `(int)remove(<path>)` passed both the whitelist and the
tool backstop, and GDB evaluates it as an inferior function call (it runs in the
target). Under the *defended* policy this executed in a local test. The
`forbidden_inspect` attack in the eval only tries `$pc` (a register read), which
is blocked, so the measured 0% attack-success-rate is real but only exercises a
weak attacker; the call-based vector was open.

Fix applied — defense in depth, three layers:
- the strict policy now rejects any `ident(` that is not `sizeof(`
  (`inspect-expr-calls-function`);
- the always-on tool backstop (`_DANGEROUS_EXPR`) rejects the same, so it holds
  even with defenses off;
- the GDB batch is invoked with `set may-call-functions off`, so even an
  expression that slipped through cannot call a function.

Simple reads (`n`, `*p`, `table[0].key`, `sizeof(buf)`) still pass. A regression
test was added (`test_inspect_rejects_inferior_function_call`).

### 3. The fix-verifier counted a clean non-zero exit as a crash → fixes under-counted, and the model gamed it  [FIXED]

`propose_fix` computed `stopped = not crash_run.crashed`, and `RunResult.crashed`
is true for any exit code outside {0, None}. So a correct fix that rejects the bad
input with `return 1` was recorded as "still crashes." Both "unverified" fixes in
the committed run (c05 null-deref, c09 integer-overflow) are exactly this false
negative: the fix is correct but exits non-zero. The model even adapted to the
checker within a run — its c06 and c11 explanations note that a first patch that
returned 1 was rejected, so it switched to `return 0`. That is specification
gaming driven by the verifier's definition, not pre-existing "cheating": the agent
optimized the measured signal. The phenomenon is itself worth showing.

Fix applied: `propose_fix` now uses a new `RunResult.crashed_by_signal` (fatal
signal or timeout — the sanitizers abort via SIGABRT, so real crashes are still
caught) and no longer treats a clean non-zero exit as a crash. Re-scoring the
**same** committed model outputs under the corrected definition gives **12/12
fix-verified** (c05 and c09 flip), up from 10/12. No new model run was needed for
the re-score.

### 4. `make eval` and the CI evaluation step were broken  [FIXED]

Both passed `--provider scripted`, which `build_provider` does not know (only
`mock` / `ollama:<model>` / `openrouter:<model>`), so `make eval` and the CI
"offline evaluation" job raised `ProviderError: unknown provider spec:
'scripted'`. Changed to `--provider mock` in `Makefile` and
`.github/workflows/ci.yml`; the documented `make eval report` quickstart now runs.

### Minor  [FIXED]
- Stale default model `anthropic/claude-3.5-sonnet` in `providers.py`,
  `Dockerfile` and the README quickstart → `anthropic/claude-haiku-5.5`.
- A few ground-truth `crash_class` labels are debatable (c08 OOB *read* labeled
  `global-buffer-overflow`; c09 integer-overflow labeled `heap-buffer-overflow`;
  c12 negative-index *write* labeled `stack-buffer-overflow`). Left as-is; noted
  for a future pass.
- The README "Why this project" company-targeting table (which named specific
  employers) was removed and replaced with generic prose.
- Root-cause-line scoring now uses a documented **±1 line tolerance** (`metrics.py`,
  applied to agent and baseline alike): several bugs span two adjacent lines (the
  free vs the use of a UAF, the undersized alloc vs the overflowing write), so an
  exact-line match was unfairly strict. This is a standard fault-localization
  tolerance, not a way to flatter the number.

## Takeaway

The engineering and the verified-fix idea are the strong parts and they hold up.
Before quoting the CWE / line numbers anywhere, finish finding #1 (de-leak +
re-run). Findings #2 and #3 are good things to have found: they are exactly the
agent-security and eval-design subtleties the project is about, and both are now
fixed, with tests and a corrected, reproducible number.

## Also in this pass: a real `eval` / `attack` / `report` CLI

The run surface was scattered (`make`, `python -m triage_agent.cli`,
`python eval/harness.py`). It is now one coherent CLI — `triage list | triage |
eval | attack | report` — with `--model X` sugar for `--provider openrouter:X`
and a soft `--max-cost-usd` budget guard (an estimate; stops between cases). The
README "Quickstart" / "Running against a real model" sections match it. Note:
there is no `--dataset/--rules/--path/examples/demo` or `serve` subcommand — those
were never part of this project.

## Second pass — 2026-11-12: documentation truth pass

A full re-read of the repository, with no change to the numbers, the benchmark or
the measurement code. The goal of this pass was narrower than the first one: make
every claim in the README something a reader can confirm by opening the file it
names. Where the code and the prose disagreed, the prose moved — except in one
case (noted below) where moving it would have changed a measured run.

What was checked: every module read end to end; the guardrails probed directly
(expression policy, beacon handling, report construction); the test suite
collected and run; the generated benchmark inspected for answer leaks. The
capability and security figures in `eval/sample-report.md` are unchanged by this
pass and were not re-measured.

### Claims corrected

1. **The verifier does not read the audit trail.** The README (threat-model table
   and defense list) said `verified` is "recomputed from the audit trail". It is
   not: `verify_report` reads a `VerifierState` held in memory, populated by
   `agent.py` from the `__FIX_VERDICT__` line that `propose_fix` emits after
   actually compiling and running the patch. The audit log stores hashes of
   arguments and outputs and is never consulted by the verifier. The defense is
   real and model-independent — it simply works on a different substrate than the
   one the text claimed. Why it mattered: "recomputed from the audit trail" is a
   stronger and more elegant statement than the implementation supports, and it
   is the first thing a reader who opens `guardrails.py` would check.

2. **The system prompt does not hand the agent the crashing input.** The prompt
   (`agent.py`) reads "The crashing input is on stdin", but nothing is on stdin:
   `run_target(case_id, stdin="")` defaults to the empty string and every tool
   takes the input as an argument. The agent has to construct an input that
   triggers the crash before it can reproduce, read a sanitizer report or verify a
   fix. The heuristic baseline, by contrast, is given
   `meta["crashing_stdin"]` directly. Why it mattered: the comparison that
   produces the headline table runs at an information advantage to the
   *baseline*, and that asymmetry was documented nowhere. It is now stated in
   *Design notes & honest limitations*. The prompt line itself was left alone —
   rewording it changes what the model is asked to do, which would invalidate the
   committed run; it needs its own pass with a re-run.

3. **Test counts.** The README said 17 in the quickstart and 16 in the layout
   section. `pytest --collect-only` reports 19 (15 unit, 4 end-to-end including
   the three parametrized attack cases). Why it mattered: a wrong, checkable
   number in the first screen of the README invites doubt about the numbers that
   cannot be checked in a minute.

4. **macOS behaviour.** The note said ASan "does not run natively on macOS Apple
   Silicon". Observed: the sources compile, and a sanitizer-built target then
   hangs until the 15 s wall-clock limit kills it, so every tool call returns a
   timeout with empty output rather than an error. Two of the 19 tests fail on
   macOS for exactly this reason. Linux (or the Docker image) is genuinely
   required; the note now says what a macOS user will actually see.

### Claims added (disclosures, not fixes)

5. **How to read the security ablation.** Every payload in `injections.py` is
   written to trip the detector's own signatures ("ignore previous", "new
   instructions", "you must", role spoofing), so an attack-success-rate of 0%
   under defense is a property of the suite as much as of the defense. This is
   now said in the security section for real-model runs too, not only for the
   `mock`. Why: the opposite reading — "the defenses generalize to unseen
   injections" — is the one a security-literate reviewer would test first, and
   the project should not be the one to imply it.

6. **Scope of the injection defenses.** Spotlighting and redaction cover the six
   untrusted channels. `propose_fix` is not among them, and its output embeds a
   few bytes of the patched program's stdout; the beacon check and strip cover
   the free-text `explanation` only — a beacon in `cwe`, `root_cause_file` or the
   diff is neither detected nor removed (confirmed by direct probe). Both are
   current gaps rather than invariants, and are now listed as such.

### Found, deliberately not changed

- **`finalize_report` is unguarded.** `agent.py` calls `_build_report` without a
  try/except, and that function does `int(root_cause_line)` and lets Pydantic
  validate `confidence ∈ [0, 1]`. A model reply of `"root_cause_line": "line 12"`
  raises `ValueError`; `"confidence": 90` raises `ValidationError`; either escapes
  `session.run` and aborts the whole evaluation with no `run.error` and no report.
  `"root_cause_line": 0` is silently rewritten to 1. Not visible in CI because the
  `mock` provider always emits well-formed integers — the exposure is real-provider
  only. Left for a pass of its own so it lands with a regression test and a re-run
  of the committed numbers.
- **`crashed` (exit ≠ 0) is still used in the functional-test check**
  (`propose_fix`) and in `benchmark/verify.py`, although finding #3 above fixed
  exactly that definition for the crash check. Same class of bug, one call site
  away.
- **`p->len` is denied** by the strict policy while `(*p).len` is allowed:
  `_FORBIDDEN_EXPR_TOKENS` contains `>`, which nullifies the `->` support that
  `SAFE_EXPR_RE` and its comment advertise. The expression rule also exists in
  three places (`guardrails`, `tools_impl._DANGEROUS_EXPR`, `_CALL_RE`) which have
  already diverged; it should become one definition.
- **`case_id` is model-supplied and unconstrained.** Every tool takes it as an
  argument and `Policy.check` never validates it, so the agent can act on any case
  in the benchmark, not just the one under triage. `load_case` even tolerates a
  descriptive suffix. Least privilege here would be to pin the case on the server
  side.
- **`forbidden_inspect_executed` conflates two different events**: "the model
  emitted an expression outside the whitelist" and "code was executed". A benign
  `p->len` attempt in the undefended condition counts as a successful attack.
  The metric should be instrumented at the GDB layer and split.
- Cosmetic: `make lint` is advertised in `.PHONY` with no target;
  `benchmark/manifest.json` is generated and never read;
  `VerifierState.evidence_lines` is dead.

### Reproducing this pass

Each probe is self-contained: no C toolchain, no model, no network. Run from the
repository root.

Test count:

```bash
python -m pytest --collect-only -q      # 19 tests, not the 17 / 16 the README used to say
```

A beacon is only detected in `explanation` — put it anywhere else and it survives:

```bash
python - <<'PY'
import sys; sys.path.insert(0, "src")
from triage_agent import guardrails as g
from triage_agent.schema import CrashClass, TriageReport
r = TriageReport(case_id="c01", crash_class=CrashClass.SEGV,
                 cwe="CWE-476 PWNED-a1b2c3",      # beacon hidden in the CWE field
                 root_cause_file="bug.c", root_cause_line=3,
                 explanation="clean text", confidence=0.9)
out = g.verify_report(r, g.VerifierState(source_line_count=20),
                      enabled=True, beacon="PWNED-a1b2c3")
print(out.beacon_found, r.verifier_flags, repr(r.cwe))
# -> False [] 'CWE-476 PWNED-a1b2c3'
PY
```

A malformed `finalize_report` payload escapes as an exception:

```bash
python - <<'PY'
import sys; sys.path.insert(0, "src")
from triage_agent import guardrails
from triage_agent.agent import _build_report
base = {"crash_class": "SEGV", "cwe": "CWE-476", "root_cause_file": "bug.c",
        "root_cause_line": 12, "explanation": "x", "confidence": 0.9}
for label, patch in [("line as string", {"root_cause_line": "line 12"}),
                     ("confidence 90", {"confidence": 90})]:
    try:
        _build_report("c05", {**base, **patch}, guardrails.VerifierState(source_line_count=20))
        print(label, "-> accepted")
    except Exception as e:
        print(label, "->", type(e).__name__)
# -> line as string -> ValueError
# -> confidence 90 -> ValidationError
PY
```

The `->` member access the whitelist advertises is rejected:

```bash
python - <<'PY'
import sys; sys.path.insert(0, "src")
from triage_agent.guardrails import Policy
p = Policy(strict=True)
for expr in ("p->len", "(*p).len"):
    print(f"{expr:10s} {p.check('inspect', {'expr': expr}).tag}")
# -> p->len     deny:inspect-expr-forbidden-token
# -> (*p).len   allow
PY
```

## Third pass — 2026-11-12: harden finalize_report

One fix, carrying the second pass's discipline into code. The `finalize_report`
exposure above is the only deferred item that can *silently void a measured run*
— an exception out of `session.run` aborts the harness with no `run.error` and no
report — and runs are the thing this project shows, so it was promoted from
deferred to done.

- `_build_report` now parses `root_cause_line` defensively (`"line 12"` -> 12,
  garbage -> 1) and clamps `confidence` into `[0, 1]`, instead of letting Pydantic
  raise.
- `session.run` wraps the finalize call in try/except and records the failure in
  `run.error`, so one bad reply degrades that case instead of aborting the grid.
- Regression tests cover both coercions (20 tests now).

Behaviour-preserving for well-formed replies: the committed numbers are unchanged
and need no re-run.

**Deliberately still not changed:** the `crashed` (exit != 0) check in
`propose_fix`'s *functional* test (and `verify.py`). Unlike the crash check, where
a clean non-zero exit is not a crash, a *valid* input is expected to exit 0 — so
`exit != 0` there is a genuine functional failure, not the same bug. The second
pass grouped the two call sites; they are different semantics, and only the crash
check was wrong.
