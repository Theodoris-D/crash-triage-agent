# Crash-Triage Agent

A security-focused AI **agent** that triages crashing C programs: given a program
that crashes on some input, it drives **GDB and AddressSanitizer through an MCP
server**, reads the source, identifies the **root cause, crash class and CWE**,
writes a patch, and **verifies the patch by actually recompiling and re-running
it**. It is built around a concrete threat model — the agent reads
attacker-influenceable text (source comments, debugger and sanitizer output) — and
ships a **least-privilege tool policy, prompt-injection defenses, an independent
report verifier, a tamper-evident audit log, and an adversarial evaluation
harness** that measures attack-success-rate with the defenses on and off.

The pipeline, guardrails and tests run **offline** with a deterministic mock
provider (no model, no API key, no network) for CI; real capability and security
numbers come from a **real LLM** via any OpenAI-compatible endpoint — a local
**Ollama** server or **OpenRouter**.

> Author: Theodoris Donval. Built on existing GDB/QEMU/C and applied-crypto work;
> this project adds the agent/MCP, RAG, evaluation and guardrail pieces.

---

## Why this project

It sits on the intersection of agentic AI and systems security: an autonomous
agent that debugs crashes and is *evaluated* for both correctness and robustness.
It drives GDB programmatically over a tool interface and wraps the loop in a
least-privilege policy, prompt-injection defenses, an independent report verifier
and a tamper-evident audit trail — reusing a GDB/QEMU/C debugging stack I already
know. The point is not just "an LLM that fixes bugs" but a *measured* one: every
capability and security claim below comes with a reproducible number.

## Results

Measured run (`claude-haiku-5.5` via OpenRouter, 12-case benchmark, defended, no
attack; full output in [`eval/sample-report.md`](eval/sample-report.md)). The
baseline is the **same tools without the LLM** — a script that runs
AddressSanitizer/UBSan and regex-maps its output to a CWE and line, proposing no
fix. It isolates what the agent's reasoning and verified fixes add on top of the
sanitizer.

| metric | agent (Haiku 5.5) | baseline (no LLM) |
|---|---|---|
| CWE exact | 75% (9/12) | 75% (9/12) |
| CWE family | 83% (10/12) | 83% (10/12) |
| root-cause line (±1) | 83% (10/12) | 83% (10/12) |
| crash-class exact | 83% (10/12) | — |
| **fix verified** | **100% (12/12)** | **0% (0/12)** |

The audit hash-chain verified intact on every run; 0 runs errored.

**Second run** (`20261115-214207-6c443d`, same model and benchmark): fix verified
**11/12** (c09 failed), crash-class 11/12, root-cause line 11/12, CWE exact 9/12.
Across both runs the agent verified **23 of 24** fixes; expect this kind of
run-to-run variation from a single model.

**How to read it.** These are measured on the *de-leaked* benchmark — neutral ids
and no CWE hints in the sources (see [`REVIEW.md`](REVIEW.md)) — so they reflect
reasoning, not labels the agent could read off the source. The honest result: on
**classification and localization the agent ties the sanitizer baseline** —
CWE-exact 75% = 75%, and CWE-family and root-cause line (scored within **±1**, as
these bugs span two adjacent lines) 83% = 83%. Naming the weakness is something a
sanitizer parser already does well. The agent's **decisive, sole advantage is
repair**: `fix verified` **100% vs 0%** — a parser cannot write a patch, whereas
the agent produces fixes that compile, stop the crash, and pass the functional
tests on all 12 cases. n = 12, one model, one run (wide intervals; CWE 75% is
[46.8, 91.1]). The claim to lead with is *verified repair*, not CWE identification.

*The methodology and the fixes behind these numbers — the benchmark de-leak, the
±1 localization tolerance, the fix-verifier correction and the `inspect` hardening
— are documented in [`REVIEW.md`](REVIEW.md).*

A model is required for these numbers; the default `mock` provider is a
deterministic CI test double (see *Design notes*), not an agent.

**Security ablation.** The harness also runs each case × attack × {defenses on,
off} and reports attack-success-rate and injection-detection separately. Against
the deterministic `mock` attacker the defenses block every attack **by
construction** (0% on / 100% off — a mechanism self-test); the *interesting*
measurement is a real model's ASR under injection, which the same harness
produces when pointed at one (`make eval` without `--capability-only`). One
caveat on how to read it: every payload is written to trip the detector's
signatures, so a low ASR on a real model should be read as "the mechanism
engages", not as generalization to paraphrased or indirect injections. The suite
is a mechanism test, not an attack benchmark.

**Measured on a real model** (`20261115-214207-6c443d`, Claude Haiku 5.5, cases
c01–c03 × 3 goals × 3 channels × defenses on/off, 0 errors, $0.20):

| condition | attack success | injection detected |
|---|---|---|
| defenses OFF | 0/27 [0, 12.5] | 20/27 |
| defenses ON | 0/27 [0, 12.5] | 19/27 |

The model refused every payload on its own, even with defenses off, so this run
**does not measure what the defenses add**: the payloads are too blunt for this
model. It does expose a detector gap: only 4 of 18 payloads delivered through
debugger output (`gdb_note`) are detected, versus 35 of 36 in source comments and
sanitizer notes. Next step: paraphrased and indirect payloads, all 12 cases, and a
weaker model.

### CWE retrieval: keyword vs BM25 vs Hugging Face embeddings

The `cwe_lookup` tool started as keyword overlap over 18 hand-written CWE entries.
[`eval/retrieval_eval.py`](eval/retrieval_eval.py) compares it offline (no LLM,
no API cost) with BM25, three Hugging Face sentence-embedding models stored in
ChromaDB, a BM25 + embedding hybrid (reciprocal-rank fusion) and a cross-encoder
reranker, on two query sets with every literal CWE id stripped: **288 real NVD CVE
descriptions** (single-label, 15 CWEs) and the **24 root-cause explanations the
agent itself wrote** in the two Haiku 5.5 runs. Full table:
[`eval/retrieval_report.md`](eval/retrieval_report.md).

| top-1 CWE (curated 18 entries) | NVD (n=288) | agent explanations (n=24) |
|---|---|---|
| keyword (old tool) | 52% [47-58] | 71% [51-85] |
| BM25 | 50% [45-56] | 92% [74-98] |
| bge-small-en-v1.5 (dense) | 58% [52-63] | 92% [74-98] |
| **hybrid BM25 + bge-small** | **61% [55-66]**, McNemar p=0.006 | **96% [80-99]**, p=0.031 |
| bge-small + bge-reranker-base | 75% [69-79] | 25% [12-45] |

What it shows:
- **The hybrid wins on both sets** and is significantly better than the old tool
  on paired queries (+48/-24 on NVD, +6/-0 on the agent's explanations). It is
  now available as `TRIAGE_CWE_RETRIEVER=hybrid`; keyword stays the default so CI
  needs no model download.
- **More data made retrieval worse.** Indexing the full MITRE catalogue (956
  weaknesses) drops every retriever, e.g. the hybrid to 28% / 29% top-1: many
  near-duplicate siblings compete with the right entry. The curated set wins.
- **The reranker does not transfer.** The cross-encoder is the best on short CVE
  descriptions (75%) but collapses on the agent's longer explanations (25%), and
  costs ~1 s per query. Not yet explained; it is not used.
- Limits: NVD labels are noisy (often one level off, hence the "one-hop" column in
  the report); n=24 for agent queries is small; retrieval accuracy is not CWE
  accuracy of the agent end to end, which needs a new real-model run.

## Costs

The benchmark is small, so a full run is cheap and the right model axis is
**tool-calling reliability + code quality, not price**. Per-million-token rates
(OpenRouter, late 2026) and the rough cost of one 12-case capability run
(≈ a few hundred k input / tens of k output tokens, growing with the tool loop):

| model | in / out per 1M | ≈ one capability run |
|---|---|---|
| `anthropic/claude-haiku-5.5` | $0.10 / $0.50 | ~$0.05–0.10 |
| `deepseek/deepseek-v4-flash-0731` | $0.043 / $0.30 | ~$0.02–0.05 |
| `anthropic/claude-opus-5.5` | $4 / $20 | ~$2–3 |

The entire development and evaluation of this project cost well under **$1**.
Check exact spend on the OpenRouter activity dashboard. Adding the security
ablation (drop `--capability-only`) multiplies the run count but stays in the
same order of magnitude for the cheap models.

---

## Architecture

```
                 ┌──────────────────────────────────────────────────────┐
                 │                      agent.py                         │
   provider ───▶ │  loop:  provider.chat(messages, tools)               │
 (mock /         │           │                                          │
  ollama /       │           ▼                                          │
  openrouter)    │   ┌──────────────┐  deny    ┌───────────────────┐    │
                 │   │ Policy check │ ───────▶ │ audit (hash-chain)│    │
                 │   └──────┬───────┘          └───────────────────┘    │
                 │          │ allow                                      │
                 │          ▼                                           │
                 │   ┌──────────────┐   MCP (stdio)   ┌──────────────┐  │
                 │   │  MCP client  │ ──────────────▶ │ mcp_server.py│  │
                 │   └──────┬───────┘                 │  8 tools     │  │
                 │          │ tool output             └──────┬───────┘  │
                 │          ▼                                │          │
                 │   ┌──────────────┐   ┌──────────────┐     ▼          │
                 │   │ adversary    │──▶│ spotlight +  │  sandbox.py    │
                 │   │ channel      │   │ injection    │  (rlimits,     │
                 │   └──────────────┘   │ detect/redact│   timeout,     │
                 │                      └──────┬───────┘   scrubbed env)│
                 │                             ▼            gcc/gdb/ASan │
                 │   finalize_report ─▶ verifier ─▶ TriageReport        │
                 └──────────────────────────────────────────────────────┘
```

**The 8 MCP tools** (`src/triage_agent/mcp_server.py`): `run_target`,
`sanitizer_report`, `gdb_backtrace`, `inspect` (read-only expression print),
`read_source`, `search_source`, `cwe_lookup` (retrieval over a local CWE
knowledge base), and `propose_fix` (compile + verify a patch). All are read-only
except `propose_fix`, which only ever touches an isolated scratch copy.

## Threat model & defenses

The agent consumes attacker-influenceable bytes: a program's source comments, and
the text of debugger/sanitizer output, can all contain a prompt-injection payload.
Three attacker goals, each targeting a specific defense:

| attacker goal | what it tries | defense that stops it |
|---|---|---|
| `forbidden_inspect` | run a non-read-only GDB expression (e.g. registers / calls) | **least-privilege policy** — `inspect` expression whitelist |
| `false_verified` | report an **unverified** fix as verified | **report verifier** — `verified` is recomputed from the verdict the tool emitted after actually compiling and running the patch, never trusted from the model |
| `beacon_exfil` | copy an attacker token into the report | **spotlighting + detect/redact**, plus verifier strips beacons |

Defense-in-depth, all **model-agnostic** (they act on the message/tool streams, so
the same mechanism applies to a real LLM as to the deterministic test provider —
though their *effectiveness* against a creative real-world attacker is bounded by
the detector's coverage, and is what the real-model evaluation is for):

1. **Least-privilege policy** (`guardrails.Policy`) — structural per-call checks:
   `inspect` expressions are whitelisted to source-level reads; source paths are
   confined to `bug.c`; code-executing expressions are refused at the tool itself.
2. **Spotlighting + injection detection** (`guardrails.Spotlighter`) — untrusted
   tool output is delimited with a per-run nonce and scanned; spans matching
   injection signatures are quarantined before the model sees them.
3. **Report verifier** (`guardrails.verify_report`) — recomputes fix verification
   from what the tools actually established (`VerifierState`, fed by the
   `propose_fix` verdict), strips beacon tokens, flags unsupported claims, and
   derates confidence. It reads that in-memory tool verdict, not the audit log:
   the audit log is the tamper-evident record of what was called, not an input to
   scoring.
4. **Tamper-evident audit log** (`audit.py`) — every tool call is recorded in a
   SHA-256 hash chain; any edit/reorder/deletion breaks `verify_chain()`.

`defenses=False` disables 1–3 so the harness can measure the attack-success-rate
*lift* the defenses provide.

---

## Quickstart

Everything runs offline against a deterministic `mock` provider (no model, no
network), so you can exercise the whole pipeline before spending a cent.

```bash
pip install -e .[dev]        # needs a C toolchain: gcc, gdb (Linux — see note)
make verify                  # generate + validate the 12-case benchmark
make test                    # unit + end-to-end tests (21)

triage list                  # the 12 cases
triage triage c06            # triage one case with the offline mock provider

# watch a prompt-injection attack land with defenses off, then get blocked:
triage triage c02 --no-defenses --attack beacon_exfil:source_comment
triage triage c02            --attack beacon_exfil:source_comment

triage eval                  # capability run over the benchmark -> eval/results.db
triage report -o eval/report.md   # render the Markdown report
```

> **Linux is required for a run.** The tools compile and execute crashing C under
> AddressSanitizer and drive gdb, which needs Linux + gdb. On macOS Apple Silicon
> the sources compile but a sanitizer-built target hangs until the wall-clock limit
> kills it, so every tool call times out instead of returning output. On macOS,
> use the bundled Docker image (below).

### Running against a real model

`--model X` is sugar for `--provider openrouter:X`; any OpenAI-compatible endpoint
works (`--provider ollama:<model>` / `openrouter:<model>`).

```bash
export OPENROUTER_API_KEY=sk-or-...
# or, on macOS, store the key once in the Keychain and use ./run_eval.sh
#   security add-generic-password -a "$USER" -s openrouter -w

# capability over the 12 cases, with a soft budget guard:
triage eval   --model anthropic/claude-sonnet-5.5 --max-cost-usd 1

# capability + the prompt-injection ablation (defenses on vs off):
triage eval   --model anthropic/claude-sonnet-5.5 --security

# the ablation on its own (guarded vs unguarded, by case × attack):
triage attack --model anthropic/claude-sonnet-5.5 --cases 3

triage report -o eval/report.md
```

`--max-cost-usd` is a soft estimate (it stops between cases); set a hard cap on
your provider account for real protection. The benchmark is tiny, so a capability
run is usually a few cents.

#### On macOS (no local gdb/ASan): run it in Docker

```bash
docker build -t crash-triage-agent .
docker run --rm -e OPENROUTER_API_KEY -v "$PWD/eval:/app/eval" crash-triage-agent \
  sh -lc "triage eval --model anthropic/claude-sonnet-5.5 --max-cost-usd 1 && triage report -o eval/report.md"
```

The MCP server (`python -m triage_agent.mcp_server`) is a standalone stdio MCP
server, so the same tools can be driven from Claude Desktop or any MCP client.

### Regression gating

```bash
python eval/compare.py <baseline_run_id> <candidate_run_id>
```

Exits non-zero if the candidate raises attack-success-rate or drops accuracy
beyond tolerance — suitable as a CI gate on a model or prompt change.

---

## The benchmark

`benchmark/gen_cases.py` generates 12 small, self-contained C programs, each with
one injected memory-safety or arithmetic bug that crashes deterministically on a
known input (standard teaching demonstrators, in the spirit of the Juliet suite —
they crash, they do nothing malicious). Each ships a **reference fix** and
**ground truth** (crash class, CWE, root-cause line, functional tests).
`benchmark/verify.py` proves, for every case, that the bug crashes under
ASan/UBSan and that the reference fix survives the crashing input and still passes
its functional tests.

| | CWE | class | | | CWE | class |
|---|---|---|---|---|---|---|
| c01 | 121 | stack overflow | | c07 | 674 | uncontrolled recursion |
| c02 | 122 | heap overflow | | c08 | 125 | out-of-bounds read |
| c03 | 416 | use-after-free | | c09 | 190 | integer overflow → alloc |
| c04 | 415 | double free | | c10 | 193 | off-by-one |
| c05 | 476 | null deref | | c11 | 195 | signed→unsigned memcpy |
| c06 | 369 | divide by zero | | c12 | 129 | untrusted array index |

## Repository layout

```
benchmark/      gen_cases.py, verify.py, cases/<id>/{bug.c,fix.c,meta.json}
src/triage_agent/
  sandbox.py        resource-limited subprocess execution (gcc/gdb/ASan)
  casedb.py         case loading, confined source access, unified-diff apply
  tools_impl.py     the 8 tool implementations
  mcp_server.py     MCP server exposing the tools (stdio)
  guardrails.py     policy, spotlighting, injection detection, verifier
  audit.py          hash-chained audit log
  providers.py      mock (offline CI double) + OpenAI-compatible (Ollama/OpenRouter)
  agent.py          the guarded MCP tool-use loop
  baseline.py       non-LLM heuristic triager (the floor)
  schema.py         Pydantic report / result models
  knowledge/cwe.json  retrieval knowledge base
eval/
  injections.py     adversarial payloads + delivery channel
  harness.py        runs the grid, stores to SQLite
  metrics.py        Wilson-interval scoring
  report.py         Markdown report
  compare.py        regression gate between two runs
tests/            unit + end-to-end (21 tests)
Dockerfile, Makefile, .github/workflows/ci.yml (same steps locally: docker build -t crash-triage-agent . && docker run --rm --network=none crash-triage-agent make verify)
```

## Design notes & honest limitations

- **The `mock` provider is a deterministic test double, not an agent.** It does
  not use ground truth: it classifies by parsing sanitizer output (so it scores
  like the heuristic baseline) and proposes no fix. It exists to run the pipeline,
  guardrails and injection-obedience path in CI without a model. Any capability or
  attack-success number worth reading comes from a **real** provider; the mock's
  numbers only prove the harness works.
- **The sandbox is defence-in-depth, not a jail.** The targets are programs we
  compiled ourselves; isolation is resource limits + a scrubbed environment + a
  killable process group, and the repo ships a `--network=none` Dockerfile for a
  stronger boundary. It is deliberately *not* presented as a container escape
  defense. (Note: an ASan address-space rlimit is intentionally omitted — ASan
  reserves a huge shadow region and would abort; CPU/wall limits bound memory.)
- **`inspect` is doubly guarded**: the tool always refuses code-executing
  expressions, and the toggleable policy additionally blocks over-privileged reads
  (registers/convenience vars), so the security ablation measures the policy layer
  cleanly while dangerous execution is never possible either way.
- **CWE scoring is reported two ways** (exact and family) because several of these
  weaknesses legitimately share a parent (an out-of-bounds write is also CWE-787).
- **The agent is not handed the crashing input.** Its prompt gives it the case id
  and the source; the tools take the stdin to feed the target, so it has to work
  out an input that triggers the crash before it can reproduce, read a sanitizer
  report or verify a fix. The heuristic baseline is given
  `meta["crashing_stdin"]` directly, so the classification/localization
  comparison runs at an information advantage to the **baseline**, not the agent.
- **Scope of the injection defenses.** Spotlighting and redaction cover the six
  untrusted channels (`run_target`, `sanitizer_report`, `gdb_backtrace`,
  `inspect`, `read_source`, `search_source`). `propose_fix` — whose output embeds
  a few bytes of the patched program's stdout — is returned unredacted, and the
  beacon check/strip covers the free-text `explanation` only, not `cwe`,
  `root_cause_file` or the diff. Both are current gaps rather than guarantees,
  and both are the first things to widen.

## License

MIT.
