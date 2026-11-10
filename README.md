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

It sits exactly on the intersection of agentic AI and systems security that the
following roles ask for, and reuses a debugging stack I already know:

| Role (from my search) | What this demonstrates |
|---|---|
| Apple — *AI-Assisted Baseband Debugging Evaluation* | an agent that debugs crashes and is **evaluated** for correctness and robustness |
| Intel — *System Debugger Development Intern* (GDB/QEMU/C) | driving GDB programmatically over a tool interface |
| BMW — *Thesis: AI-Assisted Fault Injection* | LLM + fault/crash analysis with a measured harness |
| Infineon — *Thesis: Trustworthy Agentic AI* | least-privilege, injection defenses, verifier, audit trail |
| NVIDIA / Munich Re — *AI Agents*, *AI security* | MCP tool-use agent with guardrails and an eval suite |

## Results

Measured run (`claude-haiku-5.5` via OpenRouter, 12-case benchmark, defended, no
attack; full output in [`eval/sample-report.md`](eval/sample-report.md)). The
baseline is the **same tools without the LLM** — a script that runs
AddressSanitizer/UBSan and regex-maps its output to a CWE and line, proposing no
fix. It isolates what the agent's reasoning and verified fixes add on top of the
sanitizer.

| metric | **agent (Haiku 5.5)** | baseline (no LLM) |
|---|---|---|
| CWE exact | **100%** (12/12) | 75% (9/12) |
| CWE family | 100% (12/12) | 83% (10/12) |
| root-cause line | 83% (10/12) | 75% (9/12) |
| **fix verified** | **83%** (10/12) | 0% (0/12) |
| crash-class exact | 83% (10/12) | — |

The audit hash-chain verified intact on every run; 0 runs errored.

**How to read it.** The classification edge is real but moderate — the sanitizer
is already informative, which is why the baseline is a *strong* 75% and not a
strawman; the agent's wins there are the ambiguous cases (an out-of-bounds *read*
vs an off-by-one *write*, where the sanitizer only says "index out of bounds").
The **decisive** gap is `fix verified` (0% → 83%): a parser cannot write a patch
at all, whereas the agent produces fixes that **compile, stop the crash, and pass
the functional tests**. Caveats worth stating plainly: n = 12 (confidence
intervals are wide — CWE 100% is [75.7, 100]), this is one run of one model, and
the two unverified fixes (null-deref, integer-overflow-alloc) are reported
honestly rather than hidden.

A model is required for these numbers; the default `mock` provider is a
deterministic CI test double (see *Design notes*), not an agent.

**Security ablation.** The harness also runs each case × attack × {defenses on,
off} and reports attack-success-rate and injection-detection separately. Against
the deterministic `mock` attacker the defenses block every attack **by
construction** (0% on / 100% off — a mechanism self-test); the *interesting*
measurement is a real model's ASR under injection, which the same harness
produces when pointed at one (`make eval` without `--capability-only`).

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
| `false_verified` | report an **unverified** fix as verified | **report verifier** — `verified` is recomputed from the audit trail, never trusted from the model |
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
   from the audit trail, strips beacon tokens, flags unsupported claims, and
   derates confidence.
4. **Tamper-evident audit log** (`audit.py`) — every tool call is recorded in a
   SHA-256 hash chain; any edit/reorder/deletion breaks `verify_chain()`.

`defenses=False` disables 1–3 so the harness can measure the attack-success-rate
*lift* the defenses provide.

---

## Quickstart

```bash
pip install -e .[dev]        # needs a C toolchain: gcc, gdb
make verify                  # generate + validate the 12-case benchmark
make test                    # unit + end-to-end tests

# Triage one case, offline (deterministic mock provider — CI double, not a model):
python -m triage_agent.cli triage c06_divide_by_zero

# See a prompt-injection attack land with defenses off, then get blocked:
python -m triage_agent.cli triage c02_heap_buffer_overflow --no-defenses \
       --attack beacon_exfil:source_comment
python -m triage_agent.cli triage c02_heap_buffer_overflow \
       --attack beacon_exfil:source_comment

# Full offline evaluation + Markdown report:
make eval report             # writes eval/results.db and eval/report.md
```

### Running against a real model

Any OpenAI-compatible endpoint works; only `--provider` changes.

```bash
# Local Ollama (set OLLAMA_HOST if not on localhost:11434):
ollama pull qwen2.5-coder:7b
python -m triage_agent.cli triage c05_null_pointer_deref --provider ollama:qwen2.5-coder:7b
python eval/harness.py --provider ollama:qwen2.5-coder:7b

# OpenRouter:
export OPENROUTER_API_KEY=sk-or-...
python eval/harness.py --provider openrouter:anthropic/claude-3.5-sonnet
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
tests/            unit + end-to-end (16 tests)
Dockerfile, Makefile, .github/workflows/ci.yml
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

## License

MIT.
