"""Concrete debugging tools.

Each function is a thin, deterministic capability over one case: run the target,
get a backtrace, inspect a value, read/search source, retrieve CWE knowledge, or
compile-and-verify a candidate fix. They return a `ToolOutput` carrying the text
the model will see plus two pieces of metadata the guardrail layer needs:

  * `untrusted` -- the text contains case-controlled content (source, debugger or
    sanitizer output) and must be spotlighted / scanned before the model sees it.
  * `structured` -- tool-authored facts (e.g. whether a fix really verified) that
    the agent and verifier trust, because the tool computed them from execution.

Policy enforcement and spotlighting live in guardrails.py; this module is the
ground truth of what each tool *does*.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re

from . import casedb, sandbox
from .config import KNOWLEDGE_DIR


@dataclasses.dataclass
class ToolOutput:
    text: str
    untrusted: bool = False
    structured: dict | None = None
    error: bool = False


# Tool-level backstop: always refuse expressions that could execute code or
# break out of a print, regardless of policy. The stricter *whitelist* (which
# also rejects over-privileged reads such as gdb registers/convenience vars) is
# the toggleable Policy in guardrails.py, so the security ablation can measure
# that layer separately.
_DANGEROUS_EXPR = re.compile(
    r"""[;"'`={}\n]|system|exec|popen|call\s|\$\(|(?<![\w.])(?!sizeof\b)[A-Za-z_]\w*\s*\(""",
    re.I)


def run_target(case_id: str, stdin: str = "") -> ToolOutput:
    case = casedb.load_case(case_id)
    r = case.run_bug(stdin)
    verdict = ("timed out" if r.timed_out else
               f"killed by {r.signal_name} (signal {r.signal})" if r.signal
               else f"exited {r.exit_code}")
    head = (f"target {case_id}: {verdict}\n"
            f"--- stdout ---\n{r.stdout.strip()[:1500]}\n"
            f"--- stderr (first lines) ---\n" +
            "\n".join(r.stderr.strip().splitlines()[:8]))
    return ToolOutput(head, untrusted=True,
                      structured={"crashed": r.crashed, "signal": r.signal_name,
                                  "exit_code": r.exit_code, "timed_out": r.timed_out})


def sanitizer_report(case_id: str, stdin: str = "") -> ToolOutput:
    """Full AddressSanitizer/UBSan diagnostic for the crashing input."""
    case = casedb.load_case(case_id)
    r = case.run_bug(stdin)
    if not r.stderr.strip():
        return ToolOutput(f"no sanitizer output; target {verdict_of(r)}", untrusted=True,
                          structured={"has_report": False})
    return ToolOutput(r.stderr.strip(), untrusted=True, structured={"has_report": True})


def verdict_of(r: sandbox.RunResult) -> str:
    if r.timed_out:
        return "timed out"
    if r.signal:
        return f"killed by {r.signal_name}"
    return f"exited {r.exit_code}"


def gdb_backtrace(case_id: str, stdin: str = "") -> ToolOutput:
    case = casedb.load_case(case_id)
    cr = case.compiled_bug()
    if not cr.ok or cr.binary is None:
        return ToolOutput(f"compile error:\n{cr.stderr}", error=True)
    r = sandbox.run_under_gdb(cr.binary, stdin,
                              ["run", "bt 20", "frame", "info locals", "info args"])
    return ToolOutput(r.stdout.strip() or r.stderr.strip() or "<no gdb output>",
                      untrusted=True)


def inspect(case_id: str, expr: str, stdin: str = "", frame: int = 0) -> ToolOutput:
    """Print a C expression at a stack frame of the crash (read-only)."""
    expr = expr.strip()
    if not expr or len(expr) > 80 or _DANGEROUS_EXPR.search(expr):
        return ToolOutput(f"rejected expression {expr!r}: may execute code or is "
                          f"not a simple read-only expression", error=True)
    case = casedb.load_case(case_id)
    cr = case.compiled_bug()
    if not cr.ok or cr.binary is None:
        return ToolOutput(f"compile error:\n{cr.stderr}", error=True)
    cmds = ["run", f"frame {int(frame)}", f"print {expr}"]
    r = sandbox.run_under_gdb(cr.binary, stdin, cmds)
    # Keep only the lines that look like gdb print output.
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    tail = "\n".join(lines[-12:]) if lines else (r.stderr.strip() or "<no output>")
    return ToolOutput(tail, untrusted=True)


def read_source(case_id: str, path: str = "bug.c", start: int = 1,
                end: int = 100000) -> ToolOutput:
    case = casedb.load_case(case_id)
    try:
        text = case.source_lines(path, start, end)
    except casedb.CaseError as e:
        return ToolOutput(str(e), error=True)
    return ToolOutput(text, untrusted=True)


def search_source(case_id: str, pattern: str, path: str = "bug.c") -> ToolOutput:
    case = casedb.load_case(case_id)
    try:
        text = case.read_source(path)
    except casedb.CaseError as e:
        return ToolOutput(str(e), error=True)
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return ToolOutput(f"bad pattern: {e}", error=True)
    hits = [f"{i:4d}| {ln}" for i, ln in enumerate(text.splitlines(), 1)
            if rx.search(ln)]
    return ToolOutput("\n".join(hits) if hits else "<no matches>", untrusted=True)


_RETRIEVER = None
_DOCS = None


def _retriever():
    """Pick the cwe_lookup backend once per process.

    TRIAGE_CWE_RETRIEVER=keyword (default, dependency-free, used by CI),
    dense (Hugging Face bge-small-en-v1.5 embeddings in ChromaDB) or hybrid
    (BM25 + dense, reciprocal-rank fusion: the best retriever in the evaluation). Both search the
    18 curated entries: eval/retrieval_report.md shows that the full MITRE
    catalogue (956 entries) makes every retriever worse on these queries. If the
    optional `rag` dependencies are missing, dense falls back to keyword.
    """
    global _RETRIEVER, _DOCS
    if _RETRIEVER is None:
        from . import retrieval
        _DOCS = {d.cwe: d for d in retrieval.load_curated(KNOWLEDGE_DIR / "cwe.json")}
        docs = list(_DOCS.values())
        mode = os.environ.get("TRIAGE_CWE_RETRIEVER", "keyword").lower()
        try:
            if mode == "dense":
                _RETRIEVER = retrieval.DenseRetriever(docs, "BAAI/bge-small-en-v1.5")
            elif mode == "hybrid":
                _RETRIEVER = retrieval.HybridRetriever(
                    retrieval.BM25Retriever(docs),
                    retrieval.DenseRetriever(docs, "BAAI/bge-small-en-v1.5"))
            else:
                _RETRIEVER = retrieval.KeywordRetriever(docs)
        except ImportError:
            _RETRIEVER = retrieval.KeywordRetriever(docs)
    return _RETRIEVER


def cwe_lookup(query: str, k: int = 3) -> ToolOutput:
    """Retrieve the most relevant CWE entries (trusted internal knowledge base)."""
    hits = _retriever().search(query, max(1, k))
    if not hits:
        return ToolOutput("<no matching CWE entries>")
    out = []
    for cwe, _ in hits:
        e = _DOCS[cwe]
        out.append(f"{e.cwe} {e.name}\n  {e.summary}\n  fix: {e.fix_hint}")
    return ToolOutput("\n".join(out), untrusted=False)


def propose_fix(case_id: str, unified_diff: str) -> ToolOutput:
    """Apply a unified diff to bug.c, compile it, and verify it.

    The verdict ('verified') is computed here from real execution: the patched
    program must (a) compile, (b) NOT crash on the crashing input, and (c) pass
    every functional test. The model cannot assert this itself.
    """
    case = casedb.load_case(case_id)
    cr, _patched = case.compile_patched(unified_diff)
    if not cr.ok or cr.binary is None:
        return ToolOutput(f"fix did not compile:\n{cr.stderr[:1500]}", error=True,
                          structured={"compile_ok": False, "verified": False,
                                      "stopped_crash": False,
                                      "functional_pass": 0, "functional_total": 0})
    meta = case.meta
    crash_run = sandbox.run(cr.binary, meta["crashing_stdin"])
    # A crash is a signal/timeout (incl. the sanitizer's SIGABRT), NOT a clean
    # non-zero exit: a fix that rejects the bad input with `return 1` has stopped
    # the crash. Using `crashed` here (which also counts exit != 0) wrongly marked
    # correct fixes as unverified -- see REVIEW.md.
    stopped = not crash_run.crashed_by_signal
    fpass = 0
    ftests = meta["functional_tests"]
    details = []
    for t in ftests:
        rr = sandbox.run(cr.binary, t["stdin"])
        ok = (not rr.crashed) and (t["expect_substr"] in rr.stdout)
        fpass += int(ok)
        details.append(f"  input {t['stdin']!r}: "
                       f"{'pass' if ok else 'FAIL'} (got {rr.stdout.strip()[:40]!r})")
    verified = bool(stopped and fpass == len(ftests))
    struct = {"compile_ok": True, "stopped_crash": stopped, "verified": verified,
              "functional_pass": fpass, "functional_total": len(ftests)}
    text = (f"compile: ok\n"
            f"crashing input now: {'no longer crashes' if stopped else 'STILL CRASHES'}\n"
            f"functional tests: {fpass}/{len(ftests)} passed\n" + "\n".join(details) +
            f"\nVERIFIED: {verified}\n"
            # Machine-readable, tool-authored verdict the agent trusts.
            f"__FIX_VERDICT__ {json.dumps(struct)}")
    return ToolOutput(text, untrusted=False, structured=struct)


# Registry used by the MCP server and the agent. Each entry: (callable, untrusted
# default, one-line description, json schema of arguments).
TOOLS = {
    "run_target": run_target,
    "sanitizer_report": sanitizer_report,
    "gdb_backtrace": gdb_backtrace,
    "inspect": inspect,
    "read_source": read_source,
    "search_source": search_source,
    "cwe_lookup": cwe_lookup,
    "propose_fix": propose_fix,
}
