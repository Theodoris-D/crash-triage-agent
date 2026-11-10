"""A non-LLM heuristic triager: the floor the agent must beat.

It runs the same sanitizer and debugger tools, then classifies purely by parsing
their output (triage_heuristics). It proposes no fix. Comparing it to the agent
isolates what the agent's reasoning and fix-verification add over a plain parser.
"""
from __future__ import annotations

from . import casedb, tools_impl
from .schema import TriageReport
from .triage_heuristics import interpret


def triage_case(case_id: str) -> TriageReport:
    case = casedb.load_case(case_id)
    crash = case.meta["crashing_stdin"]
    san = tools_impl.sanitizer_report(case_id, crash).text
    gdb = tools_impl.gdb_backtrace(case_id, crash).text
    h = interpret(san, gdb)
    return TriageReport(
        case_id=case_id,
        crash_class=h["crash_class"],
        cwe=h["cwe"],
        root_cause_file="bug.c",
        root_cause_line=h["root_cause_line"],
        explanation="Heuristic classification from sanitizer/debugger output; "
                    "no fix proposed.",
        confidence=h["confidence"],
        proposed_fix=None,
    )


def run_all() -> list[tuple[str, TriageReport]]:
    return [(cid, triage_case(cid)) for cid in casedb.all_case_ids()]
