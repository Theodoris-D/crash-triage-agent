"""Typed data models shared across the agent, tools and evaluation.

The report schema is the contract the agent must satisfy. Fields that can only
be established by *running* code (whether a fix actually compiles and stops the
crash) are marked as tool-owned: the model proposes, the tooling disposes, and
the verifier (guardrails.py) refuses to trust model-asserted success.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class CrashClass(str, Enum):
    STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
    HEAP_BUFFER_OVERFLOW = "heap-buffer-overflow"
    GLOBAL_BUFFER_OVERFLOW = "global-buffer-overflow"
    HEAP_USE_AFTER_FREE = "heap-use-after-free"
    DOUBLE_FREE = "double-free"
    SEGV = "SEGV"
    INTEGER_DIVIDE_BY_ZERO = "integer-divide-by-zero"
    STACK_OVERFLOW = "stack-overflow"
    MEMCPY_OVERFLOW = "memcpy-overflow"
    UNKNOWN = "unknown"


class FixProposal(BaseModel):
    """A candidate patch. `unified_diff` is the only model-authored field.

    Everything else is filled in by the `propose_fix` tool after it compiles
    and runs the patched program, so the agent cannot simply claim success.
    """
    unified_diff: str = Field(description="A unified diff against bug.c.")
    verified: bool = Field(default=False,
                           description="Tool-owned: fix compiled and stopped the crash.")
    stopped_crash: bool = Field(default=False, description="Tool-owned.")
    functional_pass: int = Field(default=0, description="Tool-owned.")
    functional_total: int = Field(default=0, description="Tool-owned.")
    compile_ok: bool = Field(default=False, description="Tool-owned.")


class TriageReport(BaseModel):
    case_id: str
    crash_class: CrashClass
    cwe: str = Field(description="Canonical identifier, e.g. 'CWE-121'.")
    root_cause_file: str = Field(description="Source file of the root cause.")
    root_cause_line: int = Field(ge=1, description="1-based line of the root cause.")
    explanation: str = Field(description="One short paragraph, plain language.")
    confidence: float = Field(ge=0.0, le=1.0)
    proposed_fix: FixProposal | None = None

    # Verifier-owned annotations (never set by the model).
    verifier_flags: list[str] = Field(default_factory=list)
    verified_confidence: float | None = None


class ToolCallRecord(BaseModel):
    """One entry in the audit trail."""
    index: int
    tool: str
    arguments_redacted: dict
    args_sha256: str
    output_sha256: str
    output_bytes: int
    policy_decision: str  # "allow" | "deny:<reason>" | "sanitized"
    injection_flags: list[str] = Field(default_factory=list)
    duration_ms: int
    prev_hash: str
    entry_hash: str


class CaseResult(BaseModel):
    """Everything the harness records for one (case, condition) run."""
    run_id: str
    case_id: str
    provider: str
    defenses: bool
    adversarial: bool
    attack_channel: str | None = None
    attack_goal: str | None = None

    report: TriageReport | None = None
    tool_calls: int = 0
    wall_ms: int = 0
    error: str | None = None

    # Scored against ground truth (metrics.py).
    crash_class_correct: bool | None = None
    cwe_correct: bool | None = None
    root_line_correct: bool | None = None
    fix_verified: bool | None = None

    # Security outcomes.
    injection_detected: bool | None = None
    attack_succeeded: bool | None = None
