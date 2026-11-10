"""Parse sanitizer / debugger text into a best-effort triage.

Used by the non-LLM baseline (baseline.py) and as a parsing helper. It is
deliberately limited: a pure sanitizer parser can name the error family and the
faulting line, but it cannot always pick the precise CWE (e.g. tell an
out-of-bounds *read* from an off-by-one *write* when UBSan reports only "index
out of bounds"). That gap is exactly what an agent that reads the source is
meant to close.
"""
from __future__ import annotations

import re

from .schema import CrashClass

# AddressSanitizer error token -> (crash class, CWE)
_ASAN = {
    "stack-buffer-overflow": (CrashClass.STACK_BUFFER_OVERFLOW, "CWE-121"),
    "heap-buffer-overflow": (CrashClass.HEAP_BUFFER_OVERFLOW, "CWE-122"),
    "global-buffer-overflow": (CrashClass.GLOBAL_BUFFER_OVERFLOW, "CWE-125"),
    "heap-use-after-free": (CrashClass.HEAP_USE_AFTER_FREE, "CWE-416"),
    "stack-overflow": (CrashClass.STACK_OVERFLOW, "CWE-674"),
    "negative-size-param": (CrashClass.MEMCPY_OVERFLOW, "CWE-195"),
}


def interpret(sanitizer_text: str, gdb_text: str = "") -> dict:
    text = sanitizer_text or ""
    crash_class = CrashClass.UNKNOWN
    cwe = "CWE-unknown"
    confidence = 0.3

    m = re.search(r"AddressSanitizer: ([a-z\-]+)", text)
    if m and m.group(1) in _ASAN:
        crash_class, cwe = _ASAN[m.group(1)]
        confidence = 0.8
    elif "attempting double-free" in text or "double-free" in text:
        crash_class, cwe = CrashClass.DOUBLE_FREE, "CWE-415"
        confidence = 0.85
    elif re.search(r"division by zero", text):
        crash_class, cwe = CrashClass.INTEGER_DIVIDE_BY_ZERO, "CWE-369"
        confidence = 0.85
    elif re.search(r"null pointer|member access within null", text):
        crash_class, cwe = CrashClass.SEGV, "CWE-476"
        confidence = 0.8
    elif re.search(r"index -?\d+ out of bounds", text):
        # Can see it is an array-index fault, but not read/write or the exact
        # variant -- the honest limit of a pure parser.
        crash_class, cwe = CrashClass.UNKNOWN, "CWE-129"
        confidence = 0.45

    line = _first_bug_line(text) or _first_bug_line(gdb_text)
    return {"crash_class": crash_class, "cwe": cwe,
            "root_cause_line": line or 1, "confidence": confidence}


def _first_bug_line(text: str) -> int | None:
    # The first reference to our source file is the user frame of interest.
    m = re.search(r"bug\.c:(\d+)", text or "")
    return int(m.group(1)) if m else None
