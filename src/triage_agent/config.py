"""Project paths and sandbox limits in one place."""
from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass

# Repo layout:  <root>/src/triage_agent/config.py  ->  root is parents[2]
ROOT = pathlib.Path(__file__).resolve().parents[2]
BENCHMARK_DIR = ROOT / "benchmark"
CASES_DIR = BENCHMARK_DIR / "cases"
KNOWLEDGE_DIR = pathlib.Path(__file__).resolve().parent / "knowledge"

# Where per-run scratch (compiled binaries, patched sources) is written.
WORK_ROOT = pathlib.Path(os.environ.get("TRIAGE_WORK", "/tmp/triage_work"))

CC = os.environ.get("CC", "cc")

ASAN_CFLAGS = [
    "-g", "-O0", "-fno-omit-frame-pointer",
    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
]

# Deterministic sanitizer behaviour: abort (SIGABRT) on first error, no leak
# scan (keeps crash signals clean), no address randomness in the report.
SANITIZER_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:handle_abort=1:"
                    "symbolize=1:print_module_map=0:log_path=stderr",
    "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
}


@dataclass(frozen=True)
class SandboxLimits:
    cpu_seconds: int = 5
    wall_seconds: float = 15.0
    # NOTE: we deliberately do NOT cap RLIMIT_AS. AddressSanitizer reserves a
    # very large virtual shadow region at startup; an address-space rlimit makes
    # it abort before main(). Memory is bounded by the CPU+wall limits instead,
    # which is sufficient for these tiny programs.
    file_size_bytes: int = 8 * 1024 * 1024
    max_procs: int = 64
    max_open_files: int = 128
    max_output_bytes: int = 64 * 1024


DEFAULT_LIMITS = SandboxLimits()

# Environment variables a target is allowed to see. Everything else (including
# any secret the operator exported) is stripped before exec.
ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "ASAN_OPTIONS", "UBSAN_OPTIONS",
                 "ASAN_SYMBOLIZER_PATH")
