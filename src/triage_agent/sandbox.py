"""Run untrusted-ish native code under resource limits.

The targets here are programs we compiled ourselves from known source, so this
is defence in depth rather than a true adversarial jail: a scrubbed environment,
POSIX resource limits (CPU, file size, procs, fds, no core dumps), a wall-clock
timeout that kills the whole process group, and bounded captured output. It is
the single choke point through which every tool executes a binary.

Not a container. The repo ships a Dockerfile for CI isolation; this module is
what runs inside it (or directly, for local use).
"""
from __future__ import annotations

import dataclasses
import os
import resource
import signal
import subprocess
import sys
import pathlib

from .config import (CC, ASAN_CFLAGS, SANITIZER_ENV, ENV_ALLOWLIST,
                     SandboxLimits, DEFAULT_LIMITS)


@dataclasses.dataclass
class CompileResult:
    ok: bool
    stderr: str
    binary: pathlib.Path | None


@dataclasses.dataclass
class RunResult:
    exit_code: int | None       # None if killed by signal or timeout
    signal: int | None          # POSIX signal number if killed, else None
    signal_name: str | None
    timed_out: bool
    stdout: str
    stderr: str
    truncated: bool

    @property
    def crashed(self) -> bool:
        return self.timed_out or self.signal is not None or (self.exit_code not in (0, None))

    @property
    def crashed_by_signal(self) -> bool:
        # A real memory-safety/arith crash is a fatal signal or a timeout (the
        # sanitizers abort via SIGABRT). A clean non-zero exit is NOT a crash.
        return self.timed_out or self.signal is not None


def _scrubbed_env(extra: dict | None = None) -> dict:
    env = {k: os.environ[k] for k in ENV_ALLOWLIST if k in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin")
    env.update(SANITIZER_ENV)
    if extra:
        env.update(extra)
    return env


def _preexec(limits: SandboxLimits):
    def apply():
        resource.setrlimit(resource.RLIMIT_CPU,
                           (limits.cpu_seconds, limits.cpu_seconds + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE,
                           (limits.file_size_bytes, limits.file_size_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        try:
            resource.setrlimit(resource.RLIMIT_NPROC,
                               (limits.max_procs, limits.max_procs))
        except (ValueError, OSError):
            pass
        resource.setrlimit(resource.RLIMIT_NOFILE,
                           (limits.max_open_files, limits.max_open_files))
    return apply


def _sandbox_popen_kwargs(limits: SandboxLimits) -> dict:
    """Start the child in its own session (so a timeout can kill the whole group)
    and, on Linux, apply resource limits via preexec_fn.

    preexec_fn is deliberately skipped on macOS: forking a CoreFoundation/libdispatch
    process and running Python before exec can deadlock the child, which shows up as
    every sandboxed run timing out. `start_new_session` does setsid in C (fork-safe),
    and the wall-clock timeout + process-group kill still bound execution there.
    """
    kw = {"start_new_session": True}
    if sys.platform != "darwin":
        kw["preexec_fn"] = _preexec(limits)
    return kw


def compile_c(src: pathlib.Path, out: pathlib.Path,
              cflags: list[str] | None = None) -> CompileResult:
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [CC, *(cflags or ASAN_CFLAGS), str(src), "-o", str(out)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        return CompileResult(False, p.stderr, None)
    return CompileResult(True, p.stderr, out)


def run(binary: pathlib.Path, stdin: str = "", *,
        limits: SandboxLimits = DEFAULT_LIMITS,
        extra_env: dict | None = None,
        cwd: pathlib.Path | None = None) -> RunResult:
    proc = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=_scrubbed_env(extra_env),
        cwd=str(cwd) if cwd else None,
        **_sandbox_popen_kwargs(limits),
    )
    timed_out = False
    try:
        out, err = proc.communicate(input=stdin, timeout=limits.wall_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
    rc = proc.returncode
    sig = None
    signame = None
    exit_code: int | None = rc
    if rc is not None and rc < 0:
        sig = -rc
        signame = signal.Signals(sig).name if sig in set(s.value for s in signal.Signals) else f"SIG{sig}"
        exit_code = None
    if timed_out:
        exit_code = None

    trunc = False
    limit = limits.max_output_bytes
    if len(out) > limit:
        out, trunc = out[:limit] + "\n<...truncated...>", True
    if len(err) > limit:
        err, trunc = err[:limit] + "\n<...truncated...>", True

    return RunResult(exit_code=exit_code, signal=sig, signal_name=signame,
                     timed_out=timed_out, stdout=out, stderr=err, truncated=trunc)


def run_under_gdb(binary: pathlib.Path, stdin: str, gdb_commands: list[str], *,
                  limits: SandboxLimits = DEFAULT_LIMITS,
                  extra_env: dict | None = None) -> RunResult:
    """Drive a target under gdb in batch mode and capture gdb's output.

    gdb shares its stdin with the inferior, so piping `stdin` feeds the program.
    The command list is fixed by the caller (never built from model text).
    """
    ex: list[str] = []
    for c in gdb_commands:
        ex += ["-ex", c]
    cmd = ["gdb", "-q", "-nx", "-batch",
           "-ex", "set pagination off", "-ex", "set confirm off",
           # Defence in depth: never let an inspected expression call a function
           # in the target (that would execute code). The policy/tool backstop
           # already reject call-shaped expressions; this is the third layer.
           "-ex", "set may-call-functions off",
           *ex, "--args", str(binary)]
    # gdb itself must not inherit the sanitizer's abort handler noise on stdout.
    env = _scrubbed_env(extra_env)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env,
                                **_sandbox_popen_kwargs(dataclasses.replace(limits, cpu_seconds=limits.cpu_seconds + 10)))
    except FileNotFoundError:
        return RunResult(exit_code=127, signal=None, signal_name=None,
                         timed_out=False, stdout="",
                         stderr="gdb not found on this host; use the Docker image "
                                "or install gdb for backtrace/inspect tools",
                         truncated=False)
    timed_out = False
    try:
        out, err = proc.communicate(input=stdin, timeout=limits.wall_seconds + 10)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
    limit = limits.max_output_bytes
    trunc = False
    if len(out) > limit:
        out, trunc = out[:limit] + "\n<...truncated...>", True
    return RunResult(exit_code=proc.returncode, signal=None, signal_name=None,
                     timed_out=timed_out, stdout=out, stderr=err[:limit],
                     truncated=trunc)
