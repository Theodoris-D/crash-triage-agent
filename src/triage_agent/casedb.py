"""Load benchmark cases and give tools controlled access to their files.

A `Case` exposes exactly the files the agent is allowed to see (bug.c) and never
the oracle (fix.c, meta.json). Path access is confined to the case directory so
a tool argument cannot escape via `..` or an absolute path.
"""
from __future__ import annotations

import dataclasses
import difflib
import hashlib
import json
import pathlib

from . import sandbox
from .config import CASES_DIR, WORK_ROOT, SandboxLimits, DEFAULT_LIMITS


class CaseError(Exception):
    pass


@dataclasses.dataclass
class Case:
    id: str
    dir: pathlib.Path
    meta: dict  # ground truth; agent-visible tools must NOT read this

    @property
    def bug_path(self) -> pathlib.Path:
        return self.dir / "bug.c"

    def agent_visible_files(self) -> list[str]:
        return ["bug.c"]

    def read_source(self, relpath: str) -> str:
        if relpath not in self.agent_visible_files():
            raise CaseError(f"source not available: {relpath!r}")
        return (self.dir / relpath).read_text()

    def source_lines(self, relpath: str, start: int, end: int) -> str:
        text = self.read_source(relpath)
        lines = text.splitlines()
        start = max(1, start)
        end = min(len(lines), end)
        out = []
        for i in range(start, end + 1):
            out.append(f"{i:4d}| {lines[i - 1]}")
        return "\n".join(out)

    # --- compilation / execution helpers -------------------------------------

    def _work(self) -> pathlib.Path:
        d = WORK_ROOT / self.id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def compiled_bug(self) -> sandbox.CompileResult:
        out = self._work() / "bug.asan"
        if out.exists():
            return sandbox.CompileResult(True, "", out)
        return sandbox.compile_c(self.bug_path, out)

    def compile_patched(self, unified_diff: str) -> tuple[sandbox.CompileResult, str]:
        """Apply `unified_diff` to bug.c in a scratch copy and compile it.

        Returns (compile_result, patched_source_or_error). The diff is applied
        with a tolerant internal patcher (no shelling out to `patch`), so model
        text never reaches a shell.
        """
        original = self.bug_path.read_text()
        try:
            patched = _apply_unified_diff(original, unified_diff)
        except Exception as e:  # noqa: BLE001 - surfaced to the agent as a tool error
            return sandbox.CompileResult(False, f"patch failed: {e}", None), ""
        digest = hashlib.sha256(unified_diff.encode()).hexdigest()[:12]
        src = self._work() / f"patched_{digest}.c"
        src.write_text(patched)
        out = self._work() / f"patched_{digest}.asan"
        return sandbox.compile_c(src, out), patched

    def run_bug(self, stdin: str, limits: SandboxLimits = DEFAULT_LIMITS):
        cr = self.compiled_bug()
        if not cr.ok or cr.binary is None:
            raise CaseError(f"bug.c failed to compile: {cr.stderr}")
        return sandbox.run(cr.binary, stdin, limits=limits)


def load_case(case_id: str) -> Case:
    d = CASES_DIR / case_id
    meta_path = d / "meta.json"
    if not meta_path.exists():
        # Tolerate a descriptive suffix a model may append to the neutral id
        # (e.g. 'c01_stack_buffer_overflow' -> 'c01'), so a stray tool argument
        # does not abort the whole run.
        short = case_id.split("_", 1)[0]
        alt = CASES_DIR / short / "meta.json"
        if short != case_id and alt.exists():
            d, meta_path = CASES_DIR / short, alt
        else:
            raise CaseError(f"unknown case: {case_id!r}")
    return Case(id=d.name, dir=d, meta=json.loads(meta_path.read_text()))


def all_case_ids() -> list[str]:
    if not CASES_DIR.exists():
        return []
    return sorted(p.name for p in CASES_DIR.iterdir()
                  if p.is_dir() and (p / "meta.json").exists())


def make_unified_diff(original: str, patched: str, path: str = "bug.c") -> str:
    diff = difflib.unified_diff(original.splitlines(keepends=True),
                               patched.splitlines(keepends=True),
                               fromfile=f"a/{path}", tofile=f"b/{path}")
    return "".join(diff)


def _apply_unified_diff(original: str, diff_text: str) -> str:
    """Apply a unified diff using only its hunk bodies.

    Robust to missing/looser @@ headers: we match each hunk's context+removed
    lines against the source and splice in the added lines. Good enough for the
    small single-file patches the agent produces, and it never runs a subprocess.
    """
    src_lines = original.splitlines()
    hunks = _parse_hunks(diff_text)
    if not hunks:
        raise ValueError("no hunks found in diff")
    result = list(src_lines)
    # Apply from the last hunk to the first so earlier edits don't shift offsets.
    for hunk in sorted(hunks, key=lambda h: _locate(result, h), reverse=True):
        at = _locate(result, hunk)
        old = [t for tag, t in hunk if tag in (" ", "-")]
        new = [t for tag, t in hunk if tag in (" ", "+")]
        result[at:at + len(old)] = new
    return "\n".join(result) + ("\n" if original.endswith("\n") else "")


def _parse_hunks(diff_text: str):
    hunks = []
    cur = None
    for raw in diff_text.splitlines():
        if raw.startswith("@@"):
            cur = []
            hunks.append(cur)
            continue
        if raw.startswith(("--- ", "+++ ", "diff ", "index ")):
            continue
        if cur is None:
            # Allow a bare diff with no @@ header: treat +/-/space lines as one hunk.
            if raw[:1] in ("+", "-", " "):
                cur = []
                hunks.append(cur)
            else:
                continue
        if raw[:1] in ("+", "-", " "):
            cur.append((raw[0], raw[1:]))
        elif raw == "":
            cur.append((" ", ""))
    return [h for h in hunks if h]


def _locate(src_lines: list[str], hunk) -> int:
    old = [t for tag, t in hunk if tag in (" ", "-")]
    if not old:
        return len(src_lines)
    # exact match first
    for i in range(0, len(src_lines) - len(old) + 1):
        if src_lines[i:i + len(old)] == old:
            return i
    # whitespace-insensitive fallback
    norm = [s.strip() for s in old]
    for i in range(0, len(src_lines) - len(old) + 1):
        if [s.strip() for s in src_lines[i:i + len(old)]] == norm:
            return i
    raise ValueError("hunk context not found in source")
