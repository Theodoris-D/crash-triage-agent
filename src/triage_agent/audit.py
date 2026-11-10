"""Tamper-evident audit trail of every tool call.

Each record carries the SHA-256 of the previous record, so any later edit,
deletion or reordering breaks the chain and `verify_chain()` fails. The log
stores hashes of arguments and outputs rather than their full text, keeping it
compact and avoiding re-persisting untrusted content.
"""
from __future__ import annotations

import hashlib
import json

from .schema import ToolCallRecord

GENESIS = "0" * 64


def _sha(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha256(s).hexdigest()


def _redact_args(args: dict) -> dict:
    """Keep argument shapes and small scalars; truncate long strings."""
    out = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 120:
            out[k] = v[:120] + f"…(+{len(v) - 120})"
        else:
            out[k] = v
    return out


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[ToolCallRecord] = []

    @property
    def _last_hash(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS

    def record(self, *, tool: str, arguments: dict, output: str,
               policy_decision: str, injection_flags: list[str],
               duration_ms: int) -> ToolCallRecord:
        prev = self._last_hash
        args_hash = _sha(json.dumps(arguments, sort_keys=True, default=str))
        out_hash = _sha(output)
        index = len(self.entries)
        body = json.dumps({
            "index": index, "tool": tool, "args_sha256": args_hash,
            "output_sha256": out_hash, "output_bytes": len(output.encode()),
            "policy_decision": policy_decision,
            "injection_flags": sorted(injection_flags), "prev_hash": prev,
        }, sort_keys=True)
        entry_hash = _sha(body)
        rec = ToolCallRecord(
            index=index, tool=tool, arguments_redacted=_redact_args(arguments),
            args_sha256=args_hash, output_sha256=out_hash,
            output_bytes=len(output.encode()), policy_decision=policy_decision,
            injection_flags=sorted(injection_flags), duration_ms=duration_ms,
            prev_hash=prev, entry_hash=entry_hash)
        self.entries.append(rec)
        return rec

    def verify_chain(self) -> bool:
        prev = GENESIS
        for e in self.entries:
            if e.prev_hash != prev:
                return False
            body = json.dumps({
                "index": e.index, "tool": e.tool, "args_sha256": e.args_sha256,
                "output_sha256": e.output_sha256, "output_bytes": e.output_bytes,
                "policy_decision": e.policy_decision,
                "injection_flags": sorted(e.injection_flags), "prev_hash": e.prev_hash,
            }, sort_keys=True)
            if _sha(body) != e.entry_hash:
                return False
            prev = e.entry_hash
        return True

    def to_jsonl(self) -> str:
        return "\n".join(e.model_dump_json() for e in self.entries)

    def counts(self) -> dict:
        denied = sum(1 for e in self.entries if e.policy_decision.startswith("deny"))
        flagged = sum(1 for e in self.entries if e.injection_flags)
        return {"total": len(self.entries), "denied": denied, "flagged": flagged}
