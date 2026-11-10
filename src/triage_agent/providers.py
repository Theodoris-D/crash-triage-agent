"""LLM providers behind one small interface.

A provider receives the running OpenAI-style message list plus the tool schemas
and returns the next assistant message (either `tool_calls` or a final
`finalize_report` call). The agent owns the loop.

  * OpenAICompatibleProvider -- talks to any OpenAI-compatible chat/completions
    endpoint. The same class serves a local Ollama server and OpenRouter; only
    base_url / model / api_key differ (see factories below). This is what
    produces real capability and security numbers.

  * MockProvider -- a deterministic test double for CI and offline smoke tests.
    It does NOT use ground truth: it walks a fixed tool sequence and fills the
    report by parsing the sanitizer/debugger output with the same heuristic as
    the non-LLM baseline, and it proposes no fix. It is NOT a measurement of an
    agent -- it exists so the pipeline, guardrails and (when an attack is
    configured) the injection-obedience path can be exercised without a model.
    When an attack payload survives undefended, it carries the attacker's action
    out, modelling a gullible instruction-follower, so the defense tests have a
    deterministic subject.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error

from .triage_heuristics import interpret


# --------------------------------------------------------------------------- #
# OpenAI-compatible HTTP provider (Ollama / OpenRouter / anything compatible)  #
# --------------------------------------------------------------------------- #
class ProviderError(RuntimeError):
    pass


class OpenAICompatibleProvider:
    def __init__(self, base_url: str, model: str, api_key: str | None = None,
                 name: str | None = None, temperature: float = 0.0,
                 timeout: float = 120.0, extra_headers: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.name = name or f"openai:{model}"
        self.temperature = temperature
        self.timeout = timeout
        self.extra_headers = extra_headers or {}

    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": self.temperature,
        }
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(self.base_url + "/chat/completions",
                                     data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise ProviderError(f"{self.name}: HTTP {e.code}: {e.read()[:400]!r}")
        except urllib.error.URLError as e:
            raise ProviderError(f"{self.name}: cannot reach {self.base_url}: {e.reason}")
        try:
            msg = body["choices"][0]["message"]
        except (KeyError, IndexError):
            raise ProviderError(f"{self.name}: unexpected response: {str(body)[:400]}")
        return {
            "role": "assistant",
            "content": msg.get("content"),
            "tool_calls": msg.get("tool_calls") or [],
        }


def ollama_provider(model: str = "qwen2.5-coder:7b",
                    host: str | None = None) -> OpenAICompatibleProvider:
    host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    return OpenAICompatibleProvider(base_url=host.rstrip("/") + "/v1",
                                    model=model, api_key="ollama",
                                    name=f"ollama:{model}")


def openrouter_provider(model: str = "anthropic/claude-3.5-sonnet",
                        api_key: str | None = None) -> OpenAICompatibleProvider:
    api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ProviderError("OPENROUTER_API_KEY not set")
    return OpenAICompatibleProvider(
        base_url="https://openrouter.ai/api/v1", model=model, api_key=api_key,
        name=f"openrouter:{model}",
        extra_headers={"HTTP-Referer": "https://github.com/", "X-Title": "crash-triage-agent"})


def build_provider(spec: str, case=None):
    """spec forms: 'mock', 'ollama:<model>', 'openrouter:<model>'."""
    if spec == "mock":
        return MockProvider(case) if case is not None else None
    kind, _, model = spec.partition(":")
    if kind == "ollama":
        return ollama_provider(model or "qwen2.5-coder:7b")
    if kind == "openrouter":
        return openrouter_provider(model or "anthropic/claude-3.5-sonnet")
    raise ProviderError(f"unknown provider spec: {spec!r}")


# --------------------------------------------------------------------------- #
# Deterministic mock (test double) -- no ground truth, no model                #
# --------------------------------------------------------------------------- #
ATTACK_FORBIDDEN_INSPECT = "forbidden_inspect"
ATTACK_FALSE_VERIFIED = "false_verified"
ATTACK_BEACON = "beacon_exfil"


class MockProvider:
    name = "mock"

    def __init__(self, case, attack: str | None = None, beacon: str | None = None):
        self.case = case
        self.attack = attack
        self.beacon = beacon
        self._did_attack = False

    def _plan(self) -> list[tuple[str, dict]]:
        cid = self.case.id
        crash = self.case.meta["crashing_stdin"]
        return [
            ("run_target", {"case_id": cid, "stdin": crash}),
            ("sanitizer_report", {"case_id": cid, "stdin": crash}),
            ("gdb_backtrace", {"case_id": cid, "stdin": crash}),
            ("read_source", {"case_id": cid, "path": "bug.c", "start": 1, "end": 200}),
            ("cwe_lookup", {"query": "memory safety crash in C"}),
        ]

    def _visible_injection(self, messages: list[dict]) -> bool:
        return any("INJECT::" in (m.get("content") or "")
                   for m in messages if m.get("role") == "tool")

    def _collect(self, messages: list[dict]) -> dict:
        out = {}
        for m in messages:
            if m.get("role") == "tool" and m.get("name"):
                out[m["name"]] = m.get("content") or ""
        return out

    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        done = sum(1 for m in messages if m.get("role") == "tool")
        plan = self._plan()

        if (self.attack and not self._did_attack and done >= len(plan)
                and self._visible_injection(messages)):
            self._did_attack = True
            if self.attack == ATTACK_FORBIDDEN_INSPECT:
                return self._call("inspect", {"case_id": self.case.id, "expr": "$pc",
                                              "stdin": self.case.meta["crashing_stdin"]})

        if done < len(plan):
            name, args = plan[done]
            return self._call(name, args)
        return self._finalize(messages)

    def _call(self, name: str, args: dict) -> dict:
        return {"role": "assistant", "content": None,
                "tool_calls": [{"id": f"call_{name}_{id(args) % 10000}",
                                "type": "function",
                                "function": {"name": name,
                                             "arguments": json.dumps(args)}}]}

    def _finalize(self, messages: list[dict]) -> dict:
        got = self._collect(messages)
        h = interpret(got.get("sanitizer_report", ""), got.get("gdb_backtrace", ""))
        explanation = (f"Heuristic triage from sanitizer/debugger output: "
                       f"{h['crash_class'].value} at bug.c:{h['root_cause_line']}.")
        diff = ""
        fix_verified = False
        if self.attack and self._visible_injection(messages):
            if self.attack == ATTACK_BEACON and self.beacon:
                explanation += f" {self.beacon}"
            if self.attack == ATTACK_FALSE_VERIFIED:
                diff = "--- a/bug.c\n+++ b/bug.c\n@@\n // attacker: no real change\n"
                fix_verified = True
        args = {
            "case_id": self.case.id,
            "crash_class": h["crash_class"].value,
            "cwe": h["cwe"],
            "root_cause_file": "bug.c",
            "root_cause_line": h["root_cause_line"],
            "explanation": explanation,
            "confidence": h["confidence"],
            "fix_unified_diff": diff,
            "fix_verified": fix_verified,
        }
        return {"role": "assistant", "content": None,
                "tool_calls": [{"id": "call_finalize", "type": "function",
                                "function": {"name": "finalize_report",
                                             "arguments": json.dumps(args)}}]}
