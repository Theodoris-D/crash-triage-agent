"""Live progress for long evaluation runs.

In a terminal it draws one status line under the log, redrawn by a background
thread (the provider call is blocking, so an asyncio task would freeze):

    ⠹ [██████░░░░░░░░░░░░] 21/66  32% · c02 false_verified def=1 · this run 0:14 · elapsed 3:02 · ~6:20 left · $0.021

The spinner and the "this run" timer keep moving while the model is thinking,
which is how you can tell the run is alive. Without a terminal (CI, logs, docker
without -t) it prints plain, flushed lines prefixed with [n/total] instead.
"""
from __future__ import annotations

import sys
import threading
import time

SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _clock(s: float) -> str:
    s = int(s)
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}" if s >= 3600 else f"{s // 60}:{s % 60:02d}"


class Progress:
    def __init__(self, total: int, cost=None, stream=None, live: bool | None = None, width: int = 18):
        self.total = max(total, 1)
        self.cost = cost                       # callable -> estimated USD, or None
        self.out = stream or sys.stdout
        self.live = self.out.isatty() if live is None else live
        self.width = width
        self.done = 0
        self.errors = 0
        self.label = "starting"
        self.t0 = time.time()
        self.t_item = self.t0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        if self.live:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()

    # --- public API -------------------------------------------------------
    def start(self, label: str) -> None:
        with self._lock:
            self.label = label
            self.t_item = time.time()

    def finish(self, line: str, error: bool = False) -> None:
        """Record one completed run and print its permanent log line."""
        with self._lock:
            self.done += 1
            self.errors += int(error)
            prefix = "" if self.live else f"[{self.done:>3}/{self.total}] "
            self._emit(prefix + line)

    def log(self, line: str) -> None:
        with self._lock:
            self._emit(line)

    def close(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        with self._lock:
            if self.live:
                self.out.write("\r\033[2K")
            took = _clock(time.time() - self.t0)
            err = f", {self.errors} errored" if self.errors else ""
            self.out.write(f"done: {self.done}/{self.total} runs in {took}{err}\n")
            self.out.flush()

    # --- internals --------------------------------------------------------
    def _emit(self, line: str) -> None:
        if self.live:
            self.out.write("\r\033[2K")
        self.out.write(line + "\n")
        if self.live:
            self.out.write(self._status(0))
        self.out.flush()

    def _status(self, tick: int) -> str:
        now = time.time()
        frac = self.done / self.total
        fill = int(round(frac * self.width))
        bar = "█" * fill + "░" * (self.width - fill)
        elapsed = now - self.t0
        left = f" · ~{_clock(elapsed / self.done * (self.total - self.done))} left" if self.done else ""
        cost = ""
        if self.cost is not None:
            try:
                cost = f" · ${self.cost():.3f}"
            except Exception:
                cost = ""
        err = f" · {self.errors} errors" if self.errors else ""
        return (f"{SPIN[tick % len(SPIN)]} [{bar}] {self.done}/{self.total} {frac * 100:3.0f}%"
                f" · {self.label} · this run {_clock(now - self.t_item)}"
                f" · elapsed {_clock(elapsed)}{left}{cost}{err}")

    def _spin(self) -> None:
        tick = 0
        while not self._stop.wait(0.12):
            tick += 1
            with self._lock:
                self.out.write("\r\033[2K" + self._status(tick))
                self.out.flush()
