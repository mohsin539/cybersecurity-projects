"""Bounded parallel engine scheduler (architecture.md §5.4, memory.md §4).

- MAX_WORKERS worker pool, no nested pools.
- Tasks are named functions returning structured dicts.
- Failures are captured per task: an engine error becomes status=error result
  and never raises through the pipeline (memory.md §5 guarantees).
- Cooperative cancellation via threading.Event.
"""
from __future__ import annotations

import concurrent.futures
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

MAX_WORKERS = 4


@dataclass
class TaskResult:
    ok: bool
    value: Optional[dict] = None
    error: Optional[str] = None


def run_parallel(tasks: dict[str, Callable[[], dict]],
                 cancel_event: Optional[threading.Event] = None) -> dict[str, dict]:
    """Run named zero-arg tasks in parallel; always return per-task results.

    Results are wrapped: {"status": "ok"|"error", ...value or error}.
    """
    cancel_event = cancel_event or threading.Event()
    outcomes: dict[str, dict] = {}
    if not tasks:
        return outcomes

    workers = max(1, min(MAX_WORKERS, len(tasks)))

    def run(name: str, fn: Callable[[], dict]) -> tuple[str, dict]:
        if cancel_event.is_set():
            return name, {"status": "cancelled"}
        try:
            value = fn()
            return name, {"status": "ok", **value}
        except Exception as exc:  # engine isolation (memory.md §5/§7)
            return name, {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:500]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run, name, fn): name for name, fn in tasks.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                _, wrapped = future.result()
            except Exception as exc:
                wrapped = {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:500]}
            outcomes[name] = wrapped
    return outcomes