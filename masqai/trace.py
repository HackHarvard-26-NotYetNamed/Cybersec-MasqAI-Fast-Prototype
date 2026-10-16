"""In-memory record of each sanitize pass, shown live on the GUI's Security page.

A trace holds what the security model was given (its instructions and the exact input JSON), what it
answered (raw text, even when that text is rejected), and what the gateway did with the answer.
Traces hold raw context values, so they live in RAM only, like sessions. They are never logged or
written to disk (the filesystem is untrusted).
"""
from __future__ import annotations

import itertools
import time
from collections import deque
from typing import Any, Callable

TRACE_LIMIT = 100
_ids = itertools.count(1)


class Trace:
    def __init__(self, session_id: str, endpoint: str, notify: Callable[["Trace"], None] | None = None) -> None:
        self.notify = notify
        self.data: dict[str, Any] = {
            "id": f"call-{next(_ids)}",
            "session_id": session_id,
            "endpoint": endpoint,
            "started_at": time.time(),
            "finished_at": None,
            "duration_ms": None,
            # running -> passed | skipped | blocked | error
            "status": "running",
            "stage": "detectors",
            "reason": None,
            "error": None,
            "detectors": None,
            "known": None,
            "security": None,
            "validation": None,
            "applied": None,
        }

    @property
    def id(self) -> str:
        return self.data["id"]

    def update(self, **fields: Any) -> None:
        self.data.update(fields)
        if self.notify:
            self.notify(self)

    def security(self, **fields: Any) -> None:
        """Merge fields into the security-call record, then publish."""
        self.data["security"] = {**(self.data["security"] or {}), **fields}
        if self.notify:
            self.notify(self)

    def finish(self, status: str, **fields: Any) -> None:
        now = time.time()
        self.update(status=status, finished_at=now, duration_ms=round((now - self.data["started_at"]) * 1000), **fields)

    def as_dict(self) -> dict[str, Any]:
        return self.data


class TraceLog:
    """The most recent traces, oldest first. Older ones are forgotten."""

    def __init__(self, limit: int = TRACE_LIMIT) -> None:
        self.traces: deque[Trace] = deque(maxlen=limit)

    def start(self, session_id: str, endpoint: str, notify: Callable[[Trace], None]) -> Trace:
        trace = Trace(session_id, endpoint, notify)
        self.traces.append(trace)
        return trace

    def as_list(self) -> list[dict[str, Any]]:
        return [trace.as_dict() for trace in self.traces]
