"""Diagnostic logging for the gateway.

What is logged: routing decisions, request *shapes* (message counts, roles, tool names, sampling
parameters), timings, HTTP statuses and upstream error bodies. Error bodies pass through the session's
known mappings before they are logged.

What is never logged: raw context, or the security model's raw input or output. At DEBUG level the
*sanitized* outbound body is also logged. That is exactly what the untrusted upstream receives anyway.
The filesystem is untrusted, so don't redirect DEBUG output to a file you keep.

    MASQAI_LOG_LEVEL=DEBUG|INFO|WARNING   (default INFO)
"""
from __future__ import annotations

import contextvars
import itertools
import json
import logging
import os
from typing import Any

log = logging.getLogger("masqai")
request_id: contextvars.ContextVar[str] = contextvars.ContextVar("masqai_request_id", default="-")
_ids = itertools.count(1)

CONTENT_KEYS = {"messages", "input", "system", "instructions", "tools", "prompt", "contents"}
PRIVATE_KEYS = {"user", "metadata", "prompt_cache_key", "safety_identifier"}
MAX_ERROR = 4000
MAX_DEBUG_BODY = 20000


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.rid = request_id.get()
        return True


def configure() -> None:
    if log.handlers:
        return
    handler = logging.StreamHandler()
    handler.addFilter(_RequestIdFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s [%(rid)s] %(message)s", "%H:%M:%S"))
    log.addHandler(handler)
    log.setLevel(os.getenv("MASQAI_LOG_LEVEL", "INFO").upper())
    log.propagate = False


def begin() -> str:
    """Give the current request an id that every following log line carries."""
    rid = f"req{next(_ids)}"
    request_id.set(rid)
    return rid


def clip(text: str, limit: int = MAX_ERROR) -> str:
    return text if len(text) <= limit else text[:limit] + f"... [{len(text) - limit} more chars]"


def error_text(content: bytes | str) -> str:
    """An upstream error body on one line: compact JSON if it parses, otherwise text."""
    text = content.decode("utf-8", "replace") if isinstance(content, bytes) else content
    try:
        text = json.dumps(json.loads(text), ensure_ascii=False, separators=(",", ":"))
    except ValueError:
        text = " ".join(text.split())
    return clip(text or "<empty body>")


def shape(body: Any) -> str:
    """Describe a request body without any of its content."""
    if not isinstance(body, dict):
        return type(body).__name__
    parts = []
    for key in ("messages", "input"):
        value = body.get(key)
        if isinstance(value, list):
            roles: dict[str, int] = {}
            for message in value:
                if isinstance(message, dict):
                    role = message.get("role") or message.get("type") or "?"
                    roles[role] = roles.get(role, 0) + 1
            parts.append(f"{key}={len(value)} {roles}")
        elif isinstance(value, str):
            parts.append(f"{key}=<string {len(value)} chars>")
    for key in ("system", "instructions"):
        if key in body:
            parts.append(f"{key}=<{len(json.dumps(body[key], ensure_ascii=False))} chars>")
    tools = body.get("tools")
    if isinstance(tools, list):
        names = [t.get("name") or (t.get("function") or {}).get("name") or t.get("type", "?") for t in tools if isinstance(t, dict)]
        parts.append(f"tools={len(tools)} {names}")
    params = {}
    for key, value in body.items():
        if key in CONTENT_KEYS:
            continue
        if key in PRIVATE_KEYS:
            params[key] = "<set>"
        elif len(json.dumps(value, ensure_ascii=False, default=str)) <= 300:
            params[key] = value
        else:
            params[key] = f"<{type(value).__name__}>"
    parts.append("params=" + json.dumps(params, ensure_ascii=False, default=str))
    parts.append(f"bytes={len(json.dumps(body, ensure_ascii=False))}")
    return " ".join(parts)


def debug_body(label: str, body: Any) -> None:
    if log.isEnabledFor(logging.DEBUG):
        log.debug("%s: %s", label, clip(json.dumps(body, ensure_ascii=False), MAX_DEBUG_BODY))
