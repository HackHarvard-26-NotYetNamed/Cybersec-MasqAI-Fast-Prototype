"""Leak rule: a canary leaked if a relay request of its run contains its exact value, or (keys only) any
12-character or longer piece of its random part."""
from __future__ import annotations

import json
from typing import Any

from .cases import Canary

MIN_KEY_PIECE = 12


def relay_text(records: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(r.get("body"), ensure_ascii=False) for r in records)


def leaked(canaries: list[Canary], records: list[dict[str, Any]]) -> list[str]:
    """Names of the canaries that reached the relay. Values never leave this function."""
    text = relay_text(records)
    escaped = text.replace("\\\\", "\\")   # JSON-escaped backslashes, in case a value has any
    found = []
    for canary in canaries:
        if not canary.scan:
            continue
        if canary.value in text or canary.value in escaped:
            found.append(canary.name)
        elif canary.kind == "key" and canary.secret_part:
            part = canary.secret_part
            if any(part[i:i + MIN_KEY_PIECE] in text for i in range(len(part) - MIN_KEY_PIECE + 1)):
                found.append(canary.name)
    return found
