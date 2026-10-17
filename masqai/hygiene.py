"""Request hygiene: identifiers the untrusted model doesn't need.

- Exactly four fields are pseudonymized: `user`, `metadata.user_id`, `safety_identifier`,
  `prompt_cache_key`. Each becomes the session's pseudonym (`masq-` + 128 random bits), stable for the
  session and inherited by a branch. Other `metadata` keys pass. Session hints are read before this.
- Headers: see config.HeaderPolicy (blocklist mode by default) and upstream.headers_for. This module
  only records which identifying headers a request carried, for the GUI and the replay export.
"""
from __future__ import annotations

from typing import Any

from .config import ALWAYS_DROPPED_HEADERS, HeaderPolicy
from .model import Session

PSEUDONYM_FIELDS = ("user", "metadata.user_id", "safety_identifier", "prompt_cache_key")
FRAMING = {h for h in ALWAYS_DROPPED_HEADERS if not h.endswith("*")} - {"authorization", "proxy-authorization", "x-api-key"}


def pseudonymize(payload: dict[str, Any], session: Session) -> list[str]:
    """Replace the four identifying fields in place. Returns the fields that were present."""
    replaced = []
    for field in ("user", "safety_identifier", "prompt_cache_key"):
        if payload.get(field) not in (None, ""):
            payload[field] = session.pseudonym
            replaced.append(field)
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and metadata.get("user_id") not in (None, ""):
        metadata["user_id"] = session.pseudonym
        replaced.append("metadata.user_id")
    session.pseudonymized.update(replaced)
    return replaced


def stripped_headers(incoming: dict[str, str], policy: HeaderPolicy) -> list[str]:
    """Identifying headers the request carried that are not forwarded (credentials and framing aside)."""
    names = []
    for name in incoming:
        lower = name.lower()
        if lower in FRAMING or lower.startswith("x-masqai-") or lower in {"authorization", "x-api-key", "proxy-authorization"}:
            continue
        if lower == "user-agent" and policy.user_agent:
            names.append("user-agent")   # replaced, not forwarded as is
        elif not policy.allows(lower):
            names.append(lower)
    return sorted(set(names))
