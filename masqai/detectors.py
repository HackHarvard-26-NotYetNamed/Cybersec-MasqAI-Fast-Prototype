from __future__ import annotations

import os
import re
import socket
from pathlib import Path
from typing import Iterable

from .config import DetectorConfig
from .model import Entity, Session

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OPENAI_KEY", re.compile(r"sk-[A-Za-z0-9][A-Za-z0-9_-]{12,}")),
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-[A-Za-z0-9_-]{12,}")),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("AWS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # The whole PEM block (header, body, footer), not just the header line. Without a footer
    # (truncated tool output), the header plus the base64 lines that follow it. `\\n` covers a key
    # inside JSON text; spaces are excluded there so the match stops at the next normal text.
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?P<kind>[A-Z0-9 ]*)PRIVATE KEY( BLOCK)?-----"
                               r"(?:[\s\S]*?-----END (?P=kind)PRIVATE KEY( BLOCK)?-----|(?:[\r\n]|\\[rn]|[A-Za-z0-9+/=])*)")),
]


def host_values() -> list[tuple[str, str]]:
    """Identifiers of the machine running the gateway, masked when detect_host_identifiers is on."""
    values = [("HOST", socket.gethostname()), ("USERNAME", os.getenv("USERNAME") or os.getenv("USER") or "")]
    for name in ("USERPROFILE", "HOME", "HOMEPATH"):
        if os.getenv(name):
            values.append(("PATH", os.getenv(name, "")))
    return [(t, v) for t, v in values if v]


def seed_entities(session: Session, texts: Iterable[str], config: DetectorConfig) -> list[Entity]:
    """Add every detector hit to the session's entities. Their exact copies are then masked
    automatically (at token boundaries) by ops.plan_item."""
    values: list[tuple[str, str, str]] = []
    if config.detect_host_identifiers:
        values += [(t, v, "detector:host") for t, v in host_values()]
    values += [(item.type, item.value, "detector:custom") for item in config.custom_values]
    found: list[Entity] = []
    for text in texts:
        for entity_type, pattern in PATTERNS:
            for match in pattern.finditer(text):
                values.append((entity_type, match.group(0), "detector:pattern"))
    for entity_type, value, origin in values:
        if not value or len(value) < 3:
            continue
        entity = session.entity_for(value)
        if entity is None:
            entity = session.new_entity(value, entity_type, origin)
            found.append(entity)
    return found
