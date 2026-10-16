from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ContextItem:
    id: str
    kind: str
    role: str
    original: Any
    sanitized: Any
    eligible: bool = True
    reasoning: bool = False
    changed: bool = False
    request_index: int = 0
    revision: int = 0
    path: tuple = field(default_factory=tuple)
    json_value: bool = False
    # Computed by ops.plan_item on every request: what is masked/collapsed, and known values left as-is.
    spans: list = field(default_factory=list)
    unmasked: list = field(default_factory=list)
    collapses: list = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "role": self.role,
            "original": self.original,
            "sanitized": self.sanitized,
            "eligible": self.eligible,
            "reasoning": self.reasoning,
            "changed": self.changed,
            "request_index": self.request_index,
            "revision": self.revision,
            "path": list(self.path),
            "spans": self.spans,
            "unmasked": self.unmasked,
            "collapses": self.collapses,
        }


@dataclass
class Entity:
    """One sensitive value. `canonical` is the exact value; `merged_into` links it to another entity,
    after which every occurrence of it is sent as that entity's `<$TOKEN>` (a partial/changed form)."""
    token: str
    canonical: str
    entity_type: str
    origin: str = "model"   # "model", "detector:pattern", "detector:host", "detector:custom"
    merged_into: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"token": self.token, "type": self.entity_type, "canonical": self.canonical,
                "origin": self.origin, "merged_into": self.merged_into}


@dataclass
class MaskOp:
    """A mask bound to exactly one occurrence: characters [start, end) of one item's original text."""
    item_id: str
    start: int
    end: int
    token: str
    alias: bool
    text: str
    origin: str = "model"
    request: int = 0


@dataclass
class CollapseOp:
    """Lines start..end (1-based, inclusive) of one tool result, sent as one summary line."""
    item_id: str
    start_line: int
    end_line: int
    summary: str
    first: str
    last: str
    request: int = 0


@dataclass
class Session:
    id: str
    hint: str | None = None
    items: list[ContextItem] = field(default_factory=list)
    entities: dict[str, Entity] = field(default_factory=dict)
    # Security-model operations by item id. Item ids hash path + content, so an operation stays valid
    # whenever the same item is resent, and is simply unused while it is absent (rollback).
    ops: dict[str, list] = field(default_factory=dict)
    vetoes: dict[str, set] = field(default_factory=dict)   # item id -> {(start, end)} of auto masks undone
    inspected: set[str] = field(default_factory=set)       # item ids the security model has accepted
    request_count: int = 0
    revision: int = 0
    last_seen: float = field(default_factory=time.time)
    parent_id: str | None = None
    rollbacks: int = 0  # times a request diverged from the stored history and truncated it

    def entity_for(self, value: str) -> Entity | None:
        for entity in self.entities.values():
            if value == entity.canonical:
                return entity
        return None

    def new_entity(self, value: str, entity_type: str, origin: str = "model") -> Entity:
        token = f"<{entity_type.upper()}_{secrets.token_hex(4)}>"
        entity = Entity(token, value, entity_type.upper(), origin)
        self.entities[token] = entity
        return entity

    def root(self, token: str) -> Entity:
        entity = self.entities[token]
        seen = {token}
        while entity.merged_into and entity.merged_into not in seen:
            seen.add(entity.merged_into)
            entity = self.entities[entity.merged_into]
        return entity

    def alias_texts(self, token: str) -> list[str]:
        """Texts the security model marked as partial/changed forms of `token` (directly or via links)."""
        root = self.root(token).token
        texts = {op.text for ops in self.ops.values() for op in ops
                 if isinstance(op, MaskOp) and op.alias and self.root(op.token).token == root}
        texts |= {e.canonical for e in self.entities.values() if e.token != root and self.root(e.token).token == root}
        return sorted(texts)

    def known_values(self) -> list[tuple[str, str]]:
        """(value, placeholder) for every known sensitive text, longest first. Used to scrub logs and
        to check model-written summaries; never used to rewrite the context."""
        pairs: dict[str, str] = {}
        for entity in self.entities.values():
            root = self.root(entity.token)
            pairs.setdefault(entity.canonical, root.token if root is entity else root.token.replace("<", "<$", 1))
        for ops in self.ops.values():
            for op in ops:
                if isinstance(op, MaskOp) and op.token in self.entities:
                    pairs.setdefault(op.text, self.root(op.token).token.replace("<", "<$", 1) if op.alias else self.root(op.token).token)
        return sorted(pairs.items(), key=lambda pair: -len(pair[0]))

    def restore_table(self) -> list[dict[str, str]]:
        """Placeholder -> real value for tool-call arguments. Linked tokens restore to their root's value."""
        return [{"token": entity.token, "canonical": self.root(entity.token).canonical} for entity in self.entities.values()]

    def fingerprint(self, payload: Any) -> str:
        return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True).encode()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "parent_id": self.parent_id,
            "hint": self.hint,
            "request_count": self.request_count,
            "revision": self.revision,
            "rollbacks": self.rollbacks,
            "last_seen": self.last_seen,
            "entities": [{**entity.as_dict(), "aliases": self.alias_texts(entity.token) if not entity.merged_into else []}
                         for entity in self.entities.values()],
            "items": [item.as_dict() for item in self.items],
        }
