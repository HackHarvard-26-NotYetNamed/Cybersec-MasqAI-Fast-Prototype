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
    # Computed by ops.plan_item on every request: what is masked/hidden/replaced, and known values left as-is.
    spans: list = field(default_factory=list)
    unmasked: list = field(default_factory=list)
    hides: list = field(default_factory=list)
    replaces: list = field(default_factory=list)
    # Whitelisted opaque content (an image, a base64 document): forwarded unread, shown as a description.
    opaque: bool = False
    # Mask only, never hide/replace (user messages, system prompts, past assistant text, tool arguments).
    mask_only: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "role": self.role,
            "original": self.original,
            "sanitized": self.sanitized,
            "eligible": self.eligible,
            "reasoning": self.reasoning,
            "opaque": self.opaque,
            "changed": self.changed,
            "request_index": self.request_index,
            "revision": self.revision,
            "path": list(self.path),
            "spans": self.spans,
            "unmasked": self.unmasked,
            "hides": self.hides,
            "replaces": self.replaces,
        }


@dataclass
class Entity:
    """One sensitive value. `canonical` is the exact value; `merged_into` links it to another entity,
    after which every occurrence of it is sent as that entity's `<$TOKEN>` (a partial/changed form)."""
    token: str
    canonical: str
    entity_type: str
    origin: str = "model"   # "model", "detector:<rule>", "detector:host", "detector:custom"
    merged_into: str | None = None
    cls: str = "secret"     # "secret" or "intel"
    # Item ids where a detector matched this value (those occurrences are reported as `detector`,
    # every other exact copy as `auto`).
    detected_in: set = field(default_factory=set)
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"token": self.token, "type": self.entity_type, "canonical": self.canonical, "class": self.cls,
                "origin": self.origin, "merged_into": self.merged_into, "reason": self.reason}


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
    reason: str | None = None


@dataclass
class HideOp:
    """Rephrase / hide: lines start..end (1-based, inclusive) of one tool result, sent as
    `…[hidden: summary]…`. Lossy, intel by default."""
    item_id: str
    start_line: int
    end_line: int
    summary: str
    first: str
    last: str
    request: int = 0
    cls: str = "intel"
    reason: str | None = None


@dataclass
class ReplaceOp:
    """Rephrase / replace: one occurrence [start, end) of one tool result, sent as `replacement`.
    Lossy and never restored, intel by default."""
    item_id: str
    start: int
    end: int
    text: str
    replacement: str
    request: int = 0
    cls: str = "intel"
    reason: str | None = None


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
    veto_reasons: dict = field(default_factory=dict)       # (item id, start, end) -> the model's reason
    inspected: set[str] = field(default_factory=set)       # item ids the security model has accepted
    request_count: int = 0
    revision: int = 0
    last_seen: float = field(default_factory=time.time)
    parent_id: str | None = None
    rollbacks: int = 0  # times a request diverged from the stored history and truncated it
    remasks: int = 0    # times an already-sent item was re-sanitized (breaks the upstream prompt cache)
    created: float = field(default_factory=time.time)
    # Stand-in for user / metadata.user_id / safety_identifier / prompt_cache_key: 128 random bits,
    # stable for the session and inherited by a branch.
    pseudonym: str = field(default_factory=lambda: "masq-" + secrets.token_hex(16))
    in_flight: int = 0  # requests or open streams; never evicted while > 0
    # Model operations that failed validation and were corrected in the retry round, per item id.
    rejected: dict[str, list] = field(default_factory=dict)
    # Relinks applied in this session, in order: {"from", "to", "request", "items"}.
    relinks: list = field(default_factory=list)
    headers_stripped: set = field(default_factory=set)
    pseudonymized: set = field(default_factory=set)
    # One record per request: what was sent upstream (for the replay export). RAM only.
    requests: list = field(default_factory=list)

    def entity_for(self, value: str) -> Entity | None:
        for entity in self.entities.values():
            if value == entity.canonical:
                return entity
        return None

    def new_entity(self, value: str, entity_type: str, origin: str = "model", cls: str = "secret", reason: str | None = None) -> Entity:
        # Random ids, never a hash of the value: the upstream must not be able to confirm guesses.
        token = f"<{entity_type.upper()}_{secrets.token_hex(4)}>"
        while token in self.entities:
            token = f"<{entity_type.upper()}_{secrets.token_hex(4)}>"
        entity = Entity(token, value, entity_type.upper(), origin, cls=cls, reason=reason)
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
            "remasks": self.remasks,
            "relinks": self.relinks,
            "created": self.created,
            "last_seen": self.last_seen,
            "entities": [{**entity.as_dict(), "aliases": self.alias_texts(entity.token) if not entity.merged_into else []}
                         for entity in self.entities.values()],
            "items": [item.as_dict() for item in self.items],
        }
