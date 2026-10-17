"""Sessions: which stored conversation a request continues.

There is no standard session id, and agents resend the whole history, compact it and branch it.
- Hard hint: only the `x-masqai-session` header.
- Otherwise prefix matching: the request continues the stored history it shares the longest prefix with
  (leading system/developer messages don't count as evidence). Soft hints (`user`, `metadata.*`,
  `prompt_cache_key`, client session-id headers) only choose BETWEEN sessions whose prefix matches equally.
- A request that diverges from the stored history at index k is a rollback: the session keeps its
  mapping, and its item list is replaced from k on.
- Retention: idle TTL and an LRU cap, enforced periodically. A session with a request in flight or an
  open stream is never evicted; the next-oldest goes instead.
"""
from __future__ import annotations

import copy
import secrets
import time
from typing import Any

from .model import Session

HARD_HINT = "x-masqai-session"
SOFT_HEADER_HINTS = ("x-session-id", "session-id", "x-conversation-id", "conversation-id", "x-request-id")


class SessionStore:
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}
        self.histories: dict[str, list] = {}
        self.hard: dict[str, str] = {}             # x-masqai-session value -> session id
        self.soft: dict[str, set[str]] = {}         # session id -> soft hints seen

    @staticmethod
    def history(payload: dict[str, Any]) -> list:
        value = payload.get("messages", payload.get("input", []))
        return copy.deepcopy(value) if isinstance(value, list) else [value]

    @staticmethod
    def soft_hints(payload: dict[str, Any], headers: dict[str, str]) -> set[str]:
        """Read from the ORIGINAL payload, before pseudonymization."""
        hints = {f"header:{k}:{headers[k]}" for k in SOFT_HEADER_HINTS if headers.get(k)}
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            hints |= {f"metadata:{k}:{v}" for k, v in metadata.items() if isinstance(v, (str, int)) and v != ""}
        for key in ("user", "prompt_cache_key", "safety_identifier"):
            if isinstance(payload.get(key), str) and payload[key]:
                hints.add(f"{key}:{payload[key]}")
        return hints

    def resolve(self, payload: dict[str, Any], headers: dict[str, str]) -> Session:
        hint = headers.get(HARD_HINT)
        soft = self.soft_hints(payload, headers)
        history = self.history(payload)
        if hint:
            sid = self.hard.get(hint)
            if sid in self.sessions:
                session = self.sessions[sid]
                self.soft.setdefault(sid, set()).update(soft)
                return session
            session = self._new(hint=hint)
            self.hard[hint] = session.id
            self.soft[session.id] = set(soft)
            return session
        scored = [(self._evidence(history, previous), sid) for sid, previous in self.histories.items() if sid in self.sessions]
        best = max((score for score, _ in scored), default=0)
        candidates = [sid for score, sid in scored if score == best and score > 0]
        if len(candidates) > 1 and soft:
            narrowed = [sid for sid in candidates if self.soft.get(sid, set()) & soft]
            if narrowed:
                candidates = narrowed
        if len(candidates) == 1:
            self.soft.setdefault(candidates[0], set()).update(soft)
            return self.sessions[candidates[0]]
        session = self._new()
        if candidates:
            # Still ambiguous: a new branch that keeps the most recent candidate's mapping, so the same
            # value keeps the same placeholder and shared history is sanitized the same way.
            self._inherit(session, max((self.sessions[s] for s in candidates), key=lambda s: s.last_seen))
        self.soft[session.id] = set(soft)
        return session

    def _new(self, hint: str | None = None) -> Session:
        session = Session("session-" + secrets.token_hex(8), hint=hint)
        self.sessions[session.id] = session
        return session

    @staticmethod
    def _inherit(child: Session, parent: Session) -> None:
        child.entities = copy.deepcopy(parent.entities)
        child.ops = copy.deepcopy(parent.ops)
        child.vetoes = copy.deepcopy(parent.vetoes)
        child.veto_reasons = dict(parent.veto_reasons)
        child.inspected = set(parent.inspected)
        child.rejected = copy.deepcopy(parent.rejected)
        child.pseudonym = parent.pseudonym
        child.parent_id = parent.id

    @staticmethod
    def _evidence(history: list, previous: list) -> int:
        """Shared leading messages that are not system/developer messages."""
        evidence = 0
        for a, b in zip(history, previous):
            if a != b:
                break
            if not (isinstance(a, dict) and a.get("role") in {"system", "developer"}):
                evidence += 1
        return evidence

    def remember(self, session: Session, payload: dict[str, Any]) -> None:
        history = self.history(payload)
        previous = self.histories.get(session.id)
        if isinstance(previous, list):
            shared = 0
            for a, b in zip(history, previous):
                if a != b:
                    break
                shared += 1
            if shared < len(previous):
                session.rollbacks += 1
        self.histories[session.id] = history
        session.last_seen = time.time()

    # ---------- retention ----------
    def enforce(self, idle_ttl_h: float, max_sessions: int, now: float | None = None) -> list[str]:
        """Drop idle sessions, then the least recently used past the cap. Busy sessions are kept."""
        now = time.time() if now is None else now
        evicted = [sid for sid, s in self.sessions.items() if s.in_flight == 0 and now - s.last_seen > idle_ttl_h * 3600]
        for sid in evicted:
            self.forget(sid)
        idle = sorted((s for s in self.sessions.values() if s.in_flight == 0), key=lambda s: s.last_seen)
        while len(self.sessions) > max_sessions and idle:
            victim = idle.pop(0)
            self.forget(victim.id)
            evicted.append(victim.id)
        return evicted

    def forget(self, sid: str) -> bool:
        if sid not in self.sessions:
            return False
        del self.sessions[sid]
        self.histories.pop(sid, None)
        self.soft.pop(sid, None)
        for hint in [h for h, s in self.hard.items() if s == sid]:
            del self.hard[hint]
        return True
