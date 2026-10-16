from __future__ import annotations

import copy
import secrets

from .model import Session


class SessionStore:
    def __init__(self):
        self.sessions = {}
        self.histories = {}
        self.hints = {}

    @staticmethod
    def history(payload):
        return copy.deepcopy(payload.get("messages", payload.get("input", [])))

    def resolve(self, payload, headers):
        """Hints first, then history prefix (design Q&A: "Hybrid: hints, then prefix").

        Without a hint, the request continues the stored history it shares the longest prefix
        with. If it diverges at index k (compaction, edited or retried turn), the session is
        rolled back: items after k are replaced by the new request's items. Leading
        system/developer messages are identical across sessions of the same agent, so they do
        not count as evidence; at least one conversational message must match.
        """
        hint = self._hint(payload, headers)
        if hint and hint in self.hints:
            return self.sessions[self.hints[hint]]
        history = self.history(payload)
        best, score, ambiguous = None, 0, False
        if isinstance(history, list):
            for sid, previous in self.histories.items():
                if not isinstance(previous, list):
                    continue
                common = self._evidence(history, previous)
                if common > score:
                    best, score, ambiguous = sid, common, False
                elif common and common == score:
                    ambiguous = True
        if best and not ambiguous and not hint:
            return self.sessions[best]
        sid = "session-" + secrets.token_hex(8)
        session = Session(sid, hint=hint)
        if best:
            # A new branch (hinted or ambiguous) keeps the parent's mapping and operations so the same
            # value gets the same placeholder and shared history is sanitized the same way.
            parent = self.sessions[best]
            session.entities = copy.deepcopy(parent.entities)
            session.ops = copy.deepcopy(parent.ops)
            session.vetoes = copy.deepcopy(parent.vetoes)
            session.inspected = set(parent.inspected)
            session.parent_id = best
        self.sessions[sid] = session
        if hint:
            self.hints[hint] = sid
        return session

    @staticmethod
    def _evidence(history: list, previous: list) -> int:
        """Number of shared leading messages that are not system/developer messages."""
        evidence = 0
        for a, b in zip(history, previous):
            if a != b:
                break
            if not (isinstance(a, dict) and a.get("role") in {"system", "developer"}):
                evidence += 1
        return evidence

    def remember(self, session, payload):
        history = self.history(payload)
        previous = self.histories.get(session.id)
        if isinstance(previous, list) and isinstance(history, list):
            shared = 0
            for a, b in zip(history, previous):
                if a != b:
                    break
                shared += 1
            if shared < len(previous):
                session.rollbacks += 1
        self.histories[session.id] = history

    @staticmethod
    def _hint(payload, headers):
        for key in ("x-session-id", "session-id", "session_id", "x-conversation-id", "conversation-id"):
            if headers.get(key):
                return f"header:{key}:{headers[key]}"
        metadata = payload.get("metadata") or {}
        for key in ("session_id", "conversation_id", "user_id"):
            if metadata.get(key):
                return f"metadata:{key}:{metadata[key]}"
        for key in ("prompt_cache_key", "user"):
            if payload.get(key):
                return f"{key}:{payload[key]}"
        return None
