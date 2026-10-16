"""Tests for alignment with Design-QnA.doc.md (session rollback, collapse rephrase, keys, headers)."""
import json
import unittest

from pydantic import ValidationError

from masqai.config import GatewayConfig, HeaderPolicy, ProviderConfig, load_config
from masqai.model import Session
from masqai.sanitize import SanitizationError, Sanitizer
from masqai.session import SessionStore
from masqai.upstream import headers_for

SYSTEM = {"role": "system", "content": "You are OpenCode. cwd=/repo"}


def msgs(*contents, system=True):
    out = [SYSTEM] if system else []
    roles = ["user", "assistant"]
    return {"messages": out + [{"role": roles[i % 2], "content": c} for i, c in enumerate(contents)]}


def track(store, payload, headers=None):
    session = store.resolve(payload, headers or {})
    store.remember(session, payload)
    return session


class SessionRollback(unittest.TestCase):
    def test_append_continues(self):
        store = SessionStore()
        a = track(store, msgs("hi"))
        self.assertIs(track(store, msgs("hi", "hello", "next")), a)

    def test_divergence_rolls_back_same_session(self):
        store = SessionStore()
        a = track(store, msgs("task", "answer 1", "follow-up"))
        # Retry / edit: same start, different last turn.
        b = track(store, msgs("task", "answer 1", "edited follow-up"))
        self.assertIs(b, a)
        self.assertEqual(a.rollbacks, 1)

    def test_compaction_keeps_session_and_mapping(self):
        store = SessionStore()
        a = track(store, msgs("task", "a1", "u2", "a2", "u3"))
        a.new_entity("alice@corp.com", "EMAIL")
        compacted = track(store, msgs("task", "summary of a1..a2", "u4"))
        self.assertIs(compacted, a)
        self.assertEqual(len(compacted.entities), 1)

    def test_shared_system_prompt_alone_is_not_evidence(self):
        store = SessionStore()
        a = track(store, msgs("first conversation"))
        b = track(store, msgs("unrelated conversation"))
        self.assertIsNot(a, b)

    def test_longest_prefix_wins(self):
        store = SessionStore()
        short = track(store, msgs("x"))
        long = track(store, msgs("x", "y", "z", system=False))
        self.assertIsNot(short, long)
        self.assertIs(track(store, msgs("x", "y", "z", "w", system=False)), long)

    def test_ambiguous_branch_forks_with_inherited_mapping(self):
        store = SessionStore()
        a = track(store, msgs("task", "a1", "left"))
        a.new_entity("secret-value", "SECRET")
        b = track(store, msgs("task", "a1", "right"))  # rolls a back to "right"
        self.assertIs(b, a)
        c = track(store, msgs("task", "a1", "left", system=False))  # new history, no system prompt
        self.assertIsNot(c, a)

    def test_hint_wins_over_prefix(self):
        store = SessionStore()
        a = track(store, msgs("task"))
        hinted = track(store, msgs("task", "more"), {"x-session-id": "s1"})
        self.assertIsNot(hinted, a)
        self.assertEqual(hinted.parent_id, a.id)
        self.assertEqual(hinted.entities, a.entities)


class CollapseRephrase(unittest.TestCase):
    TEXT = "header\nsecret 1\nsecret 2\nkeep me\nsecret 3"

    def setUp(self):
        from masqai.adapter import extract
        self.session = Session("s")
        self.items = extract({"messages": [{"role": "tool", "tool_call_id": "1", "content": self.TEXT}]}, "openai")

    def apply(self, *ops):
        from masqai.ops import Applier, plan_all
        results = Applier(self.session, self.items, False, 1).apply(list(ops))
        plan_all(self.session, self.items)
        return results

    def test_each_range_gets_its_own_summary(self):
        results = self.apply(
            {"op": "collapse", "item": "#1", "start": 2, "end": 3, "first": "secret 1", "last": "secret 2", "summary": "two credentials"},
            {"op": "collapse", "item": "#1", "start": 5, "end": 5, "first": "secret 3", "last": "secret 3", "summary": "one token"})
        self.assertTrue(all(r["ok"] for r in results))
        self.assertEqual(self.items[0].sanitized, "header\n…[MASQ_BLOCK: two credentials]…\nkeep me\n…[MASQ_BLOCK: one token]…")

    def test_invalid_collapse_is_rejected_on_its_own(self):
        bad = [
            {"op": "collapse", "item": "#1"},
            {"op": "collapse", "item": "#1", "start": 2, "end": 2, "first": "secret 1", "last": "secret 1"},  # no summary
            {"op": "collapse", "item": "#1", "start": 2, "end": 2, "first": "secret 1", "last": "secret 1", "summary": "a\nb"},
            {"op": "collapse", "item": "#1", "start": 2, "end": 2, "first": "secret 1", "last": "secret 1", "summary": "x" * 201},
            {"op": "collapse", "item": "#1", "start": 2, "end": 9, "first": "secret 1", "last": "x", "summary": "s"},
            {"op": "collapse", "item": "#1", "start": True, "end": 2, "first": "header", "last": "secret 1", "summary": "s"},
            {"op": "collapse", "item": "#2", "start": 1, "end": 1, "first": "header", "last": "header", "summary": "s"},
        ]
        good = {"op": "collapse", "item": "#1", "start": 4, "end": 4, "first": "keep me", "last": "keep me", "summary": "ok"}
        results = self.apply(*bad, good)
        self.assertEqual([r["ok"] for r in results], [False] * len(bad) + [True])
        self.assertIn("…[MASQ_BLOCK: ok]…", self.items[0].sanitized)

    def test_overlapping_collapse_rejected(self):
        self.apply({"op": "collapse", "item": "#1", "start": 2, "end": 3, "first": "secret 1", "last": "secret 2", "summary": "a"})
        [r] = self.apply({"op": "collapse", "item": "#1", "start": 3, "end": 4, "first": "secret 2", "last": "keep me", "summary": "b"})
        self.assertFalse(r["ok"])

    def test_summary_with_known_value_rejected(self):
        self.session.new_entity("Falcon", "PROJECT")
        [r] = self.apply({"op": "collapse", "item": "#1", "start": 2, "end": 2, "first": "secret 1", "last": "secret 1", "summary": "Falcon creds"})
        self.assertFalse(r["ok"])
        self.assertIn("sensitive value", r["error"])


class EnvVarKeysOnly(unittest.TestCase):
    def test_literal_key_rejected(self):
        with self.assertRaises(ValidationError):
            ProviderConfig(name="p", base_url="http://x", api_key="sk-literal")

    def test_credential_in_static_headers_rejected(self):
        with self.assertRaises(ValidationError):
            ProviderConfig(name="p", base_url="http://x", headers={"Authorization": "Bearer sk-x"})

    def test_gui_marker_and_keyless_local_provider_accepted(self):
        p = ProviderConfig.model_validate({"name": "p", "base_url": "http://127.0.0.1:11434", "api_key": "<configured>"})
        self.assertIsNone(p.resolved_key())
        self.assertNotIn("authorization", headers_for(p, {}))

    def test_example_config_is_valid(self):
        from pathlib import Path
        load_config(Path(__file__).resolve().parents[1] / "masqai.json.example")


class HeaderPolicies(unittest.TestCase):
    INCOMING = {"User-Agent": "opencode/1", "X-Title": "app", "Cookie": "c", "api-key": "azure", "x-goog-api-key": "g",
                "Authorization": "Bearer client", "Host": "localhost", "Connection": "keep-alive, X-Hop", "X-Hop": "1", "X-Custom": "v", "x-stainless-os": "Windows"}

    def forwarded(self, policy):
        return headers_for(ProviderConfig(name="p", base_url="http://x"), self.INCOMING, policy)

    def test_default_blocklist_forwards_everything_but_credentials(self):
        out = self.forwarded(HeaderPolicy())
        self.assertEqual(set(out), {"User-Agent", "X-Title", "X-Custom", "x-stainless-os"})

    def test_allowlist_mode(self):
        out = self.forwarded(HeaderPolicy(mode="allowlist"))
        self.assertEqual(set(out), {"User-Agent", "X-Title", "x-stainless-os"})

    def test_custom_lists_and_wildcards(self):
        self.assertNotIn("x-stainless-os", self.forwarded(HeaderPolicy(blocklist=["x-stainless-*"])))
        self.assertIn("Cookie", self.forwarded(HeaderPolicy(blocklist=[])))
        self.assertEqual(set(self.forwarded(HeaderPolicy(mode="allowlist", allowlist=["x-custom"]))), {"X-Custom"})

    def test_auth_always_dropped_even_if_allowlisted(self):
        out = self.forwarded(HeaderPolicy(mode="allowlist", allowlist=["authorization", "host"]))
        self.assertEqual(out, {})

    def test_policy_is_part_of_config(self):
        config = GatewayConfig.model_validate({"headers": {"mode": "allowlist", "allowlist": ["accept"]}})
        self.assertEqual(config.headers.mode, "allowlist")
        with self.assertRaises(ValidationError):
            GatewayConfig.model_validate({"headers": {"mode": "whitelist"}})


if __name__ == "__main__":
    unittest.main()
