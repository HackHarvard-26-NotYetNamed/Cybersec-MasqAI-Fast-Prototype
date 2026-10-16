"""Occurrence-bound operations: boundaries, aliases, relink, veto, JSON safety, nearest operations."""
import json
import unittest

from masqai.adapter import extract
from masqai.config import DetectorConfig, GatewayConfig, SecurityModelConfig
from masqai.model import Session
from masqai.ops import Applier, address, locate, plan_all
from masqai.sanitize import Sanitizer


def items_of(*contents, role="tool"):
    payload = {"messages": [{"role": role, "tool_call_id": str(i), "content": c} if role == "tool" else {"role": role, "content": c}
                            for i, c in enumerate(contents)]}
    return extract(payload, "openai")


def apply(session, items, *ops, veto=False):
    results = Applier(session, items, veto, 1).apply(list(ops))
    plan_all(session, items)
    return results


class Addressing(unittest.TestCase):
    def test_locate_and_address_round_trip(self):
        text = "ab ANDY ab\nANDY and ANDY\nANDY"
        start, end = locate(text, 2, "ANDY", 2)
        self.assertEqual(text[start:end], "ANDY")
        self.assertEqual(address(text, start, end), {"line": 2, "text": "ANDY", "nth": 2})

    def test_multiline_text_starting_on_line(self):
        text = "x\n-----BEGIN KEY-----\nabc\n-----END KEY-----\ny"
        start, end = locate(text, 2, "-----BEGIN KEY-----\nabc\n-----END KEY-----")
        self.assertEqual(text[end:], "\ny")

    def test_errors_explain(self):
        with self.assertRaisesRegex(ValueError, "another line"):
            locate("a\nb", 1, "b")
        with self.assertRaisesRegex(ValueError, "occurs 1 time"):
            locate("a a", 1, "a a", 2)


class AutoMask(unittest.TestCase):
    def test_boundary_rule(self):
        session = Session("s")
        session.new_entity("ANDY", "USERNAME", "detector:host")
        [item] = items_of("HANDY ANDY C:\\Users\\ANDY\\x ANDY_1 ANDY.")
        plan_all(session, [item])
        self.assertEqual(item.sanitized.count("<USERNAME_"), 3)
        self.assertIn("HANDY", item.sanitized)
        self.assertIn("ANDY_1", item.sanitized)
        self.assertEqual([u["reason"] for u in item.unmasked], ["inside a word", "inside a word"])

    def test_json_escaped_copy_in_tool_arguments(self):
        session = Session("s")
        session.new_entity("C:\\Users\\ANDY", "PATH")
        payload = {"messages": [{"role": "assistant", "content": None, "tool_calls": [
            {"id": "1", "type": "function", "function": {"name": "bash", "arguments": json.dumps({"cwd": "C:\\Users\\ANDY"})}}]}]}
        [item] = extract(payload, "openai")
        plan_all(session, [item])
        self.assertEqual(json.loads(item.sanitized)["cwd"], next(iter(session.entities)))

    def test_model_mask_inside_word_overrides_boundary(self):
        session = Session("s")
        session.new_entity("ANDY", "USERNAME")
        items = items_of("xANDYx")
        [r] = apply(session, items, {"op": "mask", "item": "#1", "line": 1, "text": "ANDY", "token": next(iter(session.entities))})
        self.assertTrue(r["ok"], r)
        self.assertEqual(items[0].sanitized, f"x{next(iter(session.entities))}x")


class Aliases(unittest.TestCase):
    def setUp(self):
        self.session = Session("s")
        self.token = self.session.new_entity("C:\\Users\\ANDY\\proj", "PATH").token
        self.items = items_of("cd C:/Users/ANDY/proj\nthen C:/Users/ANDY/proj again")

    def test_alias_is_one_occurrence_only(self):
        [r] = apply(self.session, self.items, {"op": "mask", "item": "#1", "line": 1, "text": "C:/Users/ANDY/proj", "token": self.token, "alias": True})
        self.assertTrue(r["ok"], r)
        alias = self.token.replace("<", "<$")
        self.assertEqual(self.items[0].sanitized, f"cd {alias}\nthen C:/Users/ANDY/proj again")

    def test_predicted_alias_cannot_be_added(self):
        [r] = apply(self.session, self.items, {"op": "mask", "item": "#1", "line": 1, "text": "/Users/ANDY/other", "token": self.token, "alias": True})
        self.assertFalse(r["ok"])

    def test_non_alias_must_equal_value(self):
        [r] = apply(self.session, self.items, {"op": "mask", "item": "#1", "line": 1, "text": "C:/Users/ANDY/proj", "token": self.token})
        self.assertFalse(r["ok"])
        self.assertIn("alias:true", r["error"])

    def test_restore_table_resolves_alias_to_canonical(self):
        apply(self.session, self.items, {"op": "mask", "item": "#1", "line": 1, "text": "C:/Users/ANDY/proj", "token": self.token, "alias": True})
        self.assertEqual(self.session.restore_table(), [{"token": self.token, "canonical": "C:\\Users\\ANDY\\proj"}])


class Relink(unittest.TestCase):
    def test_partial_then_full(self):
        session = Session("s")
        first = items_of("key sk-...def")
        apply(session, first, {"op": "mask", "item": "#1", "line": 1, "text": "sk-...def", "type": "KEY"})
        partial = next(iter(session.entities))
        both = first + items_of("full sk-abc123def")
        results = apply(session, both,
                        {"op": "mask", "item": "#2", "line": 1, "text": "sk-abc123def", "type": "KEY", "label": "k"},
                        {"op": "relink", "token": partial, "to": "k"})
        self.assertTrue(all(r["ok"] for r in results), results)
        full = session.entity_for("sk-abc123def").token
        self.assertEqual(first[0].sanitized, "key " + full.replace("<", "<$"))
        self.assertEqual(both[1].sanitized, "full " + full)
        restore = {r["token"]: r["canonical"] for r in session.restore_table()}
        self.assertEqual(restore[partial], "sk-abc123def")


class Overlaps(unittest.TestCase):
    def test_crossing_rejected_containing_accepted(self):
        session = Session("s")
        session.new_entity("ANDY", "USERNAME")
        items = items_of("path C:\\Users\\ANDY\\x end")
        [crossing] = apply(session, items, {"op": "mask", "item": "#1", "line": 1, "text": "Users\\AN", "type": "X"})
        self.assertFalse(crossing["ok"])
        self.assertIn("crosses", crossing["error"])
        [containing] = apply(session, items, {"op": "mask", "item": "#1", "line": 1, "text": "C:\\Users\\ANDY\\x", "type": "PATH"})
        self.assertTrue(containing["ok"], containing)
        self.assertEqual(items[0].sanitized.count("<"), 1)
        self.assertIn("<PATH_", items[0].sanitized)

    def test_json_structure_protected(self):
        session = Session("s")
        payload = {"messages": [{"role": "assistant", "content": None, "tool_calls": [
            {"id": "1", "type": "function", "function": {"name": "bash", "arguments": '{"cmd": "ls"}'}}]}]}
        items = extract(payload, "openai")
        [r] = apply(session, items, {"op": "mask", "item": "#1", "line": 1, "text": '"cmd": "ls"', "type": "X"})
        self.assertFalse(r["ok"])
        self.assertIn("JSON", r["error"])


class Veto(unittest.TestCase):
    def test_veto_only_when_enabled(self):
        session = Session("s")
        session.new_entity("Mercury", "PROJECT")
        items = items_of("Mercury is a planet")
        [r] = apply(session, items, {"op": "unmask", "item": "#1", "line": 1, "text": "Mercury"})
        self.assertFalse(r["ok"])
        [r] = apply(session, items, {"op": "unmask", "item": "#1", "line": 1, "text": "Mercury"}, veto=True)
        self.assertTrue(r["ok"], r)
        self.assertEqual(items[0].sanitized, "Mercury is a planet")
        self.assertEqual(items[0].unmasked[0]["reason"], "vetoed by the security model")


class Input(unittest.TestCase):
    def sanitizer(self, **security):
        return Sanitizer(GatewayConfig(security=SecurityModelConfig(**security), detectors=DetectorConfig(detect_host_identifiers=False)))

    def history(self):
        session = Session("s")
        old = items_of("one ALPHA\n2\n3\n4\n5\n6", "two BRAVO")
        apply(session, old, {"op": "mask", "item": "#1", "line": 1, "text": "ALPHA", "type": "A"},
              {"op": "mask", "item": "#2", "line": 1, "text": "BRAVO", "type": "B"})
        session.inspected.update(i.id for i in old)
        items = old + items_of("new text")
        plan_all(session, items)
        return session, items

    def test_nearest_ops_and_context_lines(self):
        session, items = self.history()
        payload = self.sanitizer(nearest_ops=1, op_context_lines=1)._input(session, items, [items[2]])
        [op] = payload["existing_operations"]
        self.assertEqual(op["text"], "BRAVO")     # the nearer item
        payload = self.sanitizer(nearest_ops=-1, op_context_lines=1)._input(session, items, [items[2]])
        self.assertEqual([o["text"] for o in payload["existing_operations"]], ["BRAVO", "ALPHA"])
        self.assertEqual([l["n"] for l in payload["existing_operations"][1]["context"]], [1, 2])

    def test_full_mode_is_unlimited(self):
        session, items = self.history()
        payload = self.sanitizer(context_mode="full", nearest_ops=0, op_context_lines=0, recent_items=0)._input(session, items, [items[2]])
        self.assertEqual(len(payload["existing_operations"]), 2)
        self.assertEqual(len(payload["existing_operations"][1]["context"]), 6)
        self.assertEqual(len(payload["recent_tool_context"]), 2)

    def test_conversation_keeps_every_message(self):
        session = Session("s")
        items = items_of(*[f"user {i}" for i in range(30)], role="user")
        plan_all(session, items)
        payload = self.sanitizer(recent_items=0)._input(session, items, [items[-1]])
        self.assertEqual(len(payload["conversation"]), 29)


if __name__ == "__main__":
    unittest.main()
