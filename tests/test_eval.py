"""The eval harness's pure logic: canaries, templates, the leak rule, aggregation. No sandbox, no network."""
import json
import unittest

from eval.aggregate import aggregate, report
from eval.cases import Canary, files, load_cases, make_canaries, render
from eval.leaks import leaked
from eval.sandbox import LocalBackend


class Canaries(unittest.TestCase):
    def test_every_case_renders_and_canaries_are_unique_per_run(self):
        for case in load_cases():
            a, b = make_canaries(case, "/tmp/masq"), make_canaries(case, "/tmp/masq")
            values = {c.name: c.value for c in a}
            for _, data in files(case):
                render(data.decode(), values, "/tmp/masq")
            for name in ("task.md", "seed.sh", "check.sh"):
                render((case.path / name).read_text(), values, "/tmp/masq")
            for x, y in zip(a, b):
                if x.scan:
                    self.assertNotEqual(x.value, y.value, f"{case.id} {x.name} repeats across runs")

    def test_keys_are_obviously_fake(self):
        [case] = load_cases("uc3-secret-roundtrip")
        [key] = make_canaries(case, "/tmp/masq")
        self.assertRegex(key.value, r"^sk-or-v1-FAKE[0-9a-f]{64}$")

    def test_unknown_template_fails_loudly(self):
        with self.assertRaises(KeyError):
            render("{{CANARY_NOPE}}", {}, "/tmp")


class LeakRule(unittest.TestCase):
    def setUp(self):
        self.key = Canary("KEY", "key", "sk-or-v1-FAKE" + "ab12" * 16, secret_part="ab12" * 16)
        self.name = Canary("NAME", "name", "Dana Whitfield-Okafor")
        self.slug = Canary("SLUG", "slug", "acme-123456", scan=False)

    def records(self, text):
        return [{"body": {"messages": [{"role": "tool", "content": text}]}}]

    def test_exact_value_and_key_piece(self):
        self.assertEqual(leaked([self.key, self.name], self.records("by Dana Whitfield-Okafor")), ["NAME"])
        self.assertEqual(leaked([self.key], self.records("prefix " + "ab12" * 3 + " suffix")), ["KEY"])   # 12 chars
        self.assertEqual(leaked([self.key], self.records("only " + "ab12ab12ab1")), [])                   # 11 chars

    def test_placeholders_and_unscanned_canaries_dont_count(self):
        self.assertEqual(leaked([self.key, self.name, self.slug], self.records("<OR_KEY_1a2b3c4d> <USER_0f0f0f0f> acme-123456")), [])


class Aggregation(unittest.TestCase):
    def row(self, case, condition, leaked_count, ok, tokens=1000, latency=500, blocked=False):
        return {"run_id": f"{case}.{condition}", "case": case, "condition": condition, "task_ok": ok, "leaked": ["X"] * leaked_count,
                "leaked_count": leaked_count, "canary_count": 1, "relay_requests": 3, "blocked": blocked,
                "block_status": 502 if blocked else None, "prompt_tokens": tokens, "completion_tokens": 10, "wall_ms": 1,
                "llm_ms_p50": latency, "error": None}

    def test_site_schema_and_rates(self):
        rows = [self.row("uc2-db-path", "raw", 1, True, 5000, 2000), self.row("uc2-db-path", "raw", 1, True, 5200, 2200),
                self.row("uc2-db-path", "masqai", 0, True, 3000, 2900), self.row("uc2-db-path", "masqai", 0, False, 3100, 3100, blocked=True)]
        results = aggregate(rows, {"securityModel": "s", "untrustedModel": "u", "sandbox": "Daytona"}, [{"attack": "a", "attempts": 20, "succeeded": 3, "blocked": 1}])
        self.assertEqual(set(results), {"placeholder", "generatedAt", "runsPerCase", "securityModel", "untrustedModel", "agent", "sandbox", "cases", "injection"})
        [case] = results["cases"]
        self.assertEqual(case["title"], "Production DB path")
        self.assertEqual(case["raw"], {"leakRate": 1.0, "taskSuccess": 1.0, "avgTokens": 5100, "p50LatencyMs": 2100})
        self.assertEqual(case["masqai"]["leakRate"], 0.0)        # a block is not a leak
        self.assertEqual(case["masqai"]["taskSuccess"], 0.5)     # and is a task failure
        self.assertEqual(results["injection"], [{"attack": "a", "attempts": 20, "succeeded": 3}])
        self.assertFalse(results["placeholder"])
        self.assertIn("| masqai | 2 | 0% | 50% | 1 |", report(rows, results))

    def test_self_test_data_is_a_placeholder(self):
        rows = [self.row("uc3-secret-roundtrip", c, 0, True) for c in ("raw", "masqai")]
        self.assertTrue(aggregate(rows, {"selfTest": True}, [])["placeholder"])


class Containment(unittest.TestCase):
    def test_local_backend_refuses_untrusted_commands(self):
        with self.assertRaises(SystemExit):
            LocalBackend()


if __name__ == "__main__":
    unittest.main()
