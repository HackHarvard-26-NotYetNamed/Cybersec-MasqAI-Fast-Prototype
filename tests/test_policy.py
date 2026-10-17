"""What to protect: the user's own category selection (config `protect`, masqai/policy.py)."""
import json
import unittest

from masqai.config import CustomValue, DetectorConfig, GatewayConfig
from masqai.detectors import seed_entities
from masqai.model import Session
from masqai.ops import Applier, plan_all
from masqai.policy import CATEGORIES, category_of, model_policy, protected
from masqai.sanitize import Sanitizer
from tests.helpers import api, gateway, make_config
from tests.test_core import tool_items

KEY = "sk-or-v1-FAKE" + "ab90" * 15
EMAIL = "dana.whitfield@corp-mail.example"


def selection(**off):
    return {c.id: c.id not in off for c in CATEGORIES}


def apply(session, items, protect, *ops):
    results = Applier(session, items, True, 1, protect).apply(list(ops))
    plan_all(session, items)
    return results


class Categories(unittest.TestCase):
    def test_types_map_to_categories(self):
        cases = {"OR_KEY": "credentials", "PRIVATE_KEY": "credentials", "DB_PASSWORD": "credentials", "STAGING_API_KEY": "credentials",
                 "PATH": "file_paths", "APP_DATA_PATH": "file_paths", "USERNAME": "machine_identity", "HOST": "machine_identity",
                 "EMAIL": "emails", "USER": "people", "PHONE": "people", "TEAMMATE": "people", "ADDRESS": "locations"}
        for entity_type, category in cases.items():
            with self.subTest(entity_type):
                self.assertEqual(category_of(entity_type), category)

    def test_unknown_types_stay_protected(self):
        everything_off = {c.id: False for c in CATEGORIES}
        for odd in ("WIDGET", "", None, 42, ["EMAIL"]):
            with self.subTest(odd):
                self.assertTrue(protected(everything_off, odd))

    def test_config_rejects_unknown_categories(self):
        with self.assertRaises(Exception):
            GatewayConfig.model_validate({"protect": {"emails": False, "pets": False}})
        self.assertTrue(all(GatewayConfig().protect.model_dump().values()))

    def test_model_gets_both_lists(self):
        policy = model_policy(selection(emails=1, locations=1))
        self.assertEqual({e["category"] for e in policy["do_not_protect"]}, {"emails", "locations"})
        self.assertIn("credentials", {e["category"] for e in policy["protect"]})


class Detectors(unittest.TestCase):
    def test_switched_off_detector_categories_are_not_seeded(self):
        session = Session("s")
        items = tool_items(f"key {KEY} mail {EMAIL}")
        seed_entities(session, items, DetectorConfig(detect_host_identifiers=False), selection(emails=1))
        plan_all(session, items)
        self.assertNotIn(KEY, items[0].sanitized)
        self.assertIn(EMAIL, items[0].sanitized)

    def test_custom_values_are_always_masked(self):
        session = Session("s")
        items = tool_items(f"mail {EMAIL}")
        detectors = DetectorConfig(detect_host_identifiers=False, custom_values=[CustomValue(type="EMAIL", value=EMAIL)])
        seed_entities(session, items, detectors, selection(emails=1))
        plan_all(session, items)
        self.assertNotIn(EMAIL, items[0].sanitized)


class SecurityModelOps(unittest.TestCase):
    def test_mask_in_a_switched_off_category_is_a_no_op(self):
        session, items = Session("s"), tool_items(f"written by Dana Whitfield <{EMAIL}>")
        name, mail = apply(session, items, selection(emails=1),
                           {"op": "mask", "item": "#1", "line": 1, "text": "Dana Whitfield", "type": "USER"},
                           {"op": "mask", "item": "#1", "line": 1, "text": EMAIL, "type": "EMAIL"})
        self.assertTrue(mail["ok"])
        self.assertIn("not protected", mail["effect"])
        self.assertIn(EMAIL, items[0].sanitized)
        self.assertNotIn("Dana Whitfield", items[0].sanitized)

    def test_intel_ops_follow_their_category(self):
        session, items = Session("s"), tool_items("PATH=/usr/bin\nHOME=/srv\nlives at 12 Elm St, Somerville")
        hide, replace = apply(session, items, selection(infrastructure=1, locations=1),
                              {"op": "hide", "item": "#1", "start": 1, "end": 2, "first": "PATH=/usr/bin", "last": "HOME=/srv",
                               "summary": "env", "category": "infrastructure"},
                              {"op": "replace", "item": "#1", "line": 3, "text": "12 Elm St, Somerville", "with": "a nearby street",
                               "category": "locations"})
        self.assertTrue(hide["ok"] and replace["ok"])
        self.assertEqual(items[0].sanitized, items[0].original)

    def test_a_policy_miss_never_costs_a_correction_round(self):
        """Even an op that would be invalid is accepted as a no-op when its category is off."""
        session, items = Session("s"), tool_items("x")
        [r] = apply(session, items, selection(emails=1), {"op": "mask", "item": "#9", "line": 7, "text": "nope", "type": "EMAIL"})
        self.assertTrue(r["ok"])

    def test_without_a_category_the_op_applies(self):
        session, items = Session("s"), tool_items("PATH=/usr/bin\nHOME=/srv")
        [r] = apply(session, items, selection(infrastructure=1),
                    {"op": "hide", "item": "#1", "start": 1, "end": 2, "first": "PATH=/usr/bin", "last": "HOME=/srv", "summary": "env"})
        self.assertTrue(r["ok"])
        self.assertNotEqual(items[0].sanitized, items[0].original)

    def test_security_model_input_carries_the_policy(self):
        cfg = make_config(security=True).model_copy(update={"protect": make_config().protect.model_copy(update={"emails": False})})
        session, items = Session("s"), tool_items("hello")
        payload = Sanitizer(cfg)._input(session, items, items)
        self.assertEqual([e["category"] for e in payload["policy"]["do_not_protect"]], ["emails"])


class EndToEnd(unittest.TestCase):
    def test_gateway_sends_unprotected_categories_as_they_are(self):
        cfg = make_config().model_copy(update={"protect": make_config().protect.model_copy(update={"emails": False})})
        with gateway(cfg) as (app, client, fakes):
            client.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": f"key {KEY}, mail {EMAIL}"}]})
            sent = fakes.upstream_calls[-1].content.decode()
            self.assertNotIn(KEY, sent)
            self.assertIn(EMAIL, sent)

    def test_gui_can_change_the_selection(self):
        with gateway(make_config()) as (app, client, fakes):
            settings = api(client, "GET", "/api/config").json()
            self.assertTrue(settings["protect"]["emails"])
            settings["protect"]["emails"] = False
            self.assertEqual(api(client, "POST", "/api/config", json=settings).status_code, 200)
            client.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": f"mail {EMAIL}"}]})
            self.assertIn(EMAIL, fakes.upstream_calls[-1].content.decode())


if __name__ == "__main__":
    unittest.main()
