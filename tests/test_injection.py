"""The injection runner's scoring, against a scripted security model (obedient vs. resistant)."""
import asyncio
import unittest
from unittest.mock import patch

import httpx

from tests.helpers import Fakes, REAL_ASYNC_CLIENT, make_config
from tests.injection.run_injection import config_for, load_fixtures, run_one


def run(fixture, answers):
    fakes = Fakes()
    fakes.security_answers = list(answers)
    factory = lambda **kw: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(fakes.handler), **kw)
    with patch("httpx.AsyncClient", factory):
        return asyncio.run(run_one(config_for(make_config(security=True), fixture), fixture))


class InjectionScoring(unittest.TestCase):
    def setUp(self):
        self.fixtures = {f["attack"]: f for f in load_fixtures()}

    def test_obedient_model_loses_every_attack(self):
        self.assertEqual(run(self.fixtures["return empty operations"], [[]]), (True, False))
        unmask = {"op": "unmask", "item": "#2", "line": 1, "text": "alice_7f3a"}
        self.assertEqual(run(self.fixtures["unmask a real secret"], [[unmask]]), (True, False))
        def obey_relink(model_input):
            keys = [e["token"] for e in model_input["mapping"] if e["type"] == "OR_KEY"]
            return [{"op": "relink", "token": keys[0], "to": keys[1]}]
        self.assertEqual(run(self.fixtures["wrong relink"], [obey_relink]), (True, False))

    def test_resistant_model_wins(self):
        mask_name = [{"op": "mask", "item": "#2", "line": 1, "text": "Dana Whitfield", "type": "USER"},
                     {"op": "mask", "item": "#2", "line": 1, "text": "+1 617-555-0142", "type": "PHONE"}]
        self.assertEqual(run(self.fixtures["return empty operations"], [mask_name]), (False, False))
        self.assertEqual(run(self.fixtures["unmask a real secret"], [[]]), (False, False))
        self.assertEqual(run(self.fixtures["wrong relink"], [[]]), (False, False))


if __name__ == "__main__":
    unittest.main()
