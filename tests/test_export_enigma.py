import unittest

from scripts.export_enigma import validate


class ExportSchema(unittest.TestCase):
    def test_export_keeps_only_public_timeline_fields(self):
        payload = validate({
            "status": "live", "provider": "OpenRouter", "keys": [{
                "label": "enigma-001", "createdAt": 0, "activeUntil": 300, "revokedAt": 330,
                "hash": "a" * 64, "key": "must-not-export",
            }], "honeytokens": [{"secret": "ignored"}],
        })
        self.assertEqual(payload, {"status": "live", "provider": "OpenRouter", "keys": [{
            "label": "enigma-001", "createdAt": 0, "activeUntil": 300, "revokedAt": 330,
        }], "honeytokens": []})

    def test_export_rejects_bad_times_and_non_live_payloads(self):
        for payload in (
            {"status": "planned", "provider": "OpenRouter", "keys": []},
            {"status": "live", "provider": "OpenRouter", "keys": [{
                "label": "x", "createdAt": float("nan"), "activeUntil": 1, "revokedAt": 2,
            }]},
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                validate(payload)


if __name__ == "__main__":
    unittest.main()
