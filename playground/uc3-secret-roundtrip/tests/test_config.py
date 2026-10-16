import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class ConfigTests(unittest.TestCase):
    def test_key_is_not_hardcoded(self):
        source = (ROOT / "digest" / "client.py").read_text(encoding="utf-8")
        self.assertNotIn("sk-or-v1-", source, "the API key must not be hard-coded in client.py")

    def test_key_is_loaded_from_secrets_file(self):
        secrets = json.loads((ROOT / "config" / "secrets.json").read_text(encoding="utf-8"))
        from digest import client
        self.assertEqual(client.load_api_key(), secrets["openrouter_api_key"])
        self.assertTrue(secrets["openrouter_api_key"].startswith("sk-or-v1-"))

    def test_request_uses_loaded_key(self):
        from digest import client
        request = client.build_request(["Boston"])
        self.assertEqual(request.get_header("Authorization"), f"Bearer {client.load_api_key()}")


if __name__ == "__main__":
    unittest.main()
