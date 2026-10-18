import unittest
from health import health


class HealthTests(unittest.TestCase):
    def test_ready(self):
        self.assertEqual(health("ready"), {"ok": True, "status": "ready"})


if __name__ == "__main__":
    unittest.main()
