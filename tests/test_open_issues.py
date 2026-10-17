"""Open detector issues found in review (expected failures until fixed). Remove a decorator only when the
test passes unchanged."""
import unittest

from masqai.detectors import load_rules, scan
from masqai.model import Session
from masqai.ops import plan_all
from tests.test_core import tool_items


def sent(entity_type, value, text):
    session = Session("s")
    session.new_entity(value, entity_type, "detector:host")
    items = tool_items(text)
    plan_all(session, items)
    return items[0].sanitized


class HostIdentifiersNextToADot(unittest.TestCase):
    """7e9d4ec made a dot count as part of the word for USERNAME/HOST, so a hostname written as a domain name
    (ssh, ping, /etc/hosts) or a username in an email goes out unmasked. Before 7e9d4ec all of these were masked."""

    def test_hostname_as_a_domain_name_is_masked(self):
        for value, text in [("DESKTOP-7Q2XK9M", "ping DESKTOP-7Q2XK9M.local"), ("archbook", "ssh me@archbook.lan")]:
            with self.subTest(text):
                self.assertNotIn(value, sent("HOST", value, text))

    def test_username_before_a_dot_is_masked(self):
        for text in ["git config user.email alice.smith@corp.com", "alice.log written"]:
            with self.subTest(text):
                self.assertNotIn("alice", sent("USERNAME", "alice", text))


class TemplatedValues(unittest.TestCase):
    """detectors.templated() treats any value starting with $ % * # as a template, so a real password that
    starts with a symbol isn't masked by the key=value detector. `${VAR}` / `$VAR` references should stay exempt."""

    def test_password_starting_with_a_symbol_is_detected(self):
        rules = load_rules("masqai/rules")
        for value in ["$ecureP@ss1", "%Tr0ub4dor&3", "#hunter2hunter2"]:
            with self.subTest(value):
                self.assertIn(value, [f.value for f in scan(f"DB_PASSWORD={value}", rules)])

    def test_shell_references_stay_exempt(self):
        rules = load_rules("masqai/rules")
        for text in ["DB_PASSWORD=${DB_PASSWORD}", "DB_PASSWORD=$DB_PASSWORD"]:
            with self.subTest(text):
                self.assertEqual(scan(text, rules), [])


if __name__ == "__main__":
    unittest.main()
