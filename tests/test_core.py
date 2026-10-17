"""Milestone 1: the core library without network. Ops (mask, hide, replace, relink, unmask), auto masks,
detectors as data, config validation. All values are synthetic."""
import json
import unittest

from masqai.adapter import extract
from masqai.config import DetectorConfig, GatewayConfig, SecurityModelConfig
from masqai.detectors import load_rules, scan, seed_entities
from masqai.model import Session
from masqai.ops import Applier, plan_all


def tool_items(*contents):
    payload = {"messages": [{"role": "tool", "tool_call_id": str(i), "content": c} for i, c in enumerate(contents)]}
    return extract(payload, "openai")


def apply(session, items, *ops, veto=True):
    results = Applier(session, items, veto, 1).apply(list(ops))
    plan_all(session, items)
    return results


class Hide(unittest.TestCase):
    def test_hide_renders_marker_and_checks_anchors(self):
        session = Session("s")
        items = tool_items("keep\nA=1\nB=2\nkeep too")
        bad, good = apply(session, items,
                          {"op": "hide", "item": "#1", "start": 2, "end": 3, "first": "A=1", "last": "wrong", "summary": "x"},
                          {"op": "hide", "item": "#1", "start": 2, "end": 3, "first": "A=1", "last": "B=2", "summary": "2 variables", "reason": "noise"})
        self.assertFalse(bad["ok"])
        self.assertTrue(good["ok"], good)
        self.assertEqual(items[0].sanitized, "keep\n…[hidden: 2 variables]…\nkeep too")
        self.assertEqual(items[0].hides[0]["class"], "intel")
        self.assertEqual(items[0].hides[0]["reason"], "noise")

    def test_hide_only_in_tool_results(self):
        session = Session("s")
        items = extract({"messages": [{"role": "user", "content": "a\nb"}]}, "openai")
        [r] = apply(session, items, {"op": "hide", "item": "#1", "start": 1, "end": 1, "first": "a", "last": "a", "summary": "s"})
        self.assertFalse(r["ok"])
        self.assertIn("only applies to tool results", r["error"])

    def test_summary_must_not_leak_known_values_or_placeholders(self):
        session = Session("s")
        token = session.new_entity("DESKTOP-7Q2XK9M", "HOST").token
        items = tool_items("a\nb")
        leak, ph = apply(session, items,
                         {"op": "hide", "item": "#1", "start": 1, "end": 1, "first": "a", "last": "a", "summary": "host DESKTOP-7Q2XK9M"},
                         {"op": "hide", "item": "#1", "start": 2, "end": 2, "first": "b", "last": "b", "summary": f"host {token}"})
        self.assertFalse(leak["ok"])
        self.assertFalse(ph["ok"])


class Replace(unittest.TestCase):
    def test_replace_one_occurrence(self):
        session = Session("s")
        items = tool_items("Meet near Somerville, MA.\nAlso Somerville, MA again.")
        [r] = apply(session, items, {"op": "replace", "item": "#1", "line": 2, "text": "Somerville, MA", "with": "a nearby city", "reason": "location"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(items[0].sanitized, "Meet near Somerville, MA.\nAlso a nearby city again.")
        self.assertEqual(items[0].replaces[0]["with"], "a nearby city")
        # Lossy and never restored: no entity, nothing in the restore table.
        self.assertEqual(session.restore_table(), [])

    def test_replace_rules(self):
        session = Session("s")
        token = session.new_entity("alice_7f3a", "USER").token
        items = tool_items("by alice_7f3a in Boston")
        overlap, multiline, ok = apply(session, items,
                                       {"op": "replace", "item": "#1", "line": 1, "text": "alice_7f3a in", "with": "someone in"},
                                       {"op": "replace", "item": "#1", "line": 1, "text": "Boston", "with": "a\ncity"},
                                       {"op": "replace", "item": "#1", "line": 1, "text": "Boston", "with": "a city"})
        self.assertFalse(overlap["ok"])
        self.assertFalse(multiline["ok"])
        self.assertTrue(ok["ok"], ok)
        self.assertEqual(items[0].sanitized, f"by {token} in a city")

    def test_replace_only_in_tool_results(self):
        session = Session("s")
        items = extract({"messages": [{"role": "user", "content": "near Somerville, MA"}]}, "openai")
        [r] = apply(session, items, {"op": "replace", "item": "#1", "line": 1, "text": "Somerville, MA", "with": "a city"})
        self.assertFalse(r["ok"])


class AutoMasksAndVeto(unittest.TestCase):
    def test_andy_handy_boundary(self):
        session = Session("s")
        token = session.new_entity("andy", "USER", "detector:custom").token
        [item] = tool_items("handy andy andy_x (andy)")
        plan_all(session, [item])
        self.assertEqual(item.sanitized, f"handy {token} andy_x ({token})")
        self.assertEqual(sorted(u["reason"] for u in item.unmasked), ["inside a word", "inside a word"])

    def test_short_values_are_never_auto_copied(self):
        session = Session("s")
        session.new_entity("ab", "USER")
        [item] = tool_items("ab ab")
        plan_all(session, [item])
        self.assertEqual(item.sanitized, "ab ab")

    def test_veto_records_reason(self):
        session = Session("s")
        session.new_entity("alice", "USERNAME", "detector:host")
        items = tool_items("theme: alice-blue")
        [r] = apply(session, items, {"op": "unmask", "item": "#1", "line": 1, "text": "alice", "reason": "a color name"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(items[0].sanitized, "theme: alice-blue")
        self.assertIn("a color name", session.veto_reasons.values())

    def test_unmask_disabled_without_auto_veto(self):
        session = Session("s")
        session.new_entity("alice", "USERNAME")
        items = tool_items("alice")
        [r] = apply(session, items, {"op": "unmask", "item": "#1", "line": 1, "text": "alice"}, veto=False)
        self.assertFalse(r["ok"])

    def test_url_encoded_auto_mask(self):
        session = Session("s")
        session.new_entity("C:/Users/alice/data", "PATH")
        items = tool_items("curl http://example.com/C%3A/Users/alice/data")
        plan_all(session, items)
        self.assertIn("<PATH_", items[0].sanitized)


class RelinkAndRestore(unittest.TestCase):
    def test_relink_rewrites_and_restores_to_root(self):
        session = Session("s")
        items = tool_items("key=sk-or-v1-a3f...9e1", "full: sk-or-v1-FAKEFAKEa3f00000000000000000000009e1")
        [frag] = apply(session, items, {"op": "mask", "item": "#1", "line": 1, "text": "sk-or-v1-a3f...9e1", "type": "OR_KEY", "label": "f"})
        self.assertTrue(frag["ok"], frag)
        fragment = next(iter(session.entities))
        [full] = apply(session, items, {"op": "mask", "item": "#2", "line": 1, "text": "sk-or-v1-FAKEFAKEa3f00000000000000000000009e1", "type": "OR_KEY"})
        full_token = [t for t in session.entities if t != fragment][0]
        [link] = apply(session, items, {"op": "relink", "token": fragment, "to": full_token})
        self.assertTrue(link["ok"], link)
        alias = full_token.replace("<", "<$", 1)
        self.assertEqual(items[0].sanitized, f"key={alias}")
        self.assertEqual(session.relinks[0]["from"], fragment)
        # Both the old token and the <$…> form restore to the full (root) value.
        table = {e["token"]: e["canonical"] for e in session.restore_table()}
        self.assertEqual(table[fragment], "sk-or-v1-FAKEFAKEa3f00000000000000000000009e1")

    def test_class_and_reason_on_new_entity(self):
        session = Session("s")
        items = tool_items("owner: Dana Whitfield")
        [r] = apply(session, items, {"op": "mask", "item": "#1", "line": 1, "text": "Dana Whitfield", "type": "USER", "class": "secret", "reason": "a name"})
        entity = next(iter(session.entities.values()))
        self.assertEqual((entity.cls, entity.reason, entity.origin), ("secret", "a name", "model"))
        [bad] = apply(session, items, {"op": "mask", "item": "#1", "line": 1, "text": "owner", "type": "X", "class": "maybe"})
        self.assertFalse(bad["ok"])


class Detectors(unittest.TestCase):
    def found(self, text):
        return {(f.type, f.value) for f in scan(text, load_rules())}

    def test_key_families(self):
        samples = {
            "OR_KEY": "sk-or-v1-FAKEFAKE0123456789abcdef0123456789",
            "ANTHROPIC_KEY": "sk-ant-FAKEFAKE0123456789abcdefABCD",
            "OPENAI_KEY": "sk-proj-FAKEFAKE0123456789abcdefABCD",
            "AWS_KEY": "AKIAFAKEFAKEFAKE1234",
            "STRIPE_KEY": "sk_live_FAKEFAKE0123456789ab",
            "GOOGLE_KEY": "AIza" + "F" * 35,
            "SLACK_TOKEN": "xoxb-FAKE-FAKE-1234567890",
            "GITLAB_TOKEN": "glpat-FAKEFAKEFAKEFAKEFAKE1",
            "NPM_TOKEN": "npm_" + "F" * 36,
            "HF_TOKEN": "hf_" + "F" * 34,
            "PYPI_TOKEN": "pypi-AgEI" + "F" * 60,
            "DO_TOKEN": "dop_v1_" + "a" * 64,
            "SHOPIFY_TOKEN": "shpat_" + "a" * 32,
            "SENDGRID_KEY": "SG." + "F" * 22 + "." + "F" * 43,
            "GITHUB_TOKEN": "ghp_FAKEFAKEFAKEFAKEFAKEFAKE1234",
            "EMAIL": "alice@example.invalid.com",
        }
        for type_, value in samples.items():
            self.assertIn((type_, value), self.found(f"x {value} y"), type_)

    def test_whole_pem_block(self):
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAFAKE\nBBBBFAKE\n-----END OPENSSH PRIVATE KEY-----"
        self.assertIn(("PRIVATE_KEY", pem), self.found("key:\n" + pem + "\nafter"))

    def test_key_value_masks_only_the_value(self):
        found = self.found('DB_PASSWORD=FakePass123 api_key: "FAKEKEY9876" max_tokens: 4096 token=true')
        self.assertIn(("SECRET", "FakePass123"), found)
        self.assertIn(("SECRET", "FAKEKEY9876"), found)
        self.assertFalse(any(v in ("4096", "true") for _, v in found))

    def test_aws_secret_only_in_key_value_context(self):
        secret = "FAKE" + "a" * 36
        self.assertIn(("AWS_SECRET", secret), self.found(f"aws_secret_access_key = {secret}"))
        self.assertNotIn(("AWS_SECRET", secret), self.found(f"random {secret}"))

    def test_url_and_connection_string_credentials(self):
        found = self.found("postgres://ledger:FakePw9xQ2@db.example:5432/x  AccountKey=FAKEbase64==;EndpointSuffix=core")
        self.assertIn(("CREDENTIAL", "ledger:FakePw9xQ2"), found)
        self.assertIn(("CREDENTIAL", "FAKEbase64=="), found)

    def test_seed_records_detected_items_and_custom_values(self):
        session = Session("s")
        items = tool_items("mail alice@example.invalid.com", "user andy here")
        config = DetectorConfig(detect_host_identifiers=False, custom_values=[{"type": "USER", "value": "andy"}])
        seed_entities(session, items, config)
        email = session.entity_for("alice@example.invalid.com")
        self.assertEqual(email.origin, "detector:email")
        self.assertEqual(email.detected_in, {items[0].id})
        self.assertEqual(session.entity_for("andy").origin, "detector:custom")

    # (type, text, secret). Synthetic values only.
    POSITIVE = [
        ("AWS_SECRET", '"AWS_SECRET_ACCESS_KEY": "FAKErXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEZ"', "FAKErXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEZ"),
        ("AWS_SECRET", '{\\"aws_secret_access_key\\": \\"FAKErXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\\"}', "FAKErXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("STRIPE_KEY", "whsec_FAKEQ9r8GKYqrTwjUPD8ILPZIRsKKAAAA", "whsec_FAKEQ9r8GKYqrTwjUPD8ILPZIRsKKAAAA"),
        ("GOOGLE_KEY", "key=AIzaFAKEI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&x", "AIzaFAKEI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"),
        ("SLACK_WEBHOOK", "post to https://hooks.slack.com/services/T0000/B0000/FAKEFAKEFAKE now",
         "https://hooks.slack.com/services/T0000/B0000/FAKEFAKEFAKE"),
        ("NPM_TOKEN", "//registry.npmjs.org/:_authToken=npm_" + "F" * 36, "npm_" + "F" * 36),
        ("SECRET", "DB_PASSWORD=FAKEhunter22", "FAKEhunter22"),
        ("SECRET", 'password: "c0rrect FAKE horse"', "c0rrect FAKE horse"),
        ("SECRET", "api_key='FAKE1234efgh'", "FAKE1234efgh"),
        ("SECRET", '{"client_secret": "Tr0ub4dor&FAKE"}', "Tr0ub4dor&FAKE"),
        ("SECRET", '{\\"passwd\\": \\"Tr0ub4dor&3FAKE\\"}', "Tr0ub4dor&3FAKE"),      # JSON inside a JSON string
        ("SECRET", "export GITHUB_TOKEN=s3cr3tFAKE99", "s3cr3tFAKE99"),
        ("SECRET", "  password: s3cretFAKE", "s3cretFAKE"),                              # YAML
        ("CREDENTIAL", "postgres://bob:s3cretFAKE@db.example.com:5432/app", "bob:s3cretFAKE"),
        ("CREDENTIAL", "Server=tcp:x;User Id=sa;Password=P@ssw0rdFAKE!;", "P@ssw0rdFAKE!"),
        ("CREDENTIAL", "Endpoint=sb://x/;SharedAccessKeyName=k;SharedAccessKey=FAKEabc123456=", "FAKEabc123456="),
        ("BEARER_TOKEN", "Authorization: Bearer FAKEdefghijklmnop1234", "FAKEdefghijklmnop1234"),
    ]

    # Code, templates, references and prose: no hit except e-mail addresses.
    NEGATIVE = [
        'token = os.environ["TOKEN"]', "password = getpass()", "secret = MY_SECRET_NAME", "self.token = token",
        '"description": "The token to use for requests"', "password: str", "api_key=${OPENAI_API_KEY}",
        "token=<SECRET_1a2b3c4d>", "bypass=enabled_mode", "oauth=something12345", "max_tokens: 4096",
        'if password == "hunter22":', "password=********", "auth: required", "token: ${{ secrets.GITHUB_TOKEN }}",
        "task-force-alpha-bravo-charlie", "url = https://user:pass@example.com", "def login(password=password1):",
        "auth: AuthTypes", 'api_key = "sk-..."', "apikey: <your key here>", "password=password,",
        "ssh://git@github.com/x", "https://example.com/a:b@c",
    ]

    def test_positive_samples_mask_only_the_value(self):
        for type_, text, secret in self.POSITIVE:
            self.assertIn((type_, secret), self.found(text), text)

    def test_code_templates_and_prose_are_not_secrets(self):
        for text in self.NEGATIVE:
            self.assertEqual({f for f in self.found(text) if f[0] != "EMAIL"}, set(), text)

    def test_overlapping_hits_keep_the_most_specific(self):
        rules = load_rules()
        url = scan("postgres://bob:s3cretFAKE@db.example.com/x", rules)
        self.assertEqual([(f.type, f.value) for f in url], [("CREDENTIAL", "bob:s3cretFAKE")])
        key = scan('api_key="sk-proj-FAKEFAKEabcdefghijklmnop"', rules)
        self.assertEqual([(f.type, f.value) for f in key], [("OPENAI_KEY", "sk-proj-FAKEFAKEabcdefghijklmnop")])

    def test_generic_and_email_rules_run_last(self):
        names = [r.name for r in load_rules()]
        self.assertEqual(names[-2:], ["email", "generic_key_value"])


class Config(unittest.TestCase):
    def test_defaults(self):
        config = GatewayConfig()
        self.assertFalse(config.security.allow_remote_security_model)
        self.assertFalse(config.pass_unknown)
        self.assertEqual(config.security.auto_mask, "auto_veto")
        self.assertEqual((config.retention.idle_ttl_h, config.retention.max_sessions), (12.0, 50))

    def test_stale_prompt_and_unknown_keys_fail_at_load(self):
        with self.assertRaises(Exception):
            SecurityModelConfig(system_prompt='return {"operations":[{"op":"collapse"}]} with MASQ_BLOCK')
        with self.assertRaises(Exception):
            GatewayConfig.model_validate({"allow_remote_security_model": True})
        with self.assertRaises(Exception):
            GatewayConfig.model_validate({"host": "0.0.0.0"})


if __name__ == "__main__":
    unittest.main()
