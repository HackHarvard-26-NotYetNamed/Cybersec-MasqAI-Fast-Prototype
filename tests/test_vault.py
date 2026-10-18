"""Key Enigma step 6: the passphrase vault, its CLI, PassphraseBackend, the key_enigma config and startup wiring.

Synthetic keys only (they contain FAKE). Argon2 runs at its floor cost (64 MiB, t=1, p=1) except where the default
cost itself is tested. Nothing touches the network: OpenRouter is tests.helpers.FakeOpenRouter.
"""
import asyncio
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

import run_gateway
from masqai.config import GatewayConfig, KeyEnigmaConfig, ProviderConfig, load_config
from masqai.custody import CustodyError, ManagementBackend, load_backend
from masqai.custody import vault as V
from masqai.custody.passphrase import PassphraseBackend, open_passphrase_backend
from masqai.enigma import EnigmaKeySource, KeyRing, KeyUnavailable, build_keyring, policy_for
from tests.helpers import (FAKE_INSTANCE, FAKE_MGMT_KEY, FAKE_WORKSPACE, TOKEN, FakeBackend, FakeOpenRouter, api,
                           gateway, make_config)
from tests.test_rotation import POLICY, START, FakeClock, Fixed

CHEAP = {"m_kib": V.MIN_M_KIB, "t": 1, "p": 1}
PASS = "correct horse battery staple"
INFERENCE_KEY = "sk-or-v1-FAKEFAKEFAKEFAKEinference0001"


def sealed(key=FAKE_MGMT_KEY, passphrase=PASS, **kw):
    return V.seal_bytes(key, passphrase, cost=CHEAP, **kw)


def reseal_header(data: bytes, **changes) -> bytes:
    header = json.loads(data)
    header.update(changes)
    return json.dumps(header).encode()


class TempDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.path = self.dir / "sub" / "openrouter.vault"

    def tearDown(self):
        self._tmp.cleanup()


# ---------------------------------------------------------------------------------------------------------------
# The format
# ---------------------------------------------------------------------------------------------------------------

class Format(unittest.TestCase):
    def test_round_trip(self):
        expires = datetime(2027, 1, 31, 23, 59, 59, tzinfo=timezone.utc)
        unsealed = V.unseal_bytes(sealed(management_expires_at=expires), PASS)
        self.assertEqual(unsealed.reveal(), FAKE_MGMT_KEY)
        self.assertEqual(unsealed.management_expires_at, expires)
        self.assertEqual(unsealed.provider, "openrouter")

    def test_the_file_holds_no_plaintext(self):
        data = sealed()
        self.assertNotIn(FAKE_MGMT_KEY.encode(), data)
        self.assertNotIn(PASS.encode(), data)
        self.assertNotIn(b"FAKEFAKE", data)
        header = json.loads(data)
        self.assertEqual(set(header), V.FIELDS)
        self.assertEqual((header["v"], header["kdf"]), (1, "argon2id"))

    def test_default_cost_is_256_mib_t3_p4(self):
        header = json.loads(V.seal_bytes(FAKE_MGMT_KEY, PASS))
        self.assertEqual((header["m_kib"], header["t"], header["p"]), (262144, 3, 4))
        self.assertEqual(V.unseal_bytes(json.dumps(header).encode(), PASS).reveal(), FAKE_MGMT_KEY)

    def test_wrong_passphrase_fails(self):
        with self.assertRaises(V.WrongPassphrase):
            V.unseal_bytes(sealed(), PASS + "!")
        with self.assertRaises(V.WrongPassphrase):
            V.unseal_bytes(sealed(), "")

    def test_every_header_field_is_bound_to_the_ciphertext(self):
        data = sealed()
        header = json.loads(data)
        other_salt = base64.b64encode(os.urandom(16)).decode()
        other_nonce = base64.b64encode(os.urandom(12)).decode()
        changes = {"salt": other_salt, "nonce": other_nonce, "hint": "something else", "created": "2020-01-01T00:00:00Z",
                   "management_expires_at": "2099-01-01T00:00:00Z", "m_kib": header["m_kib"] * 2, "t": 2, "p": 2}
        for field, value in changes.items():
            with self.subTest(field=field):
                with self.assertRaises(V.WrongPassphrase):
                    V.unseal_bytes(reseal_header(data, **{field: value}), PASS)

    def test_every_ciphertext_byte_is_authenticated(self):
        data = sealed()
        ct = bytearray(base64.b64decode(json.loads(data)["ct"]))
        for i in range(len(ct)):
            flipped = bytearray(ct)
            flipped[i] ^= 0x01
            with self.assertRaises(V.WrongPassphrase, msg=f"byte {i}"):
                V.unseal_bytes(reseal_header(data, ct=base64.b64encode(bytes(flipped)).decode()), PASS)

    def test_a_cheaper_kdf_is_refused_before_any_work(self):
        data = sealed()
        for change in ({"m_kib": 1024}, {"m_kib": V.MAX_M_KIB * 2}, {"t": 0}, {"t": 99}, {"p": 0}, {"m_kib": True},
                       {"m_kib": "65536"}):
            with self.subTest(change=change):
                with patch.object(V, "_derive", side_effect=AssertionError("derived")), self.assertRaises(V.VaultError) as caught:
                    V.unseal_bytes(reseal_header(data, **change), PASS)
                self.assertNotIsInstance(caught.exception, V.WrongPassphrase)

    def test_malformed_files_are_refused(self):
        data = sealed()
        header = json.loads(data)
        bad = [b"", b"not json", b"[]", json.dumps({**header, "extra": 1}).encode(),
               json.dumps({k: v for k, v in header.items() if k != "hint"}).encode(),
               reseal_header(data, v=2), reseal_header(data, kdf="scrypt"), reseal_header(data, provider="anthropic"),
               reseal_header(data, salt="!!!"), reseal_header(data, salt=base64.b64encode(b"short").decode()),
               reseal_header(data, nonce=base64.b64encode(b"x" * 16).decode()), reseal_header(data, ct=""),
               reseal_header(data, management_expires_at="tomorrow"), b" " * (V.MAX_FILE_BYTES + 1)]
        for blob in bad:
            with self.subTest(blob=blob[:40]):
                # Refused as malformed, before any Argon2 work, never mistaken for a wrong passphrase.
                with patch.object(V, "_derive", side_effect=AssertionError("derived")), self.assertRaises(V.VaultError) as caught:
                    V.unseal_bytes(blob, PASS)
                self.assertNotIsInstance(caught.exception, V.WrongPassphrase)

    def test_fresh_salt_and_nonce_every_seal(self):
        a, b = json.loads(sealed()), json.loads(sealed())
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotEqual(a["nonce"], b["nonce"])
        self.assertNotEqual(a["ct"], b["ct"])

    def test_passphrase_rules(self):
        for passphrase in ("short", "x" * 13, f"my {FAKE_MGMT_KEY} pass", FAKE_MGMT_KEY[:20]):
            with self.subTest(passphrase=passphrase[:12]):
                with self.assertRaises(V.VaultError):
                    sealed(passphrase=passphrase)
        self.assertEqual(V.unseal_bytes(sealed(passphrase="x" * 14), "x" * 14).reveal(), FAKE_MGMT_KEY)

    def test_unicode_passphrases_are_normalized(self):
        composed, decomposed = "caf\u00e9 au lait du matin", "cafe\u0301 au lait du matin"
        self.assertEqual(V.unseal_bytes(sealed(passphrase=composed), decomposed).reveal(), FAKE_MGMT_KEY)

    def test_management_key_checks(self):
        for key in ("", "   ", f" {FAKE_MGMT_KEY}", "sk-or-v1-FAKE with space", "k" * 5000):
            with self.subTest(key=key[:20]):
                with self.assertRaises(V.VaultError):
                    sealed(key=key)

    def test_unsealed_wipes_and_hides(self):
        unsealed = V.unseal_bytes(sealed(), PASS)
        self.assertNotIn(FAKE_MGMT_KEY, repr(unsealed))
        buffer = unsealed._buf
        unsealed.wipe()
        self.assertTrue(unsealed.wiped)
        self.assertEqual(bytes(buffer), b"")
        with self.assertRaises(V.VaultError):
            unsealed.reveal()

    def test_errors_never_contain_secrets(self):
        messages = []
        for call in (lambda: V.unseal_bytes(sealed(), "wrong passphrase!!"),
                     lambda: sealed(passphrase=f"a {FAKE_MGMT_KEY}"),
                     lambda: V.unseal_bytes(reseal_header(sealed(), t=0), PASS)):
            try:
                call()
            except V.VaultError as exc:
                messages.append(str(exc))
        self.assertEqual(len(messages), 3)
        for message in messages:
            self.assertNotIn(FAKE_MGMT_KEY, message)
            self.assertNotIn(PASS, message)
            self.assertNotIn("wrong passphrase!!", message)


# ---------------------------------------------------------------------------------------------------------------
# Files and unlocking
# ---------------------------------------------------------------------------------------------------------------

class Files(TempDir):
    def test_seal_writes_atomically_and_refuses_to_overwrite(self):
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)
        self.assertEqual(V.unseal_header(V.read_vault(self.path), PASS).reveal(), FAKE_MGMT_KEY)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], [self.path.name])   # no temp file left
        with self.assertRaises(V.VaultError):
            V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)

    def test_a_failed_write_leaves_the_old_vault_and_no_temp_file(self):
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)
        before = self.path.read_bytes()
        with patch.object(V.os, "replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
            V.seal_file(self.path, FAKE_MGMT_KEY, PASS, overwrite=True, cost=CHEAP)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], [self.path.name])

    @unittest.skipUnless(os.name == "nt", "Windows ACL")
    def test_owner_only_acl_on_windows(self):
        import subprocess
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)
        out = subprocess.run(["icacls", str(self.path)], capture_output=True, text=True).stdout
        grants = [line for line in out.splitlines()[:-2] if ":" in line.replace(str(self.path), "")]
        self.assertEqual(len(grants), 1, out)
        self.assertNotIn("(I)", out)                 # inheritance removed
        self.assertNotIn("Everyone", out)
        self.assertNotIn("BUILTIN\\Users", out)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits")
    def test_owner_only_mode_on_posix(self):
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_destroy_overwrites_then_deletes(self):
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)
        before = self.path.read_bytes()
        with patch.object(Path, "unlink") as unlink:      # keep the file to look at what was written over it
            V.destroy_file(self.path)
        after = self.path.read_bytes()
        unlink.assert_called_once()
        self.assertEqual(len(after), len(before))
        self.assertNotEqual(after, before)
        with self.assertRaises(V.VaultError):
            V.parse(after)
        V.destroy_file(self.path)
        self.assertFalse(self.path.exists())

    def test_unlock_allows_three_attempts(self):
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)
        answers = iter(["nope nope nope 1", "nope nope nope 2", PASS])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(V.unlock(self.path, lambda _: next(answers)).reveal(), FAKE_MGMT_KEY)
        tries = []
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(V.VaultError, "3 wrong"):
            V.unlock(self.path, lambda _: tries.append(1) or "nope nope nope!!")
        self.assertEqual(len(tries), 3)

    def test_unlock_reports_a_missing_vault_without_prompting(self):
        with self.assertRaisesRegex(V.VaultError, "masqai.vault seal"):
            V.unlock(self.path, lambda _: self.fail("prompted"))

    def test_no_tty_refuses(self):
        with patch.object(V.sys, "stdin", io.StringIO(PASS + "\n")):
            with self.assertRaisesRegex(V.VaultError, "no interactive terminal"):
                V.tty_prompt("Passphrase: ")

    def test_a_passphrase_environment_variable_is_ignored(self):
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)
        env = {name: PASS for name in ("MASQAI_VAULT_PASSPHRASE", "MASQAI_PASSPHRASE", "VAULT_PASSPHRASE")}
        with patch.dict(os.environ, env), patch.object(V.sys, "stdin", io.StringIO("")):
            with self.assertRaisesRegex(V.VaultError, "no interactive terminal"):
                V.unlock(self.path, V.tty_prompt)


# ---------------------------------------------------------------------------------------------------------------
# The CLI
# ---------------------------------------------------------------------------------------------------------------

class Scripted:
    """A Console with scripted answers that records everything said."""

    def __init__(self, secrets=(), answers=()):
        self.secrets, self.answers, self.out = list(secrets), list(answers), []
        self.secret_prompts = []

    def console(self):
        def secret(prompt):
            self.secret_prompts.append(prompt)
            return self.secrets.pop(0)
        return V.Console(secret=secret, ask=lambda _: self.answers.pop(0), say=self.out.append)

    @property
    def text(self):
        return "\n".join(self.out)


class Cli(TempDir):
    def setUp(self):
        super().setUp()
        self.fake = FakeOpenRouter()
        self.cheap = patch.dict(V.DEFAULT_COST, CHEAP)
        self.cheap.start()

    def tearDown(self):
        self.cheap.stop()
        super().tearDown()

    def run_cli(self, command, script, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = V.main([command, "--path", str(self.path), *extra], script.console(), transport=self.fake.transport)
        return code, script.text + stdout.getvalue() + stderr.getvalue()

    def test_seal_then_verify(self):
        code, out = self.run_cli("seal", Scripted([FAKE_MGMT_KEY, PASS, PASS]))
        self.assertEqual(code, 0, out)
        self.assertIn("2026-12-31", out)            # the expiry OpenRouter reports is recorded
        self.assertEqual(V.read_vault(self.path).management_expires_at, datetime(2026, 12, 31, tzinfo=timezone.utc))
        code, out2 = self.run_cli("verify", Scripted([PASS]))
        self.assertEqual(code, 0, out2)
        self.assertIn("ok", out2)
        for text in (out, out2):
            self.assertNotIn(FAKE_MGMT_KEY, text)
            self.assertNotIn(PASS, text)

    def test_seal_refuses_an_inference_key(self):
        self.fake.keys.clear()
        key_hash = self.fake.add_key("someone")
        inference = self.fake.keys[key_hash]["_key"]
        code, out = self.run_cli("seal", Scripted([inference, PASS, PASS]))
        self.assertEqual(code, 1)
        self.assertIn("not a management key", out)
        self.assertFalse(self.path.exists())
        self.assertNotIn(inference, out)

    def test_seal_refuses_an_unknown_key(self):
        code, out = self.run_cli("seal", Scripted(["sk-or-v1-FAKEFAKEnotakeyatall0000", PASS, PASS]))
        self.assertEqual(code, 1)
        self.assertIn("refused", out)
        self.assertFalse(self.path.exists())

    def test_seal_refuses_mismatched_or_weak_passphrases(self):
        for secrets in ([FAKE_MGMT_KEY, PASS, PASS + "x"], [FAKE_MGMT_KEY, "short"]):
            with self.subTest(secrets=len(secrets)):
                code, out = self.run_cli("seal", Scripted(secrets))
                self.assertEqual(code, 1)
                self.assertFalse(self.path.exists())

    def test_seal_asks_for_the_expiry_if_openrouter_does_not_report_it(self):
        original = self.fake._whoami

        def whoami(bearer):
            response = original(bearer)
            body = json.loads(response.content)
            body["data"].pop("expires_at", None)
            return type(response)(response.status_code, json=body)
        self.fake._whoami = whoami
        code, out = self.run_cli("seal", Scripted([FAKE_MGMT_KEY, PASS, PASS], ["2027-03-01"]))
        self.assertEqual(code, 0, out)
        self.assertEqual(V.read_vault(self.path).management_expires_at,
                         datetime(2027, 3, 1, 23, 59, 59, tzinfo=timezone.utc))

    def test_secrets_are_only_read_with_the_hidden_prompt(self):
        script = Scripted([FAKE_MGMT_KEY, PASS, PASS])
        self.run_cli("seal", script)
        self.assertEqual(len(script.secret_prompts), 3)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            V.main(["seal", "--path", str(self.path), "--key", FAKE_MGMT_KEY])   # no argument carries a secret

    def test_seal_refuses_an_existing_vault(self):
        self.run_cli("seal", Scripted([FAKE_MGMT_KEY, PASS, PASS]))
        script = Scripted([FAKE_MGMT_KEY, PASS, PASS])
        code, out = self.run_cli("seal", script)
        self.assertEqual(code, 1)
        self.assertEqual(script.secret_prompts, [])   # refused before asking for anything

    def test_repass(self):
        self.run_cli("seal", Scripted([FAKE_MGMT_KEY, PASS, PASS]))
        new = "an entirely different passphrase"
        code, out = self.run_cli("repass", Scripted([PASS, new, new]))
        self.assertEqual(code, 0, out)
        with self.assertRaises(V.WrongPassphrase):
            V.unseal_header(V.read_vault(self.path), PASS)
        unsealed = V.unseal_header(V.read_vault(self.path), new)
        self.assertEqual(unsealed.reveal(), FAKE_MGMT_KEY)
        self.assertEqual(unsealed.management_expires_at, datetime(2026, 12, 31, tzinfo=timezone.utc))

    def test_verify_reports_a_revoked_management_key(self):
        self.run_cli("seal", Scripted([FAKE_MGMT_KEY, PASS, PASS]))
        self.fake.management_key = "sk-or-v1-FAKEFAKEsomeothermanagement"
        code, out = self.run_cli("verify", Scripted([PASS]))
        self.assertEqual(code, 1)
        self.assertIn("refused", out)

    def test_destroy_needs_confirmation(self):
        self.run_cli("seal", Scripted([FAKE_MGMT_KEY, PASS, PASS]))
        code, _ = self.run_cli("destroy", Scripted(answers=["no"]))
        self.assertEqual(code, 1)
        self.assertTrue(self.path.exists())
        code, _ = self.run_cli("destroy", Scripted(answers=["destroy"]))
        self.assertEqual(code, 0)
        self.assertFalse(self.path.exists())

    def test_destroy_refuses_a_file_that_is_not_a_vault(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("my notes")
        code, _ = self.run_cli("destroy", Scripted(answers=["destroy"]))
        self.assertEqual(code, 1)
        self.assertEqual(self.path.read_text(), "my notes")


# ---------------------------------------------------------------------------------------------------------------
# PassphraseBackend
# ---------------------------------------------------------------------------------------------------------------

class Backend(TempDir):
    def setUp(self):
        super().setUp()
        self.fake = FakeOpenRouter()
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP,
                    management_expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc))

    def open(self, **kw):
        return open_passphrase_backend(vault_path=self.path, workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE,
                                       prompt=lambda _: PASS, transport=self.fake.transport, **kw)

    def test_opens_mints_and_wipes_on_close(self):
        backend = self.open()
        self.assertIsInstance(backend, ManagementBackend)
        self.assertNotIn(FAKE_MGMT_KEY, repr(backend))
        self.assertEqual(backend.known_secrets(), [(FAKE_MGMT_KEY, "ADMIN_KEY")])

        async def go():
            status = await backend.status()
            self.assertTrue(status.healthy, status.detail)
            minted = await backend.mint(suffix="t-1", expires_at=datetime.now(timezone.utc) + timedelta(minutes=31), limit_usd=2.0)
            self.assertTrue(minted.name.startswith(f"masqai-enigma-{FAKE_INSTANCE}-"))
            await backend.aclose()
        asyncio.run(go())
        self.assertEqual(backend.known_secrets(), [])
        self.assertTrue(backend._unsealed.wiped)
        self.assertEqual(backend.keys._key, "")
        with self.assertRaises(CustodyError):
            asyncio.run(backend.keys.current())
        self.assertTrue(all(r.headers["authorization"] == f"Bearer {FAKE_MGMT_KEY}" for r in self.fake.calls))

    def test_load_backend_opens_passphrase_mode(self):
        backend = load_backend({"mode": "passphrase", "vault_path": str(self.path)}, workspace_id=FAKE_WORKSPACE,
                               instance_id=FAKE_INSTANCE, prompt=lambda _: PASS, transport=self.fake.transport)
        self.assertIsInstance(backend, PassphraseBackend)
        asyncio.run(backend.aclose())

    def test_bad_ids_wipe_the_key(self):
        captured = []
        real = V.unlock

        def spy(*a, **kw):
            captured.append(real(*a, **kw))
            return captured[-1]
        with patch("masqai.custody.passphrase.unlock", spy), self.assertRaises(CustodyError):
            open_passphrase_backend(vault_path=self.path, workspace_id="not-a-uuid", instance_id=FAKE_INSTANCE,
                                    prompt=lambda _: PASS)
        self.assertTrue(captured[0].wiped)

    def test_the_management_key_is_masked_in_outbound_content_and_logs(self):
        backend = self.open()
        backend.keys._http()   # create the management client now, on the fake OpenRouter (gateway() patches httpx)
        ring, source = rotating_ring(backend)
        config = make_config()
        with gateway(config, keyring=ring) as (app, client, fakes), client:
            r = client.post("/v1/chat/completions", json={"model": "m", "messages": [
                {"role": "user", "content": f"my management key is {FAKE_MGMT_KEY} ok"}]})
            self.assertEqual(r.status_code, 200)
            self.assertNotIn(FAKE_MGMT_KEY, fakes.upstream_calls[-1].content.decode())
            fakes.upstream = lambda req: __import__("httpx").Response(400, json={"error": {"message": f"echo {FAKE_MGMT_KEY}"}})
            with self.assertLogs("masqai", level="ERROR") as logged:
                client.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
            self.assertFalse(any(FAKE_MGMT_KEY in line for line in logged.output))
            self.assertTrue(any("<ADMIN_KEY_enigma>" in line for line in logged.output))
            self.assertNotIn(FAKE_MGMT_KEY, api(client, "GET", "/api/config").text)
            self.assertNotIn(FAKE_MGMT_KEY, api(client, "GET", "/api/enigma/status").text)
        # The lifespan stopped the source, which closed the backend and wiped the key.
        self.assertTrue(backend._unsealed.wiped)


def rotating_ring(backend):
    """An EnigmaKeySource for provider "up" on `backend`, with a fake clock and a probe that trusts every key."""
    async def probe(key):
        return True
    source = EnigmaKeySource("up", backend, POLICY, clock=FakeRealClock(), probe=probe, rng=Fixed(), owns_backend=True)
    return KeyRing({"up": source}), source


class FakeRealClock(FakeClock):
    """The fake clock, but with real wall time: DirectBackend checks expires_at against the real clock."""

    def utcnow(self):
        return datetime.now(timezone.utc) + timedelta(seconds=self.now - 1000.0)


# ---------------------------------------------------------------------------------------------------------------
# Startup checks in the rotating source
# ---------------------------------------------------------------------------------------------------------------

class SourceStartup(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.clock = FakeClock()
        self.backend = FakeBackend()

        async def probe(key):
            return any(m.key == key for m in self.backend.live.values())
        self.source = EnigmaKeySource("openrouter", self.backend, POLICY, clock=self.clock, probe=probe, rng=Fixed())

    async def asyncTearDown(self):
        await self.source.stop()

    async def test_an_unhealthy_backend_refuses_before_anything_is_minted(self):
        self.backend.healthy, self.backend.detail = False, "the Key Enigma workspace has no budget"
        self.backend.leftovers = ["x"]
        with self.assertRaisesRegex(KeyUnavailable, "no budget"):
            await self.source.start()
        self.assertEqual(self.backend.live, {})
        self.assertEqual(self.backend.leftovers, ["x"])    # not even cleanup ran

    async def test_management_key_expiry_warnings_fire_once_each(self):
        self.backend.management_expires_at = START + timedelta(days=8)
        with self.assertLogs("masqai", level="WARNING") as logged:
            await self.source.start()
            self.source._check_management_expiry()
            self.assertFalse(any(e["type"] == "management_key_expiring" for e in self.source.events))
            self.clock.now += 86400 * 1.5                      # 6.5 days left
            self.source._check_management_expiry()
            self.source._check_management_expiry()
            self.clock.now += 86400 * 5.75                     # 18 h left
            self.source._check_management_expiry()
            self.source._check_management_expiry()
        warnings = [e for e in self.source.events if e["type"] == "management_key_expiring"]
        self.assertEqual(len(warnings), 2)
        self.assertEqual(len([line for line in logged.output if "management key expires" in line]), 2)
        self.assertIn("expires in 156 h", warnings[0]["detail"])
        self.assertIn("expires in 18 h", warnings[1]["detail"])
        self.assertEqual(self.source.snapshot()["management_expires_at"], (START + timedelta(days=8)).isoformat())

    async def test_a_backend_close_is_owned_only_when_asked(self):
        await self.source.start()
        await self.source.stop()
        self.assertFalse(self.backend.closed)
        owned = EnigmaKeySource("o", self.backend, POLICY, clock=self.clock, probe=self.source.probe, rng=Fixed(), owns_backend=True)
        await owned.start()
        await owned.stop()
        self.assertTrue(self.backend.closed)


# ---------------------------------------------------------------------------------------------------------------
# Config and wiring
# ---------------------------------------------------------------------------------------------------------------

def enigma_block(**overrides):
    block = {"enabled": True, "instance_id": FAKE_INSTANCE, "workspace_id": FAKE_WORKSPACE,
             "custody": {"mode": "passphrase", "vault_path": None}}
    block.update(overrides)
    return block


def or_provider(**enigma):
    return {"name": "openrouter", "base_url": "https://openrouter.ai/api", "key_enigma": enigma_block(**enigma)}


class Config(unittest.TestCase):
    def test_a_valid_block(self):
        provider = ProviderConfig.model_validate(or_provider())
        self.assertTrue(provider.rotates)
        self.assertEqual(provider.key_enigma.interval_seconds, 900)
        self.assertEqual(provider.key_enigma.failure_policy, "closed")
        self.assertEqual(provider.key_enigma.per_key_limit_usd, 2.0)
        disabled = ProviderConfig.model_validate(or_provider(enabled=False))
        self.assertFalse(disabled.rotates)

    def test_validation(self):
        bad = [
            ({"custody": {}}, "no default"), ({"custody": {"mode": "env"}}, "custody"), ({"custody": None}, "no default"),
            ({"workspace_id": None}, "workspace"), ({"workspace_id": "abc"}, "workspace_id"),
            ({"instance_id": ""}, "instance_id"), ({"instance_id": "ABCDEF12"}, "instance_id"),
            ({"interval_seconds": 299}, "interval"), ({"jitter": 0.6}, "jitter"), ({"per_key_limit_usd": 0}, "per_key"),
            ({"failure_policy": "maybe"}, "failure_policy"), ({"kind": "anthropic"}, "kind"), ({"surprise": 1}, "surprise"),
            ({"custody": {"mode": "device"}}, "serial_port"),
            ({"custody": {"mode": "passphrase", "api_key": "x"}}, "api_key"),
        ]
        for overrides, where in bad:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValidationError) as caught:
                    ProviderConfig.model_validate(or_provider(**overrides))
                self.assertIn(where, str(caught.exception))

    def test_custody_has_no_default_mode(self):
        from masqai.config import CustodyConfig
        for data in ({}, {"vault_path": "x"}):
            with self.subTest(data=data), self.assertRaises(ValidationError):
                CustodyConfig.model_validate(data)
        self.assertEqual(CustodyConfig.model_validate({"mode": "passphrase"}).vault_path, None)

    def test_rotation_only_to_openrouter(self):
        for url in ("https://evil.test/api", "http://openrouter.ai/api", "https://openrouter.ai.evil.test/api",
                    "https://user@openrouter.ai/api"):
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    ProviderConfig.model_validate({**or_provider(), "base_url": url})

    def test_policy_derives_the_drain_cap_from_the_upstream_timeout(self):
        config = GatewayConfig.model_validate({"providers": [or_provider()], "upstream_timeout_seconds": 240})
        policy = policy_for(config.providers[0], config.upstream_timeout_seconds)
        self.assertEqual(policy.drain_cap_seconds, 240)
        config = GatewayConfig.model_validate({"providers": [or_provider(drain_cap_seconds=90, failure_policy="open")]})
        policy = policy_for(config.providers[0], config.upstream_timeout_seconds)
        self.assertEqual((policy.drain_cap_seconds, policy.failure_policy), (90, "open"))

    def test_the_example_config_still_loads(self):
        example = Path(__file__).resolve().parent.parent / "masqai.json.example"
        if example.exists():
            load_config(example)


class Wiring(TempDir):
    def config(self, **enigma):
        return make_config(providers=[ProviderConfig.model_validate(or_provider(**enigma)),
                                      ProviderConfig(name="sec", base_url="http://127.0.0.1:11434")],
                           default_route={"provider": "openrouter"})

    def test_the_app_refuses_a_rotating_provider_without_a_rotating_source(self):
        with self.assertRaisesRegex(ValueError, "no rotating key source"):
            with gateway(self.config()):
                pass

    def test_build_keyring_needs_a_backend_per_rotating_provider(self):
        with self.assertRaisesRegex(ValueError, "no key backend"):
            build_keyring(self.config(), {})
        ring = build_keyring(self.config(), {"openrouter": FakeBackend()})
        self.assertTrue(ring.rotates("openrouter"))
        self.assertFalse(ring.rotates("sec"))
        self.assertFalse(build_keyring(self.config(enabled=False), {}).rotates("openrouter"))

    def test_key_enigma_settings_are_fixed_at_startup(self):
        config = self.config()
        ring = build_keyring(config, {"openrouter": FakeBackend()})
        source = ring._sources["openrouter"]
        source.probe = lambda key: _true()
        with gateway(config, keyring=ring) as (app, client, fakes), client:
            current = api(client, "GET", "/api/config").json()
            self.assertEqual(api(client, "POST", "/api/config", json=current).status_code, 200)   # unchanged: fine
            for change in ({"interval_seconds": 600}, {"enabled": False}, None):
                with self.subTest(change=change):
                    body = json.loads(json.dumps(current))
                    if change is None:
                        body["providers"][0].pop("key_enigma")
                    else:
                        body["providers"][0]["key_enigma"].update(change)
                    r = api(client, "POST", "/api/config", json=body)
                    self.assertEqual(r.status_code, 400, r.text)
                    self.assertIn("fixed at startup", r.text)
                    self.assertEqual(r.json()["errors"][0]["loc"], ["providers", 0, "key_enigma"])
            # Other edits still work, and a rotating provider can't be renamed away from its source.
            body = json.loads(json.dumps(current))
            body["providers"][0]["name"] = "renamed"
            body["default_route"] = {"provider": "renamed", "model": None}
            self.assertEqual(api(client, "POST", "/api/config", json=body).status_code, 400)

    def test_run_gateway_opens_backends_before_uvicorn_and_never_more_than_one_worker(self):
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)
        config_path = self.dir / "masqai.json"
        provider = or_provider(custody={"mode": "passphrase", "vault_path": str(self.path)})
        config_path.write_text(json.dumps({"providers": [provider], "default_route": {"provider": "openrouter"}}))
        order, seen = [], {}

        def fake_run(app, **kw):
            order.append("uvicorn")
            seen.update(kw)

        def prompt(text):
            order.append("prompt")
            return PASS
        real_load = run_gateway.load_backend
        with patch.object(run_gateway, "load_backend", lambda *a, **kw: real_load(*a, **{**kw, "prompt": prompt})), \
                patch.object(run_gateway.uvicorn, "run", fake_run), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(run_gateway.main(["--config", str(config_path)]), 0)
        self.assertEqual(order, ["prompt", "uvicorn"])
        self.assertEqual(seen["workers"], 1)
        self.assertNotIn(FAKE_MGMT_KEY, out.getvalue())

    def test_run_gateway_refuses_without_a_terminal(self):
        V.seal_file(self.path, FAKE_MGMT_KEY, PASS, cost=CHEAP)
        config_path = self.dir / "masqai.json"
        provider = or_provider(custody={"mode": "passphrase", "vault_path": str(self.path)})
        config_path.write_text(json.dumps({"providers": [provider], "default_route": {"provider": "openrouter"}}))
        with patch.object(V.sys, "stdin", io.StringIO(PASS + "\n")), \
                patch.object(run_gateway.uvicorn, "run", lambda *a, **kw: self.fail("uvicorn started")), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(run_gateway.main(["--config", str(config_path)]), 2)
        self.assertIn("no interactive terminal", err.getvalue())

    def test_run_gateway_reports_a_missing_custody_mode(self):
        config_path = self.dir / "masqai.json"
        provider = or_provider(custody={})
        config_path.write_text(json.dumps({"providers": [provider], "default_route": {"provider": "openrouter"}}))
        with patch.object(run_gateway.uvicorn, "run", lambda *a, **kw: self.fail("uvicorn started")), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(run_gateway.main(["--config", str(config_path)]), 2)
        self.assertIn("no default", err.getvalue())


async def _true():
    return True


if __name__ == "__main__":
    unittest.main()
