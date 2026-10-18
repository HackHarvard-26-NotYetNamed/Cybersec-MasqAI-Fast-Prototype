"""Key Enigma step 2: the management-key client and the backend protocol, against a fake OpenRouter.

Synthetic keys only (they contain FAKE). Nothing here touches the network: every client gets the fake's transport.
"""
import json
import unittest
from datetime import datetime, timedelta, timezone

import httpx

from masqai.custody import (BackendUnavailable, CustodyError, KeyNotFound, ManagementAuthError, ManagementBackend,
                            RateLimited, load_backend)
from masqai.custody.openrouter import DirectBackend, OpenRouterKeys, check_hash, format_expiry, probe_key
from tests.helpers import FAKE_INSTANCE, FAKE_MGMT_KEY, FAKE_WORKSPACE, FakeBackend, FakeOpenRouter

OTHER_WORKSPACE = "11111111-2222-3333-4444-555555555555"


def soon(minutes: int = 31) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


class Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.fake = FakeOpenRouter()
        self.keys = OpenRouterKeys(FAKE_MGMT_KEY, transport=self.fake.transport)
        self.sleeps: list[float] = []

        async def no_sleep(seconds: float) -> None:
            self.sleeps.append(seconds)
        self.backend = DirectBackend(self.keys, workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE, sleep=no_sleep)

    async def asyncTearDown(self) -> None:
        await self.backend.aclose()


class Protocols(unittest.TestCase):
    def test_both_backends_satisfy_the_protocol(self):
        fake = FakeOpenRouter()
        direct = DirectBackend(OpenRouterKeys(FAKE_MGMT_KEY, transport=fake.transport), workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE)
        self.assertIsInstance(direct, ManagementBackend)
        self.assertIsInstance(FakeBackend(), ManagementBackend)

    def test_load_backend_requires_an_explicit_known_mode(self):
        for custody in ({}, {"mode": None}, {"mode": "env"}, {"mode": "plaintext"}):
            with self.assertRaisesRegex(CustodyError, "no default"):
                load_backend(custody)
        # device is chosen but not built yet: refuse rather than fall back
        with self.assertRaisesRegex(CustodyError, "not built yet"):
            load_backend({"mode": "device", "serial_port": "COM5", "device_id": "esp32-a1b2c3d4"})
        with self.assertRaisesRegex(CustodyError, "workspace_id"):
            load_backend({"mode": "passphrase"})   # passphrase mode is built (tests/test_vault.py)

    def test_expiry_is_formatted_with_seconds_in_utc(self):
        when = datetime(2026, 10, 18, 21, 5, 7, 999, tzinfo=timezone(timedelta(hours=8)))
        self.assertEqual(format_expiry(when), "2026-10-18T13:05:07Z")
        with self.assertRaises(ValueError):
            format_expiry(datetime(2026, 10, 18, 13, 5, 7))   # naive: refused, never guessed

    def test_management_key_never_appears_in_repr(self):
        client = OpenRouterKeys(FAKE_MGMT_KEY)
        self.assertNotIn(FAKE_MGMT_KEY, repr(client))
        backend = FakeBackend()
        self.assertTrue(all(FAKE_MGMT_KEY not in repr(v) for v in vars(backend).values()))

    def test_bad_identifiers_are_refused_before_any_request(self):
        fake = FakeOpenRouter()
        keys = OpenRouterKeys(FAKE_MGMT_KEY, transport=fake.transport)
        with self.assertRaises(CustodyError):
            DirectBackend(keys, workspace_id="default", instance_id=FAKE_INSTANCE)
        with self.assertRaises(CustodyError):
            DirectBackend(keys, workspace_id=FAKE_WORKSPACE, instance_id="3F9A1C07")
        self.assertEqual(fake.calls, [])


class Mint(Base):
    async def test_mint_sends_the_full_policy_and_returns_the_key(self):
        minted = await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        sent = json.loads(self.fake.calls[-1].content)
        self.assertEqual(sent["name"], f"masqai-enigma-{FAKE_INSTANCE}-1")
        self.assertEqual(sent["workspace_id"], FAKE_WORKSPACE)
        self.assertEqual(sent["limit"], 2.0)
        self.assertIsNone(sent["limit_reset"])            # a reset would refill a thief's budget
        self.assertTrue(sent["include_byok_in_limit"])
        self.assertRegex(sent["expires_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(self.fake.calls[-1].headers["authorization"], f"Bearer {FAKE_MGMT_KEY}")
        self.assertTrue(await probe_key(minted.key, transport=self.fake.transport))
        self.assertNotIn(minted.key, repr(minted))
        self.assertEqual(minted.limit_usd, 2.0)

    async def test_names_cannot_escape_the_install_prefix(self):
        for suffix in ("", "../x", "UPPER", "a" * 33, "x/y", "x y"):
            with self.assertRaises(CustodyError):
                await self.backend.mint(suffix=suffix, expires_at=soon(), limit_usd=2.0)
        self.assertEqual(self.fake.calls, [])

    async def test_bad_limits_and_past_expiry_are_refused_locally(self):
        for limit in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(CustodyError):
                await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=limit)
        with self.assertRaises(CustodyError):
            await self.backend.mint(suffix="1", expires_at=soon(-1), limit_usd=2.0)
        self.assertEqual(self.fake.calls, [])

    async def test_a_key_created_without_our_ceilings_is_revoked_and_not_returned(self):
        for field, value in (("expires_at", None), ("expires_at", "2099-01-01T00:00:00Z"), ("limit", None),
                             ("limit", 50.0), ("workspace_id", OTHER_WORKSPACE)):
            self.fake.mangle_create = lambda record, f=field, v=value: record.__setitem__(f, v)
            with self.assertRaisesRegex(CustodyError, "was revoked"):
                await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
            self.assertEqual(self.fake.keys, {}, f"{field}={value!r} left a key alive")

    async def test_management_key_refusal_is_its_own_error(self):
        self.fake.fail[("POST", "/keys")] = [401]
        with self.assertRaises(ManagementAuthError):
            await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.fake.fail[("POST", "/keys")] = [429]
        with self.assertRaises(RateLimited) as caught:
            await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.assertEqual(caught.exception.retry_after, 1.0)
        self.fake.fail[("POST", "/keys")] = [503]
        with self.assertRaises(BackendUnavailable):
            await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)

    async def test_an_inference_key_cannot_manage_keys(self):
        minted = await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        impostor = DirectBackend(OpenRouterKeys(minted.key, transport=self.fake.transport),
                                 workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE)
        with self.assertRaises(ManagementAuthError):
            await impostor.mint(suffix="2", expires_at=soon(), limit_usd=2.0)
        status = await impostor.status()
        self.assertFalse(status.healthy)


class Revoke(Base):
    async def test_delete_kills_the_key(self):
        minted = await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.assertEqual(await self.backend.revoke(minted.hash), "deleted")
        self.assertFalse(await probe_key(minted.key, transport=self.fake.transport))
        self.assertEqual(await self.backend.revoke(minted.hash), "already_gone")

    async def test_failing_delete_retries_then_disables(self):
        minted = await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.fake.fail[("DELETE", "/keys/")] = [500, 500, 500]
        self.assertEqual(await self.backend.revoke(minted.hash), "disabled")
        self.assertEqual(self.sleeps, [2.0, 4.0])
        self.assertTrue(self.fake.keys[minted.hash]["disabled"])
        self.assertFalse(await probe_key(minted.key, transport=self.fake.transport))

    async def test_delete_succeeding_on_retry_does_not_disable(self):
        minted = await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.fake.fail[("DELETE", "/keys/")] = [429]
        self.assertEqual(await self.backend.revoke(minted.hash), "deleted")
        self.assertEqual(self.sleeps, [1.0])     # honors Retry-After
        self.assertFalse(any(c.method == "PATCH" for c in self.fake.calls))

    async def test_when_everything_fails_it_says_so(self):
        minted = await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.fake.fail[("DELETE", "/keys/")] = [500, 500, 500]
        self.fake.fail[("PATCH", "/keys/")] = [500]
        with self.assertRaisesRegex(CustodyError, "expires_at"):
            await self.backend.revoke(minted.hash)

    async def test_a_revoked_management_key_stops_retries_at_once(self):
        minted = await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.fake.fail[("DELETE", "/keys/")] = [401]
        with self.assertRaises(ManagementAuthError):
            await self.backend.revoke(minted.hash)
        self.assertEqual(self.sleeps, [])

    async def test_hash_must_be_64_hex_before_it_reaches_a_url(self):
        for bad in ("../../workspaces", "abc", "A" * 64, "0" * 63 + "/", "0" * 64 + "?x=1"):
            with self.assertRaisesRegex(CustodyError, "malformed key hash"):   # the first fence, not just the allowlist
                check_hash(bad)
            with self.assertRaises(CustodyError):
                await self.backend.revoke(bad)
            with self.assertRaises(CustodyError):
                await self.backend.usage(bad)
        self.assertEqual(self.fake.calls, [])

    async def test_probe_shows_revocation_propagation_delay(self):
        minted = await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.fake.revoke_delay = 2
        await self.backend.revoke(minted.hash)
        answers = [await probe_key(minted.key, transport=self.fake.transport) for _ in range(3)]
        self.assertEqual(answers, [True, True, False])

    async def test_probe_does_not_guess_on_unclear_answers(self):
        transport = httpx.MockTransport(lambda r: httpx.Response(502))
        with self.assertRaises(BackendUnavailable):
            await probe_key("sk-or-v1-FAKEFAKEFAKEFAKEFAKEFAKE0001", transport=transport)


class UsageAndCleanup(Base):
    async def test_usage_reads_the_key_details(self):
        minted = await self.backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.fake.keys[minted.hash]["usage"] = 0.37
        self.assertEqual(await self.backend.usage(minted.hash), 0.37)
        with self.assertRaises(KeyNotFound):
            await self.backend.usage("f" * 64)

    async def test_cleanup_removes_only_this_install_in_this_workspace(self):
        ours = [self.fake.add_key(f"masqai-enigma-{FAKE_INSTANCE}-{n}") for n in range(3)]
        ours.append(self.fake.add_key(f"masqai-enigma-{FAKE_INSTANCE}-9", disabled=True))
        theirs = [
            self.fake.add_key("masqai-enigma-deadbeef-1"),                                   # another install
            self.fake.add_key(f"masqai-enigma-{FAKE_INSTANCE}"),                             # no dash: not our prefix
            self.fake.add_key(f"xmasqai-enigma-{FAKE_INSTANCE}-1"),                          # prefix not at start
            self.fake.add_key("my production key"),                                          # the user's own
            self.fake.add_key(f"masqai-enigma-{FAKE_INSTANCE}-1", workspace_id="default"),   # outside the workspace
        ]
        self.assertEqual(await self.backend.cleanup(), 4)
        self.assertEqual(sorted(self.fake.keys), sorted(theirs))
        for call in self.fake.calls:
            if call.method == "GET" and call.url.path.endswith("/keys"):
                self.assertEqual(call.url.params["workspace_id"], FAKE_WORKSPACE)
                self.assertEqual(call.url.params["include_disabled"], "true")

    async def test_cleanup_pages_through_long_lists(self):
        self.fake.page_size = 3
        for n in range(8):
            self.fake.add_key(f"masqai-enigma-{FAKE_INSTANCE}-{n}")
        self.assertEqual(await self.backend.cleanup(), 8)
        self.assertEqual(self.fake.keys, {})

    async def test_a_list_that_never_ends_is_refused(self):
        endless = httpx.MockTransport(lambda r: httpx.Response(200, json={"data": [
            {"hash": f"{int(r.url.params.get('offset', '0')):064x}", "name": "x"}]}))
        keys = OpenRouterKeys(FAKE_MGMT_KEY, transport=endless)
        with self.assertRaisesRegex(BackendUnavailable, "did not end"):
            await keys.list(workspace_id=FAKE_WORKSPACE)
        await keys.aclose()


class Status(Base):
    async def test_healthy_with_management_key_workspace_and_budget(self):
        status = await self.backend.status()
        self.assertTrue(status.healthy, status.detail)
        self.assertEqual(status.management_expires_at, datetime(2026, 12, 31, tzinfo=timezone.utc))

    async def test_a_workspace_without_a_budget_is_unhealthy(self):
        self.fake.budgets = []
        status = await self.backend.status()
        self.assertFalse(status.healthy)
        self.assertIn("no budget", status.detail)

    async def test_a_missing_workspace_is_unhealthy(self):
        self.fake.workspaces = set()
        status = await self.backend.status()
        self.assertFalse(status.healthy)
        self.assertIn("does not exist", status.detail)


class Fence(unittest.IsolatedAsyncioTestCase):
    """The management client can reach only the management endpoints on openrouter.ai, and never leaks its key."""

    async def test_only_allowlisted_paths(self):
        fake = FakeOpenRouter()
        keys = OpenRouterKeys(FAKE_MGMT_KEY, transport=fake.transport)
        for method, path in (("POST", "/chat/completions"), ("GET", "/models"), ("DELETE", "/keys"),
                             ("PUT", f"/workspaces/{FAKE_WORKSPACE}/budgets/monthly"), ("GET", "/keys/../credits")):
            with self.assertRaisesRegex(CustodyError, "refuses"):
                await keys._call(method, path)
        self.assertEqual(fake.calls, [])
        await keys.aclose()

    async def test_redirects_are_not_followed_and_proxies_are_ignored(self):
        seen: list[httpx.Request] = []

        def redirect(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(307, headers={"location": "https://evil.test/collect"})
        keys = OpenRouterKeys(FAKE_MGMT_KEY, transport=httpx.MockTransport(redirect))
        with self.assertRaises(BackendUnavailable):
            await keys.list(workspace_id=FAKE_WORKSPACE)
        self.assertEqual([r.url.host for r in seen], ["openrouter.ai"])
        client = keys._http()
        self.assertFalse(client.follow_redirects)
        self.assertFalse(client.trust_env)
        await keys.aclose()

    async def test_error_messages_never_echo_keys(self):
        leaked = "sk-or-v1-FAKEFAKEFAKEFAKEFAKEFAKEechoed"
        keys = OpenRouterKeys(FAKE_MGMT_KEY, transport=httpx.MockTransport(
            lambda r: httpx.Response(400, json={"error": {"message": f"bad key {leaked} and {FAKE_MGMT_KEY}"}})))
        with self.assertRaises(CustodyError) as caught:
            await keys.list(workspace_id=FAKE_WORKSPACE)
        self.assertNotIn(leaked, str(caught.exception))
        self.assertNotIn(FAKE_MGMT_KEY, str(caught.exception))
        await keys.aclose()

    async def test_huge_responses_are_refused(self):
        keys = OpenRouterKeys(FAKE_MGMT_KEY, transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=b"x" * (5 * 1024 * 1024))))
        with self.assertRaisesRegex(BackendUnavailable, "too large"):
            await keys.list(workspace_id=FAKE_WORKSPACE)
        await keys.aclose()

    async def test_network_errors_do_not_carry_request_details(self):
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"failed sending {request.headers['authorization']}")
        keys = OpenRouterKeys(FAKE_MGMT_KEY, transport=httpx.MockTransport(boom))
        with self.assertRaises(BackendUnavailable) as caught:
            await keys.current()
        self.assertNotIn(FAKE_MGMT_KEY, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)
        await keys.aclose()


class FakeBackendBehaves(unittest.IsolatedAsyncioTestCase):
    async def test_fake_backend_round_trip(self):
        backend = FakeBackend()
        minted = await backend.mint(suffix="1", expires_at=soon(), limit_usd=2.0)
        self.assertIn("FAKE", minted.key)
        self.assertTrue(minted.name.startswith(f"masqai-enigma-{FAKE_INSTANCE}-"))
        backend.spend[minted.hash] = 0.5
        self.assertEqual(await backend.usage(minted.hash), 0.5)
        self.assertEqual(await backend.revoke(minted.hash), "deleted")
        self.assertEqual(await backend.revoke(minted.hash), "already_gone")
        backend.mint_errors.append(BackendUnavailable("down"))
        with self.assertRaises(BackendUnavailable):
            await backend.mint(suffix="2", expires_at=soon(), limit_usd=2.0)
        self.assertTrue((await backend.status()).healthy)


if __name__ == "__main__":
    unittest.main()
