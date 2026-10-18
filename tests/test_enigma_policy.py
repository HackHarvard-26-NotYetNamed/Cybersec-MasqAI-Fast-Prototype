"""Key Enigma steps 4-5: failure policy, emergency rotation, startup cleanup, masking, and the status API.

Same fake clock and fake backend as test_rotation.py. Synthetic keys only.
"""
import asyncio
import json
import unittest
from datetime import timedelta

import httpx

from masqai.custody import BackendUnavailable, ManagementAuthError
from masqai.enigma import DEAD, DRAINING, EnigmaKeySource, KeyRing, KeyUnavailable, RotationPolicy, rejection_reason
from tests.helpers import FakeBackend, TOKEN, api, gateway, make_config, sse
from tests.test_rotation import POLICY, START, FakeClock, Fixed, Rig

OPEN = RotationPolicy(**{**{k: getattr(POLICY, k) for k in vars(POLICY)}, "failure_policy": "open"})


def chat(content="hi", **extra):
    return {"model": "m", "messages": [{"role": "user", "content": content}], **extra}


def limit_body():
    return json.dumps({"error": {"code": 402, "message": "Key limit exceeded",
                                 "metadata": {"limit_source": "openrouter_key_limit"}}}).encode()


class Reasons(unittest.TestCase):
    def test_only_key_problems_trigger_rotation(self):
        self.assertEqual(rejection_reason(401, b"{}"), "revoked_externally")
        self.assertEqual(rejection_reason(402, limit_body()), "key_limit")
        self.assertEqual(rejection_reason(403, json.dumps({"error": {"limit_source": "openrouter_key_limit"}}).encode()), "key_limit")
        for status, body in ((402, {"error": {"metadata": {"limit_source": "openrouter_credits"}}}),
                             (402, {"error": {"metadata": {"limit_source": "openrouter_in_flight_budget"}}}),
                             (403, {"error": {"message": "guardrail"}}), (429, {}), (500, {}), (400, {})):
            self.assertIsNone(rejection_reason(status, json.dumps(body).encode()), (status, body))
        self.assertIsNone(rejection_reason(402, b"not json"))

    def test_policy_validates_failure_policy(self):
        with self.assertRaises(ValueError):
            RotationPolicy(failure_policy="maybe")
        with self.assertRaises(ValueError):
            RotationPolicy(emergency_max=-1)


class Cleanup(Rig):
    async def test_leftovers_are_removed_before_the_first_mint(self):
        order = []
        cleanup, mint = self.backend.cleanup, self.backend.mint

        async def tracked_cleanup():
            order.append("cleanup")
            return await cleanup()

        async def tracked_mint(**kw):
            order.append("mint")
            return await mint(**kw)
        self.backend.cleanup, self.backend.mint = tracked_cleanup, tracked_mint
        self.backend.leftovers = ["a", "b"]
        await self.source.start()
        self.assertEqual(order[:2], ["cleanup", "mint"])
        self.assertEqual(self.source.cleaned_up, 2)
        self.assertEqual(self.source.snapshot()["cleaned_up"], 2)

    async def test_a_failed_cleanup_does_not_block_startup(self):
        async def broken():
            raise BackendUnavailable("down")
        self.backend.cleanup = broken
        await self.source.start()
        self.assertIsNotNone(self.source.active)
        self.assertTrue(any(e["type"] == "cleanup_failed" for e in self.source.events))

    async def test_a_refused_management_key_at_cleanup_fails_startup(self):
        async def refused():
            raise ManagementAuthError("401")
        self.backend.cleanup = refused
        with self.assertRaises(KeyUnavailable):
            await self.source.start()
        self.assertEqual(self.backend.live, {})


class Emergency(Rig):
    async def test_a_revoked_key_is_replaced_at_once(self):
        await self.source.start()
        first = self.source.active
        lease = self.source.lease()
        self.assertFalse(self.source.report_rejected(first.minted.key, "revoked_externally"))   # nothing ready yet
        with self.assertRaises(KeyUnavailable):
            self.source.lease()
        await self.clock.advance(1)
        second = self.source.active
        self.assertIsNotNone(second)
        self.assertNotEqual(second.minted.key, first.minted.key)
        # A leaked key is not drained: revoked at once although a lease is still open.
        self.assertNotIn(first.minted.hash, self.backend.live)
        self.assertIn("revoked_externally", [e["type"] for e in self.source.events])
        lease.release()

    async def test_key_limit_rotates_early_but_drains(self):
        await self.source.start()
        first = self.source.active
        lease = self.source.lease()
        self.source.report_rejected(first.minted.key, "key_limit")
        await self.clock.advance(1)
        self.assertIsNot(self.source.active, first)
        self.assertEqual(first.state, DRAINING)                      # its own streams may still finish
        self.assertIn(first.minted.hash, self.backend.live)
        lease.release()
        await self.clock.advance(6)
        self.assertNotIn(first.minted.hash, self.backend.live)

    async def test_with_a_standby_waiting_the_caller_can_retry_at_once(self):
        await self.source.start()
        first = self.source.active
        await self.clock.advance(850)                                # standby validated
        self.assertTrue(self.source.report_rejected(first.minted.key, "revoked_externally"))
        with self.source.lease() as key:
            self.assertNotEqual(key, first.minted.key)

    async def test_stale_reports_are_ignored(self):
        await self.source.start()
        first = self.source.active
        self.source.report_rejected(first.minted.key, "key_limit")
        await self.clock.advance(1)
        second = self.source.active
        self.assertTrue(self.source.report_rejected(first.minted.key, "revoked_externally"))   # already gone: retry ok
        self.assertIs(self.source.active, second)
        self.source.report_rejected("sk-or-v1-FAKEFAKEFAKEFAKEFAKEunrelated", "key_limit")
        self.assertIs(self.source.active, second)                   # a value that is not ours changes nothing
        with self.assertRaises(ValueError):
            self.source.report_rejected(second.minted.key, "other")

    async def test_rotation_storms_are_capped(self):
        await self.source.start()
        minted_at_start = len(self.backend.live) + len(self.backend.revoked)
        for _ in range(3):                                            # three emergencies: each mints early
            self.source.report_rejected(self.source.active.minted.key, "revoked_externally")
            await self.clock.advance(1)
            self.assertIsNotNone(self.source.active)
        fourth = self.source.active
        self.source.report_rejected(fourth.minted.key, "revoked_externally")
        await self.clock.advance(60)
        minted = len(self.backend.live) + len(self.backend.revoked) - minted_at_start
        self.assertEqual(minted, 3)                                  # the 4th report did not mint early
        self.assertIsNone(self.source.active)                        # fail closed meanwhile
        self.assertIn("emergency rotation cap reached", [e.get("detail") for e in self.source.events])
        self.assertNotIn(fourth.minted.hash, self.backend.live)      # but the rejected key itself is revoked
        await self.clock.advance(POLICY.emergency_window_seconds)
        self.assertIsNotNone(self.source.active)                     # recovered once the window has passed


class OpenPolicy(Rig):
    policy = OPEN

    async def test_open_keeps_the_key_past_its_interval_until_the_hard_deadline(self):
        await self.source.start()
        first = self.source.active
        self.backend.mint_errors.extend([BackendUnavailable("down")] * 200)
        await self.clock.advance(900 + 60)
        with self.source.lease() as key:
            self.assertEqual(key, first.minted.key)                 # overstaying, as "open" allows
        hard = self.source.hard_deadline(first)
        self.clock.now = hard + 0.001
        with self.assertRaises(KeyUnavailable):                      # never past expires_at - drain - margin
            self.source.lease()
        expires = 1000.0 + (first.minted.expires_at - START).total_seconds()
        self.assertLessEqual(hard + POLICY.drain_cap_seconds, expires)

    async def test_open_still_swaps_as_soon_as_a_successor_exists(self):
        await self.source.start()
        first = self.source.active
        await self.clock.advance(900 - 60 - 1)
        self.backend.mint_errors.extend([BackendUnavailable("down")] * 6)   # 2+4+8+16+32+60 s of backoff
        await self.clock.advance(61 + 30)
        with self.source.lease() as key:
            self.assertEqual(key, first.minted.key)                  # overstaying: no successor yet
        await self.clock.advance(120)
        self.assertIsNot(self.source.active, first)                  # swapped the moment one validated
        self.assertNotIn(first.minted.hash, self.backend.live)

    async def test_open_never_keeps_a_rejected_key(self):
        await self.source.start()
        first = self.source.active
        self.backend.mint_errors.extend([BackendUnavailable("down")] * 200)
        self.source.report_rejected(first.minted.key, "revoked_externally")
        with self.assertRaises(KeyUnavailable):
            self.source.lease()

    async def test_open_does_not_let_a_condemned_key_overstay(self):
        # The overstay rule itself must refuse a condemned key, not only the emergency swap.
        await self.source.start()
        first = self.source.active
        self.backend.mint_errors.extend([BackendUnavailable("down")] * 200)
        first.condemned = "key_limit"
        self.clock.now = first.deadline + 1
        with self.assertRaises(KeyUnavailable):
            self.source.lease()

    async def test_overstay_rule(self):
        await self.source.start()
        first = self.source.active
        self.clock.now = first.deadline + 1
        self.assertTrue(self.source._may_overstay_locked(first))
        first.condemned = "key_limit"
        self.assertFalse(self.source._may_overstay_locked(first))


class Through(unittest.TestCase):
    """Through the gateway: retry once on a rejected key; masking; the status API."""

    def ring(self, policy=POLICY):
        self.clock = FakeClock()
        self.backend = FakeBackend()

        async def probe(key):
            return any(m.key == key for m in self.backend.live.values())
        self.source = EnigmaKeySource("up", self.backend, policy, clock=self.clock, probe=probe, rng=Fixed())
        return KeyRing({"up": self.source})

    def standby(self, client):
        client.portal.call(self.clock.advance, 850)
        self.assertEqual(len(self.backend.live), 2)

    def test_a_401_is_retried_once_with_a_fresh_key(self):
        for stream in (False, True):
            with self.subTest(stream=stream):
                ring = self.ring()
                with gateway(keyring=ring) as (app, client, fakes), client:
                    self.standby(client)
                    first = self.source.active.minted.key
                    seen = []

                    def upstream(request):
                        seen.append(request.headers["authorization"])
                        if len(seen) == 1:
                            return httpx.Response(401, json={"error": {"code": 401, "message": "User not found."}})
                        if stream:
                            return httpx.Response(200, headers={"content-type": "text/event-stream"},
                                                  content=sse({"choices": [{"index": 0, "delta": {"content": "ok"}, "finish_reason": "stop"}]}) + b"data: [DONE]\n\n")
                        return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]})
                    fakes.upstream = upstream
                    r = client.post("/v1/chat/completions", json=chat(stream=stream))
                    self.assertEqual(r.status_code, 200)
                    self.assertEqual(len(seen), 2)
                    self.assertEqual(seen[0], f"Bearer {first}")
                    self.assertNotEqual(seen[1], seen[0])
                    self.assertTrue(all(r.refcount == 0 for r in self.source._records))

    def test_only_one_retry(self):
        """Even if a fresh key were always ready, the proxy tries at most twice: once, then one retry."""
        class Endless:
            def __init__(self):
                self.n = 0

            def lease(self):
                from masqai.enigma import KeyLease
                self.n += 1
                return KeyLease(f"sk-or-v1-FAKEFAKEFAKEFAKEFAKE{self.n:04d}")

            def known_secrets(self):
                return []

            def report_rejected(self, key, reason):
                return True
        for stream in (False, True):
            with self.subTest(stream=stream):
                with gateway(keyring=KeyRing({"up": Endless()})) as (app, client, fakes):
                    calls = []
                    fakes.upstream = lambda r: calls.append(1) or httpx.Response(401, json={"error": {"code": 401}})
                    r = client.post("/v1/chat/completions", json=chat(stream=stream))
                    self.assertEqual(r.status_code, 401)
                    self.assertEqual(len(calls), 2)

    def test_retry_releases_both_leases(self):
        for stream in (False, True):
            with self.subTest(stream=stream):
                ring = self.ring()
                with gateway(keyring=ring) as (app, client, fakes), client:
                    self.standby(client)
                    fakes.upstream = lambda r: httpx.Response(401, json={"error": {"code": 401}})
                    self.assertEqual(client.post("/v1/chat/completions", json=chat(stream=stream)).status_code, 401)
                    self.assertTrue(all(rec.refcount == 0 for rec in self.source._records))

    def test_no_retry_when_no_successor_is_ready_or_the_error_is_not_about_the_key(self):
        ring = self.ring()
        with gateway(keyring=ring) as (app, client, fakes), client:
            calls = []
            credits = {"error": {"code": 402, "metadata": {"limit_source": "openrouter_credits"}}}
            fakes.upstream = lambda r: calls.append(1) or httpx.Response(402, json=credits)
            self.assertEqual(client.post("/v1/chat/completions", json=chat()).status_code, 402)
            self.assertEqual(len(calls), 1)                          # credits: passed through, no rotation
            self.assertIsNotNone(self.source.active)
            fakes.upstream = lambda r: calls.append(1) or httpx.Response(401, json={"error": {"code": 401}})
            self.assertEqual(client.post("/v1/chat/completions", json=chat()).status_code, 401)
            self.assertEqual(len(calls), 2)                          # rotated, but nothing to retry with yet

    def test_key_limit_retries_with_a_new_key(self):
        ring = self.ring()
        with gateway(keyring=ring) as (app, client, fakes), client:
            self.standby(client)
            seen = []

            def upstream(request):
                seen.append(request.headers["authorization"])
                if len(seen) == 1:
                    return httpx.Response(402, content=limit_body(), headers={"content-type": "application/json"})
                return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]})
            fakes.upstream = upstream
            self.assertEqual(client.post("/v1/chat/completions", json=chat()).status_code, 200)
            self.assertNotEqual(seen[0], seen[1])

    def test_our_keys_are_masked_in_outbound_content(self):
        ring = self.ring()
        with gateway(keyring=ring) as (app, client, fakes), client:
            self.standby(client)
            active = self.source.active.minted.key
            standby = next(m.key for m in self.backend.live.values() if m.key != active)
            r = client.post("/v1/chat/completions", json=chat(f"here is the key {active} and the next one {standby}"))
            self.assertEqual(r.status_code, 200)
            sent = fakes.upstream_calls[-1].content.decode()
            self.assertNotIn(active, sent)
            self.assertNotIn(standby, sent)
            # Only keys that appeared are added to a session's mapping (it is shown in the GUI and exports).
            r = client.post("/v1/chat/completions", json=chat("nothing secret here", user="other-session"))
            self.assertEqual(r.status_code, 200)

    def test_masked_even_when_credentials_are_not_protected(self):
        ring = self.ring()
        config = make_config()
        config.protect.credentials = False
        with gateway(config, keyring=ring) as (app, client, fakes), client:
            active = self.source.active.minted.key
            r = client.post("/v1/chat/completions", json=chat(f"key {active}"))
            self.assertEqual(r.status_code, 200)
            self.assertNotIn(active, fakes.upstream_calls[-1].content.decode())

    def test_upstream_error_text_echoing_our_key_is_scrubbed_from_logs(self):
        ring = self.ring()
        with gateway(keyring=ring) as (app, client, fakes), client:
            active = self.source.active.minted.key
            fakes.upstream = lambda r: httpx.Response(400, json={"error": {"message": f"bad request for {active}"}})
            with self.assertLogs("masqai", level="ERROR") as logged:
                client.post("/v1/chat/completions", json=chat())
            self.assertTrue(logged.output)
            self.assertFalse(any(active in line for line in logged.output))
            self.assertTrue(any("<OR_KEY_enigma>" in line for line in logged.output))

    def test_status_api_requires_the_token_and_holds_no_secrets(self):
        ring = self.ring()
        with gateway(keyring=ring) as (app, client, fakes), client:
            self.standby(client)
            self.assertEqual(client.get("/api/enigma/status").status_code, 401)
            r = api(client, "GET", "/api/enigma/status")
            self.assertEqual(r.status_code, 200)
            body = r.text
            status = r.json()["providers"][0]
            self.assertEqual(status["provider"], "up")
            self.assertEqual(status["active"], "enigma-001")
            self.assertEqual({k["state"] for k in status["keys"]}, {"active", "standby"})
            for minted in self.backend.live.values():
                self.assertNotIn(minted.key, body)
                self.assertNotIn(minted.hash, body)
            self.assertNotIn("sk-or-v1", body)
            self.assertNotIn(TOKEN, body)

    def test_export_api_matches_public_schema_without_secrets(self):
        ring = self.ring()
        with gateway(keyring=ring) as (app, client, fakes), client:
            self.assertEqual(client.get("/api/enigma/export").status_code, 401)
            result = api(client, "GET", "/api/enigma/export")
            self.assertEqual(result.status_code, 200)
            body = result.json()
            self.assertEqual(body["status"], "live")
            self.assertEqual(body["provider"], "OpenRouter")
            self.assertEqual(body["honeytokens"], [])
            self.assertTrue(body["keys"])
            self.assertEqual(set(body["keys"][0]), {"label", "createdAt", "activeUntil", "revokedAt"})
            text = result.text
            for minted in self.backend.live.values():
                self.assertNotIn(minted.key, text)
                self.assertNotIn(minted.hash, text)
            self.assertNotIn("sk-or-v1", text)

    def test_export_api_is_unavailable_without_a_rotating_source(self):
        with gateway() as (app, client, fakes), client:
            result = api(client, "GET", "/api/enigma/export")
            self.assertEqual(result.status_code, 404)

    def test_config_api_never_shows_our_keys(self):
        ring = self.ring()
        with gateway(keyring=ring) as (app, client, fakes), client:
            body = api(client, "GET", "/api/config").text
            self.assertNotIn(self.source.active.minted.key, body)


if __name__ == "__main__":
    unittest.main()
