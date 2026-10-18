"""Key Enigma step 3: the rotating key source (mint ahead, validate, swap, drain, revoke, confirm dead).

Time is a fake clock that only moves when a test advances it, so every interval, drain cap and retry is exact and
the suite runs in milliseconds. Keys come from tests.helpers.FakeBackend (FAKE-marked, no HTTP).
"""
import asyncio
import heapq
import itertools
import threading
import unittest
from datetime import datetime, timedelta, timezone

import httpx

from masqai.custody import BackendUnavailable, ManagementAuthError
from masqai.enigma import (ACTIVE, DEAD, DRAINING, REVOKE_FAILED, REVOKED, EnigmaKeySource, KeyRing, KeyUnavailable,
                           RotationPolicy)
from tests.helpers import FakeBackend, gateway, sse

START = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    """Monotonic and wall time that move together, only via advance(). sleep() parks until the clock reaches it."""

    def __init__(self) -> None:
        self.now = 1000.0
        self._sleepers: list[tuple[float, int, asyncio.Future]] = []
        self._order = itertools.count()

    def monotonic(self) -> float:
        return self.now

    def utcnow(self) -> datetime:
        return START + timedelta(seconds=self.now - 1000.0)

    async def sleep(self, seconds: float) -> None:
        if seconds <= 0:
            await asyncio.sleep(0)
            return
        future = asyncio.get_running_loop().create_future()
        heapq.heappush(self._sleepers, (self.now + seconds, next(self._order), future))
        await future

    async def settle(self) -> None:
        for _ in range(50):
            await asyncio.sleep(0)

    async def advance(self, seconds: float) -> None:
        """Move time forward, waking each sleeper at its own moment, in order."""
        target = self.now + seconds
        await self.settle()
        while self._sleepers and self._sleepers[0][0] <= target:
            when, _, future = heapq.heappop(self._sleepers)
            self.now = max(self.now, when)
            if not future.done():
                future.set_result(None)
            await self.settle()
        self.now = target
        await self.settle()


class Fixed:
    """A 'random' generator that always returns the same point of the jitter range (1.0 = no jitter)."""

    def __init__(self, factor: float = 1.0) -> None:
        self.factor = factor
        self.calls: list[tuple[float, float]] = []

    def uniform(self, low: float, high: float) -> float:
        self.calls.append((low, high))
        return self.factor


POLICY = RotationPolicy(interval_seconds=900, jitter=0.2, lead_seconds=60, drain_cap_seconds=600,
                        safety_margin_seconds=120, per_key_limit_usd=2.0, validate_window_seconds=10,
                        settle_seconds=5, confirm_window_seconds=120, confirm_every_seconds=2)


class Rig(unittest.IsolatedAsyncioTestCase):
    """One EnigmaKeySource on a FakeBackend and a FakeClock. The probe answers from the backend's live set."""

    policy = POLICY

    async def asyncSetUp(self) -> None:
        self.clock = FakeClock()
        self.backend = FakeBackend()
        self.dead_after: dict[str, int] = {}     # key -> probes still answered 200 after revocation
        self.invalid: set[str] = set()            # keys that never validate
        self.probes: list[str] = []
        self.source = EnigmaKeySource("openrouter", self.backend, self.policy, clock=self.clock, probe=self.probe, rng=Fixed())

    async def asyncTearDown(self) -> None:
        await self.source.stop()

    async def probe(self, key: str) -> bool:
        self.probes.append(key)
        if key in self.invalid:
            return False
        if any(m.key == key for m in self.backend.live.values()):
            return True
        left = self.dead_after.get(key, 0)
        if left > 0:
            self.dead_after[key] = left - 1
            return True
        return False

    def keys(self) -> list[str]:
        return [m.key for m in self.backend.live.values()]


class Policy(unittest.TestCase):
    def test_defaults_and_expiry_formula(self):
        policy = RotationPolicy()
        self.assertEqual((policy.interval_seconds, policy.jitter, policy.per_key_limit_usd), (900, 0.2, 2.0))
        self.assertEqual(policy.ttl_seconds, 900 * 1.2 + 60 + 600 + 120)   # about 31 min (§5)

    def test_unsafe_values_are_refused(self):
        for bad in ({"interval_seconds": 299}, {"jitter": 0.6}, {"jitter": -0.1}, {"lead_seconds": 0},
                    {"lead_seconds": 900}, {"drain_cap_seconds": 0}, {"per_key_limit_usd": 0},
                    {"interval_seconds": float("inf")}, {"per_key_limit_usd": float("nan")}, {"settle_seconds": -1},
                    {"validate_window_seconds": 0}, {"jitter": True}):
            with self.assertRaises(ValueError, msg=str(bad)):
                RotationPolicy(**bad)


class Startup(Rig):
    async def test_no_lease_before_start(self):
        with self.assertRaises(KeyUnavailable):
            self.source.lease()

    async def test_first_key_is_minted_validated_and_active(self):
        await self.source.start()
        record = self.source.active
        self.assertEqual(record.state, ACTIVE)
        self.assertEqual(self.probes, [record.minted.key])            # validated before use
        self.assertTrue(record.minted.name.startswith("masqai-enigma-3f9a1c07-"))
        self.assertEqual(record.minted.expires_at, START + timedelta(seconds=POLICY.ttl_seconds))
        self.assertEqual(record.minted.limit_usd, 2.0)
        self.assertEqual(record.deadline, self.clock.now + 900)
        with self.source.lease() as key:
            self.assertEqual(key, record.minted.key)

    async def test_a_key_that_never_validates_is_discarded_and_startup_fails_closed(self):
        original = self.backend.mint

        async def mint(**kw):
            minted = await original(**kw)
            self.invalid.add(minted.key)
            return minted
        self.backend.mint = mint
        start = asyncio.ensure_future(self.source.start())
        for _ in range(10):
            await self.clock.advance(15)
        with self.assertRaisesRegex(KeyUnavailable, "first key"):
            await start
        await self.clock.settle()
        self.assertEqual(self.backend.live, {})                       # every discarded key was revoked
        self.assertEqual(len(self.backend.revoked), 3)
        with self.assertRaises(KeyUnavailable):
            self.source.lease()

    async def test_a_new_key_may_take_a_few_seconds_to_work(self):
        original = self.backend.mint

        async def mint(**kw):
            minted = await original(**kw)
            self.invalid.add(minted.key)
            return minted
        self.backend.mint = mint
        start = asyncio.ensure_future(self.source.start())
        await self.clock.settle()
        self.invalid.clear()          # creation propagated after the first probe
        await self.clock.advance(1)
        await start
        self.assertEqual(self.source.active.state, ACTIVE)
        self.assertEqual(len(self.probes), 2)
        self.assertEqual(self.backend.revoked, [])

    async def test_a_refused_management_key_fails_startup_at_once(self):
        self.backend.mint_errors.append(ManagementAuthError("OpenRouter POST /keys -> 401"))
        with self.assertRaisesRegex(KeyUnavailable, "401"):
            await self.source.start()
        self.assertEqual(len(self.backend.live), 0)

    async def test_startup_retries_a_transient_failure(self):
        self.backend.mint_errors.append(BackendUnavailable("down"))
        start = asyncio.ensure_future(self.source.start())
        await self.clock.advance(2)
        await start
        self.assertEqual(self.source.active.label, "enigma-002")


class Rotation(Rig):
    async def test_successor_is_ready_before_the_interval_ends_and_swaps_on_time(self):
        await self.source.start()
        first = self.source.active
        await self.clock.advance(900 - 60 - 1)
        self.assertEqual(len(self.backend.live), 1)                   # not yet: minted `lead` seconds ahead
        await self.clock.advance(2)
        self.assertEqual(len(self.backend.live), 2)                   # minted and validated, waiting
        self.assertIs(self.source.active, first)
        with self.source.lease() as key:
            self.assertEqual(key, first.minted.key)
        await self.clock.advance(59)
        second = self.source.active
        self.assertIsNot(second, first)
        self.assertEqual(second.state, ACTIVE)
        with self.source.lease() as key:
            self.assertEqual(key, second.minted.key)
        await self.clock.advance(5)                                   # idle: revoked after the settle wait
        self.assertIn(first.minted.hash, self.backend.revoked)
        self.assertEqual(first.state, DEAD)
        self.assertEqual(self.keys(), [second.minted.key])

    async def test_jitter_draws_from_the_whole_range(self):
        rng = Fixed(1.2)
        self.source.rng = rng
        await self.source.start()
        self.assertEqual(rng.calls[-1], (0.8, 1.2))
        self.assertEqual(self.source.active.deadline - self.clock.now, 900 * 1.2)

    async def test_a_lease_after_the_deadline_never_gets_the_old_key(self):
        await self.source.start()
        first = self.source.active
        await self.clock.advance(850)                                 # successor waiting
        self.clock.now = first.deadline + 0.001                       # the task has not woken yet
        with self.source.lease() as key:
            self.assertNotEqual(key, first.minted.key)
        self.assertEqual(first.state, DRAINING)
        await self.clock.advance(1)
        self.assertIsNot(self.source.active, first)                   # the task saw the swap and did not repeat it
        self.assertEqual(sum(1 for e in self.source.events if e["type"] == "activated"), 2)

    async def test_an_open_lease_holds_the_old_key_until_released(self):
        await self.source.start()
        first = self.source.active
        lease = self.source.lease()                                   # a long stream
        await self.clock.advance(900 + 300)
        self.assertEqual(first.state, DRAINING)
        self.assertIn(first.minted.hash, self.backend.live)           # not revoked under the stream
        self.assertIn((first.minted.key, "OR_KEY"), self.source.known_secrets())
        lease.release()
        await self.clock.advance(5)
        self.assertNotIn(first.minted.hash, self.backend.live)
        self.assertFalse(first.forced)

    async def test_the_drain_cap_revokes_a_key_whose_stream_hangs(self):
        await self.source.start()
        first = self.source.active
        lease = self.source.lease()
        await self.clock.advance(900 + 600 - 1)
        self.assertIn(first.minted.hash, self.backend.live)
        await self.clock.advance(1 + 5)
        self.assertNotIn(first.minted.hash, self.backend.live)
        self.assertTrue(first.forced)
        self.assertTrue(any(e["type"] == "drain_cap_reached" for e in self.source.events))
        lease.release()                                               # late release is harmless

    async def test_usage_is_read_before_revocation_and_summed(self):
        await self.source.start()
        first = self.source.active
        self.backend.spend[first.minted.hash] = 0.42
        await self.clock.advance(900 + 5)
        self.assertEqual(first.usage_usd, 0.42)
        self.assertAlmostEqual(self.source.spend_usd, 0.42)

    async def test_propagation_delay_is_measured(self):
        await self.source.start()
        first = self.source.active
        self.dead_after[first.minted.key] = 3                         # still accepted for 3 probes after DELETE
        await self.clock.advance(900 + 5)
        self.assertEqual(first.state, REVOKED)
        self.assertIn((first.minted.key, "OR_KEY"), self.source.known_secrets())   # may still work: still masked
        await self.clock.advance(10)
        self.assertEqual(first.state, DEAD)
        self.assertEqual(self.source.propagation_seconds, [6.0])
        self.assertNotIn((first.minted.key, "OR_KEY"), self.source.known_secrets())

    async def test_many_rotations_keep_exactly_one_live_key_at_rest(self):
        await self.source.start()
        labels = []
        for _ in range(6):
            await self.clock.advance(900)
            labels.append(self.source.active.label)
        await self.clock.advance(10)
        self.assertEqual(labels, [f"enigma-{n:03d}" for n in range(2, 8)])
        self.assertEqual(len(self.backend.live), 1)
        self.assertEqual(len(self.backend.revoked), 6)
        names = [m.name for m in self.backend.live.values()]
        self.assertTrue(all(n.startswith("masqai-enigma-3f9a1c07-") for n in names))


class FailClosed(Rig):
    async def test_interval_end_without_successor_refuses_then_recovers(self):
        await self.source.start()
        first = self.source.active
        self.backend.mint_errors.extend([BackendUnavailable("down")] * 30)
        await self.clock.advance(900)
        with self.assertRaises(KeyUnavailable):
            self.source.lease()
        self.assertTrue(any(e["type"] == "interval_ended_without_successor" for e in self.source.events))
        await self.clock.advance(10)
        self.assertNotIn(first.minted.hash, self.backend.live)        # the old key is gone even with no successor
        self.backend.mint_errors.clear()
        await self.clock.advance(60)
        with self.source.lease() as key:
            self.assertNotEqual(key, first.minted.key)

    async def test_a_dead_rotation_task_cannot_extend_a_key(self):
        await self.source.start()
        first = self.source.active
        self.source._task.cancel()
        await self.clock.settle()
        self.clock.now = first.deadline
        with self.assertRaises(KeyUnavailable):
            self.source.lease()
        await self.clock.advance(5)                                   # retired by the lease itself, then revoked
        self.assertNotIn(first.minted.hash, self.backend.live)
        self.assertEqual(first.state, DEAD)

    async def test_a_key_is_never_leased_past_expires_at_minus_the_drain(self):
        self.source.rng = Fixed(1.2)
        await self.source.start()
        record = self.source.active
        latest_lease = record.deadline
        expires = 1000.0 + (record.minted.expires_at - START).total_seconds()
        self.assertLessEqual(latest_lease + POLICY.drain_cap_seconds, expires)

    async def test_a_short_lived_key_gets_a_short_interval(self):
        original = self.backend.mint

        async def short(**kw):   # OpenRouter granted less than asked (allowed: it is the safe direction)
            kw["expires_at"] = START + timedelta(seconds=POLICY.drain_cap_seconds + POLICY.safety_margin_seconds + 100)
            return await original(**kw)
        self.backend.mint = short
        await self.source.start()
        self.assertEqual(self.source.active.deadline - self.clock.now, 100)

    async def test_failed_revocation_is_reported_and_kept_masked_until_expiry(self):
        await self.source.start()
        first = self.source.active

        async def broken(key_hash):
            raise BackendUnavailable("down")
        self.backend.revoke = broken
        await self.clock.advance(900 + 5)
        self.assertEqual(first.state, REVOKE_FAILED)
        self.assertIn((first.minted.key, "OR_KEY"), self.source.known_secrets())
        await self.clock.advance(POLICY.ttl_seconds)
        self.assertNotIn((first.minted.key, "OR_KEY"), self.source.known_secrets())

    async def test_stop_refuses_leases_and_revokes_everything(self):
        await self.source.start()
        await self.clock.advance(850)                                 # a standby exists too
        self.assertEqual(len(self.backend.live), 2)
        await self.source.stop()
        self.assertEqual(self.backend.live, {})
        with self.assertRaises(KeyUnavailable):
            self.source.lease()


class Secrets(Rig):
    async def test_snapshot_and_events_hold_no_key_values(self):
        await self.source.start()
        await self.clock.advance(900 + 5)
        text = repr(self.source.snapshot()) + repr(list(self.source.events)) + repr(self.source.active)
        for minted in [*self.backend.live.values()]:
            self.assertNotIn(minted.key, text)
            self.assertNotIn(minted.hash, text)                       # short hashes only
        self.assertNotIn("sk-or-v1", text)

    async def test_standby_key_is_masked_before_it_is_used(self):
        await self.source.start()
        await self.clock.advance(850)
        standby = [m for m in self.backend.live.values() if m.key != self.source.active.minted.key]
        self.assertEqual(len(standby), 1)
        self.assertIn((standby[0].key, "OR_KEY"), self.source.known_secrets())


class Threads(Rig):
    async def test_concurrent_leases_during_swaps_each_get_one_valid_key(self):
        await self.source.start()
        seen: list[str] = []
        errors: list[Exception] = []
        stop = threading.Event()

        def worker():
            while not stop.is_set():
                try:
                    with self.source.lease() as key:
                        valid = {m.key for m in self.backend.live.values()}
                        if key not in valid:
                            errors.append(AssertionError("leased a revoked key"))
                        seen.append(key)
                except KeyUnavailable as exc:
                    errors.append(exc)
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for _ in range(4):
            await self.clock.advance(450)
            await asyncio.sleep(0.01)
        stop.set()
        for t in threads:
            t.join()
        await self.clock.advance(10)
        self.assertEqual(errors, [])
        self.assertGreater(len(set(seen)), 1)
        self.assertTrue(all(r.refcount == 0 for r in self.source._records))


class Gateway(unittest.TestCase):
    """Through the real app: requests use the rotating key; a stream survives a swap; no key means 503."""

    def make(self):
        self.clock = FakeClock()
        self.backend = FakeBackend()

        async def probe(key):
            return any(m.key == key for m in self.backend.live.values())
        self.source = EnigmaKeySource("up", self.backend, POLICY, clock=self.clock, probe=probe, rng=Fixed())
        return KeyRing({"up": self.source})

    def test_requests_use_the_active_key(self):
        ring = self.make()
        with gateway(keyring=ring) as (app, client, fakes):
            with client:
                r = client.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
                self.assertEqual(r.status_code, 200)
                self.assertEqual(fakes.upstream_calls[-1].headers["authorization"], f"Bearer {self.source.active.minted.key}")
            self.assertEqual(self.backend.live, {})                   # shutdown revoked it

    def test_no_key_is_503_and_nothing_is_sent(self):
        ring = self.make()
        with gateway(keyring=ring) as (app, client, fakes):
            with client:
                self.source._active = None
                r = client.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
                self.assertEqual(r.status_code, 503)
                self.assertEqual(r.json()["error"]["type"], "masqai_key_unavailable")
                self.assertEqual(client.get("/v1/models").status_code, 503)
                self.assertEqual(fakes.upstream_calls, [])

    def test_startup_fails_closed_without_a_first_key(self):
        ring = self.make()
        self.backend.mint_errors.append(ManagementAuthError("refused"))
        with gateway(keyring=ring) as (app, client, fakes):
            with self.assertRaises(KeyUnavailable):
                with client:
                    pass

    def test_a_stream_started_on_key_n_finishes_after_the_swap(self):
        ring = self.make()
        source, clock = self.source, self.clock
        gate = threading.Event()
        used: list[str] = []
        states: list[str] = []

        class Slow(httpx.AsyncByteStream, httpx.SyncByteStream):
            data = sse({"choices": [{"index": 0, "delta": {"content": "a"}}]},
                       {"choices": [{"index": 0, "delta": {"content": "b"}, "finish_reason": "stop"}]}) + b"data: [DONE]\n\n"
            first: object = None

            async def __aiter__(self):
                yield self.data[:20]
                await asyncio.get_running_loop().run_in_executor(None, gate.wait)
                states.append(Slow.first.state)
                yield self.data[20:]

            def __iter__(self):
                yield self.data

        with gateway(keyring=ring) as (app, client, fakes):
            def upstream(request):
                used.append(request.headers["authorization"])
                return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=Slow())
            fakes.upstream = upstream
            with client:
                Slow.first = source.active
                first = source.active
                result: dict = {}

                def run():
                    result["r"] = client.post("/v1/chat/completions",
                                              json={"model": "m", "stream": True, "messages": [{"role": "user", "content": "hi"}]})
                t = threading.Thread(target=run)
                t.start()
                while not used:
                    threading.Event().wait(0.01)
                client.portal.call(clock.advance, 900 + 30)           # swap happens mid-stream
                self.assertIsNot(source.active, first)
                self.assertIn(first.minted.hash, self.backend.live)   # still open: not revoked
                gate.set()
                t.join()
                client.portal.call(clock.advance, 10)
                self.assertEqual(result["r"].status_code, 200)
                self.assertIn(b"[DONE]", result["r"].content)
                self.assertEqual(used, [f"Bearer {first.minted.key}"])
                self.assertEqual(states, [DRAINING])
                self.assertNotIn(first.minted.hash, self.backend.live)
                self.assertFalse(first.forced)


if __name__ == "__main__":
    unittest.main()
