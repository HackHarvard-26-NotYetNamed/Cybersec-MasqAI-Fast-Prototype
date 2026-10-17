"""Key Enigma step 1: every upstream call leases its key and releases it exactly once, after the call or stream.

No rotation exists yet. These tests pin the seam the rotating source will plug into, and that the default
(env var) behavior is unchanged. Synthetic keys only.
"""
import os
import threading
import unittest
from unittest.mock import patch

import httpx

from masqai.enigma import EnvKeySource, KeyLease, KeyRing
from masqai.upstream import headers_for
from masqai.config import ProviderConfig
from tests.helpers import UPSTREAM, gateway, make_config, sse

ENV_KEY = "sk-or-v1-FAKEFAKEFAKEFAKEFAKEFAKEenv"


class CountingSource:
    """A stand-in for the rotating source: hands out numbered keys and counts open leases."""

    def __init__(self) -> None:
        self.issued = 0
        self.open = 0
        self.max_open = 0
        self.lock = threading.Lock()

    def lease(self) -> KeyLease:
        with self.lock:
            self.issued += 1
            self.open += 1
            self.max_open = max(self.max_open, self.open)
            key = f"sk-or-v1-FAKEFAKEFAKEFAKEFAKE{self.issued:04d}"

        def done() -> None:
            with self.lock:
                self.open -= 1
        return KeyLease(key, done)

    def known_secrets(self) -> list[tuple[str, str]]:
        return []


def chat(**extra):
    return {"model": "m", "messages": [{"role": "user", "content": "hello"}], **extra}


class Lease(unittest.TestCase):
    def test_release_is_idempotent_and_context_manager_releases(self):
        calls = []
        lease = KeyLease("k", lambda: calls.append(1))
        lease.release()
        lease.release()
        self.assertEqual(calls, [1])
        calls.clear()
        with KeyLease("k", lambda: calls.append(1)) as key:
            self.assertEqual(key, "k")
        self.assertEqual(calls, [1])

    def test_env_source_reads_the_variable_on_every_lease(self):
        provider = ProviderConfig(name="p", base_url=UPSTREAM, api_key_env="FAKE_UPSTREAM_KEY")
        source = EnvKeySource(provider)
        with patch.dict(os.environ, {"FAKE_UPSTREAM_KEY": "one"}):
            self.assertEqual(source.lease().key, "one")
        with patch.dict(os.environ, {"FAKE_UPSTREAM_KEY": "two"}):
            self.assertEqual(source.lease().key, "two")
        self.assertIsNone(EnvKeySource(ProviderConfig(name="local", base_url=UPSTREAM)).lease().key)

    def test_keyring_falls_back_to_env_and_prefers_registered_sources(self):
        provider = ProviderConfig(name="up", base_url=UPSTREAM, api_key_env="FAKE_UPSTREAM_KEY")
        with patch.dict(os.environ, {"FAKE_UPSTREAM_KEY": ENV_KEY}):
            self.assertEqual(KeyRing().lease(provider).key, ENV_KEY)
            source = CountingSource()
            self.assertTrue(KeyRing({"up": source}).lease(provider).key.endswith("0001"))

    def test_headers_use_only_the_leased_key(self):
        openai = ProviderConfig(name="o", base_url=UPSTREAM, api_key_env="FAKE_UPSTREAM_KEY")
        anthropic = ProviderConfig(name="a", base_url=UPSTREAM, api_key_env="FAKE_UPSTREAM_KEY", format="anthropic")
        with patch.dict(os.environ, {"FAKE_UPSTREAM_KEY": ENV_KEY}):
            self.assertEqual(headers_for(openai, {}, key="leased")["authorization"], "Bearer leased")
            self.assertEqual(headers_for(anthropic, {}, key="leased")["x-api-key"], "leased")
            self.assertNotIn("authorization", headers_for(openai, {}, key=None))


class DefaultBehavior(unittest.TestCase):
    def test_env_key_is_sent_upstream_as_before(self):
        with patch.dict(os.environ, {"FAKE_UPSTREAM_KEY": ENV_KEY}), gateway() as (app, client, fakes):
            self.assertEqual(client.post("/v1/chat/completions", json=chat()).status_code, 200)
            self.assertEqual(fakes.upstream_calls[-1].headers["authorization"], f"Bearer {ENV_KEY}")
            client.get("/v1/models")
            self.assertEqual(fakes.upstream_calls[-1].headers["authorization"], f"Bearer {ENV_KEY}")


class Leases(unittest.TestCase):
    def setUp(self) -> None:
        self.source = CountingSource()
        self.ring = KeyRing({"up": self.source})

    def test_non_streaming_request_leases_once_and_releases(self):
        with gateway(keyring=self.ring) as (app, client, fakes):
            self.assertEqual(client.post("/v1/chat/completions", json=chat()).status_code, 200)
        self.assertEqual((self.source.issued, self.source.open), (1, 0))
        self.assertEqual(fakes.upstream_calls[0].headers["authorization"], "Bearer sk-or-v1-FAKEFAKEFAKEFAKEFAKE0001")

    def test_upstream_errors_release_the_lease(self):
        with gateway(keyring=self.ring) as (app, client, fakes):
            fakes.upstream = lambda r: httpx.Response(401, json={"error": {"code": 401, "message": "nope"}})
            self.assertEqual(client.post("/v1/chat/completions", json=chat()).status_code, 401)
            self.assertEqual(client.post("/v1/chat/completions", json=chat(stream=True)).status_code, 401)
        self.assertEqual((self.source.issued, self.source.open), (2, 0))

    def test_transport_failure_releases_the_lease(self):
        def boom(request):
            raise httpx.ConnectError("down", request=request)
        with gateway(keyring=self.ring) as (app, client, fakes):
            fakes.upstream = boom
            self.assertEqual(client.post("/v1/chat/completions", json=chat()).status_code, 500)
            self.assertEqual(client.post("/v1/chat/completions", json=chat(stream=True)).status_code, 500)
        self.assertEqual(self.source.open, 0)

    def test_stream_holds_the_lease_until_the_last_byte(self):
        seen_open = []
        source = self.source

        class Watched(httpx.AsyncByteStream, httpx.SyncByteStream):
            data = sse({"choices": [{"index": 0, "delta": {"content": "a"}}]},
                       {"choices": [{"index": 0, "delta": {"content": "b"}, "finish_reason": "stop"}]}) + b"data: [DONE]\n\n"

            async def __aiter__(self):
                for i in range(0, len(self.data), 7):
                    seen_open.append(source.open)   # the stream is still running: its lease must be open
                    yield self.data[i:i + 7]

            def __iter__(self):
                yield self.data

        with gateway(keyring=self.ring) as (app, client, fakes):
            fakes.upstream = lambda r: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=Watched())
            r = client.post("/v1/chat/completions", json=chat(stream=True))
            self.assertEqual(r.status_code, 200)
            self.assertIn(b"[DONE]", r.content)
        self.assertTrue(seen_open and all(n == 1 for n in seen_open))
        self.assertEqual((self.source.issued, self.source.open), (1, 0))

    def test_models_passthrough_leases_and_releases(self):
        with gateway(keyring=self.ring) as (app, client, fakes):
            fakes.upstream = lambda r: httpx.Response(200, json={"data": []})
            self.assertEqual(client.get("/v1/models").status_code, 200)
        self.assertEqual((self.source.issued, self.source.open), (1, 0))

    def test_security_model_calls_lease_their_provider_key(self):
        sec = CountingSource()
        ring = KeyRing({"up": self.source, "sec": sec})
        with gateway(make_config(security=True), keyring=ring) as (app, client, fakes):
            self.assertEqual(client.post("/v1/chat/completions", json=chat()).status_code, 200)
        self.assertGreaterEqual(sec.issued, 1)
        self.assertEqual((sec.open, self.source.open), (0, 0))

    def test_blocked_request_never_leases_the_upstream_key(self):
        with gateway(make_config(security=True), keyring=self.ring) as (app, client, fakes):
            fakes.security_answers = ["not json"]
            r = client.post("/v1/chat/completions", json=chat())
            self.assertEqual(r.status_code, 502)
            self.assertEqual(fakes.upstream_calls, [])
        self.assertEqual(self.source.issued, 0)   # fail closed happens before the key is touched


if __name__ == "__main__":
    unittest.main()
