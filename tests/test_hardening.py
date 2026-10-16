"""Tier A hardening: fail-closed passthrough, response isolation, host allowlist, size limits,
remote security model enforcement, full private-key detection, masked client errors."""
import json
import unittest
from unittest.mock import patch

import httpx

from masqai.app import create_app
from masqai.config import DetectorConfig, GatewayConfig, ModelRoute, ProviderConfig, SecurityModelConfig, is_loopback_url
from masqai.detectors import seed_entities
from masqai.model import Session
from masqai.streaming import SSETransformer, StreamLimitError
from masqai.upstream import ResponseTooLarge, read_limited

REAL_CLIENT = httpx.AsyncClient

KEY = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx1y2\nZm9vYmFyYmF6cXV4\n-----END RSA PRIVATE KEY-----")


def config(**kw):
    return GatewayConfig(providers=[ProviderConfig(name="up", base_url="http://upstream"), ProviderConfig(name="sec", base_url="http://127.0.0.1:1")],
                         default_route=ModelRoute(provider="up"), security=SecurityModelConfig(enabled=False),
                         detectors=DetectorConfig(detect_host_identifiers=False), **kw)


class Hardening(unittest.IsolatedAsyncioTestCase):
    async def client(self, cfg=None, host="localhost"):
        return REAL_CLIENT(transport=httpx.ASGITransport(app=create_app(cfg or config())), base_url=f"http://{host}")

    # --- #1 catch-all fails closed ---
    async def test_unsanitized_endpoints_are_refused(self):
        calls = []
        with patch("httpx.AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200)), **kw)):
            async with await self.client() as client:
                for method, path in [("POST", "/v1/chat/completions/"), ("POST", "/v1/completions"), ("POST", "/v1/embeddings"),
                                     ("POST", "/v1/messages/batches"), ("PUT", "/v1/files"), ("DELETE", "/v1/models/x")]:
                    response = await client.request(method, path, json={"input": "a@example.com"})
                    self.assertEqual(response.status_code, 404, (method, path))
                    self.assertEqual(response.json()["error"]["type"], "masqai_unsupported_endpoint")
        self.assertEqual(calls, [])

    async def test_models_listing_still_passes_through(self):
        def handler(request):
            self.assertEqual(request.url.path, "/v1/models")
            return httpx.Response(200, json={"data": []}, headers={"set-cookie": "a=b"})
        with patch("httpx.AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw)):
            async with await self.client() as client:
                response = await client.get("/v1/models")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"data": []})
        self.assertNotIn("set-cookie", response.headers)

    # --- #2 response isolation ---
    async def test_proxied_responses_cannot_run_as_pages(self):
        def handler(request):
            return httpx.Response(200, content=b"<script>fetch('/api/state')</script>",
                                  headers={"content-type": "text/html", "set-cookie": "x=1", "content-security-policy": "default-src *"})
        with patch("httpx.AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw)):
            async with await self.client() as client:
                response = await client.get("/v1/models")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertIn("sandbox", response.headers["content-security-policy"])
        self.assertNotIn("default-src *", response.headers["content-security-policy"])
        self.assertNotIn("set-cookie", response.headers)

    async def test_gui_has_csp(self):
        async with await self.client() as client:
            response = await client.get("/")
        self.assertIn("script-src 'self'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-frame-options"], "DENY")

    async def test_cross_site_browser_requests_refused(self):
        async with await self.client() as client:
            for site in ("cross-site", "same-site"):
                response = await client.get("/api/state", headers={"sec-fetch-site": site})
                self.assertEqual(response.status_code, 403, site)
            self.assertEqual((await client.get("/api/state", headers={"sec-fetch-site": "same-origin"})).status_code, 200)
            self.assertEqual((await client.get("/", headers={"sec-fetch-site": "none"})).status_code, 200)
            self.assertEqual((await client.get("/api/state")).status_code, 200)   # agents/SDKs send no fetch metadata

    # --- #12 host allowlist ---
    async def test_testserver_host_refused(self):
        async with await self.client(host="testserver") as client:
            self.assertEqual((await client.get("/api/state")).status_code, 403)

    # --- #4 remote security model ---
    def test_loopback_detection(self):
        for url in ("http://127.0.0.1:11434", "http://localhost:1", "http://[::1]:8", "http://127.5.0.1"):
            self.assertTrue(is_loopback_url(url), url)
        for url in ("https://openrouter.ai/api", "http://127.0.0.1.evil.tld", "http://0.0.0.0", "http://10.0.0.1"):
            self.assertFalse(is_loopback_url(url), url)

    async def test_remote_security_model_refused_when_disallowed(self):
        cfg = config(allow_remote_security_model=False)
        cfg.security = SecurityModelConfig(enabled=True, provider="up", model="guard")
        sent = []
        with patch("masqai.sanitize.httpx.AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(500)), **kw)):
            async with await self.client(cfg) as client:
                response = await client.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(response.status_code, 502)
        self.assertIn("allow_remote_security_model", response.json()["error"]["message"])
        self.assertEqual(sent, [])

    async def test_meta_advertises_remote_check(self):
        async with await self.client() as client:
            self.assertTrue((await client.get("/api/config/meta")).json()["features"]["remote_security_check"])

    # --- #7a full private key ---
    def test_private_key_body_detected(self):
        session = Session("s")
        [entity] = seed_entities(session, [f"cat id_rsa\n{KEY}\ndone"], DetectorConfig(detect_host_identifiers=False))
        self.assertEqual(entity.canonical, KEY)

    def test_truncated_private_key_detected(self):
        session = Session("s")
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nAAAAB3Nz"
        [entity] = seed_entities(session, [text + "\n... output truncated"], DetectorConfig(detect_host_identifiers=False))
        self.assertTrue(entity.canonical.startswith(text))
        self.assertNotIn("truncated", entity.canonical)

    async def test_private_key_never_reaches_upstream(self):
        captured = {}

        async def upstream(provider, path, body, headers, timeout, policy=None):
            captured.update(body)
            return httpx.Response(200, json={"choices": []}, headers={"content-type": "application/json"})
        with patch("masqai.app.upstream_request", upstream):
            async with await self.client() as client:
                await client.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "tool", "tool_call_id": "1", "content": KEY}]})
        self.assertNotIn("MIIEowIBAAKCAQEAx1y2", json.dumps(captured))

    # --- #14 limits ---
    def test_sse_frame_and_argument_limits(self):
        with patch("masqai.streaming.MAX_FRAME_BYTES", 100):
            with self.assertRaises(StreamLimitError):
                SSETransformer([]).feed(b"data: " + b"x" * 200)
        with patch("masqai.streaming.MAX_ARGUMENT_CHARS", 10):
            frame = json.dumps({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "y" * 20}}]}}]})
            with self.assertRaises(StreamLimitError):
                SSETransformer([]).feed(f"data: {frame}\n\n".encode())

    def test_invalid_utf8_frame_forwarded_untouched(self):
        frame = b"data: \xff\xfe\n\n"
        self.assertEqual(SSETransformer([]).feed(frame), [frame])

    async def test_read_limited(self):
        response = httpx.Response(200, content=b"x" * 50)
        with self.assertRaises(ResponseTooLarge):
            await read_limited(response, limit=10)
        self.assertEqual(await read_limited(httpx.Response(200, content=b"ok"), limit=10), b"ok")

    # --- #18 masked client errors ---
    async def test_gateway_error_is_masked(self):
        async def upstream(provider, path, body, headers, timeout, policy=None):
            raise RuntimeError("could not send a@example.com")
        with patch("masqai.app.upstream_request", upstream):
            async with await self.client() as client:
                response = await client.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": "a@example.com"}]})
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("a@example.com", response.text)
        self.assertIn("<EMAIL_", response.text)

    async def test_non_json_body_rejected(self):
        async with await self.client() as client:
            self.assertEqual((await client.post("/v1/chat/completions", content=b"not json")).status_code, 400)
            self.assertEqual((await client.post("/v1/chat/completions", json=[1])).status_code, 400)


if __name__ == "__main__":
    unittest.main()
