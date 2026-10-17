"""Milestone 3: hardening (section 7 of the rebuild brief) and the control API. Synthetic values only."""
import json
import os
import unittest
from unittest.mock import patch

import httpx

from masqai.config import GatewayConfig, ProviderConfig, load_config
from masqai.restore import ArgumentStream, StreamLimitError
from masqai.streaming import SSETransformer
from masqai.upstream import ResponseTooLarge, read_limited
from tests.helpers import PORT, TOKEN, api, gateway, make_config

PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAFAKEFAKE\nFAKEFAKEFAKEFAKEFAKEFAKEFAKE==\n-----END OPENSSH PRIVATE KEY-----"


def chat(content):
    return {"model": "m", "messages": [{"role": "user", "content": content}]}


class AdminToken(unittest.TestCase):
    def test_api_needs_the_token(self):
        with gateway() as (app, client, fakes):
            for path in ("/api/state", "/api/security", "/api/config", "/api/config/meta", "/api/env/FAKE_UPSTREAM_KEY"):
                self.assertEqual(client.get(path).status_code, 401, path)
                self.assertEqual(client.get(path, headers={"x-masqai-token": "wrong"}).status_code, 401, path)
                self.assertEqual(api(client, "GET", path).status_code, 200, path)
            self.assertEqual(client.post("/api/sessions/x/forget").status_code, 401)

    def test_gui_static_and_v1_need_no_token(self):
        with gateway() as (app, client, fakes):
            self.assertEqual(client.get("/").status_code, 200)
            self.assertEqual(client.get("/static/app.js").status_code, 200)
            self.assertEqual(client.post("/v1/chat/completions", json=chat("x")).status_code, 200)

    def test_token_is_random_per_start(self):
        from masqai.app import create_app
        a, b = create_app(GatewayConfig()), create_app(GatewayConfig())
        self.assertNotEqual(a.state.admin_token, b.state.admin_token)
        self.assertGreaterEqual(len(a.state.admin_token), 43)   # 256 bits, urlsafe base64


class Boundary(unittest.TestCase):
    def test_host_header_must_be_loopback_with_port(self):
        with gateway() as (app, client, fakes):
            self.assertEqual(client.get("/", headers={"host": f"localhost:{PORT}"}).status_code, 200)
            for host in ("testserver", "localhost", "127.0.0.1", f"evil.test:{PORT}", f"127.0.0.1:{PORT + 1}"):
                self.assertEqual(client.get("/", headers={"host": host}).status_code, 403, host)

    def test_cross_site_and_cross_origin_refused(self):
        with gateway() as (app, client, fakes):
            self.assertEqual(client.post("/v1/chat/completions", json=chat("x"), headers={"sec-fetch-site": "cross-site"}).status_code, 403)
            self.assertEqual(api(client, "GET", "/api/state", headers={"sec-fetch-site": "same-site"}).status_code, 403)
            self.assertEqual(api(client, "GET", "/api/state", headers={"origin": "http://localhost:3000"}).status_code, 403)
            self.assertEqual(api(client, "GET", "/api/state", headers={"sec-fetch-site": "same-origin"}).status_code, 200)
            self.assertEqual(fakes.upstream_calls, [])

    def test_csp_and_upstream_cookies(self):
        with gateway() as (app, client, fakes):
            self.assertIn("default-src 'self'", client.get("/").headers["content-security-policy"])
            fakes.upstream = lambda r: httpx.Response(200, headers={"set-cookie": "a=b", "content-security-policy": "none"},
                                                      json={"choices": []})
            r = client.post("/v1/chat/completions", json=chat("x"))
            self.assertTrue(r.headers["content-security-policy"].startswith("sandbox"))
            self.assertEqual(r.headers["x-content-type-options"], "nosniff")
            self.assertEqual(r.headers["x-frame-options"], "DENY")
            self.assertNotIn("set-cookie", r.headers)

    def test_non_object_json_is_400(self):
        with gateway() as (app, client, fakes):
            for body in ("[1, 2]", '"text"', "not json"):
                r = client.post("/v1/chat/completions", content=body, headers={"content-type": "application/json"})
                self.assertEqual(r.status_code, 400, body)
            self.assertEqual(fakes.upstream_calls, [])

    def test_errors_never_echo_exception_text(self):
        with gateway() as (app, client, fakes):
            def boom(request):
                raise RuntimeError("upstream exploded with alice@example.invalid.com")
            fakes.upstream = boom
            r = client.post("/v1/chat/completions", json=chat("x"))
            self.assertEqual(r.status_code, 500)
            self.assertNotIn("exploded", r.text)
            self.assertNotIn("alice", r.text)


class Limits(unittest.TestCase):
    def test_frame_and_argument_caps(self):
        with patch("masqai.streaming.MAX_FRAME_BYTES", 100):
            with self.assertRaises(StreamLimitError):
                SSETransformer({}).feed(b"data: " + b"x" * 200)
        with patch("masqai.restore.MAX_ARGUMENT_CHARS", 10):
            stream = ArgumentStream({}, True)
            with self.assertRaises(StreamLimitError):
                stream.feed("a" * 11)

    def test_invalid_utf8_frame_forwarded_unchanged(self):
        frame = b"data: \xff\xfe\n\n"
        self.assertEqual(SSETransformer({}).feed(frame), [frame])

    async def _read(self, response, limit):
        return await read_limited(response, limit)

    def test_response_size_cap(self):
        import asyncio
        response = httpx.Response(200, content=b"x" * 50)
        with self.assertRaises(ResponseTooLarge):
            asyncio.run(self._read(response, 10))


class FrozenEnv(unittest.TestCase):
    def test_env_names_frozen_at_startup(self):
        with gateway() as (app, client, fakes):
            self.assertEqual(api(client, "GET", "/api/env/HOME").status_code, 404)
            with patch.dict(os.environ, {"FAKE_UPSTREAM_KEY": "sk-or-v1-FAKEFAKEFAKEFAKEFAKEFAKE"}):
                r = api(client, "GET", "/api/env/FAKE_UPSTREAM_KEY")
            self.assertEqual(r.json(), {"name": "FAKE_UPSTREAM_KEY", "set": True})
            self.assertNotIn("FAKEFAKE", r.text)
            config = api(client, "GET", "/api/config").json()
            config["providers"][0]["api_key_env"] = "SOME_NEW_VAR"
            r = api(client, "POST", "/api/config", json=config)
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.json()["errors"][0]["loc"], ["providers", 0, "api_key_env"])
            config["providers"][0]["api_key_env"] = "FAKE_UPSTREAM_KEY"
            self.assertEqual(api(client, "POST", "/api/config", json=config).status_code, 200)


class ConfigApi(unittest.TestCase):
    def test_round_trip_and_field_errors(self):
        with gateway() as (app, client, fakes):
            config = api(client, "GET", "/api/config").json()
            self.assertEqual(api(client, "POST", "/api/config", json=config).json(), config)
            config["security"]["recent_items"] = -1
            r = api(client, "POST", "/api/config", json=config)
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.json()["errors"][0]["loc"], ["security", "recent_items"])
            config["security"]["recent_items"] = 3
            config["port"] = 9999
            self.assertEqual(api(client, "POST", "/api/config", json=config).json()["errors"][0]["loc"], ["port"])

    def test_literal_keys_and_credential_headers_rejected(self):
        with self.assertRaises(Exception):
            ProviderConfig(name="x", base_url="https://x.test", api_key="sk-or-v1-FAKEFAKE")
        with self.assertRaises(Exception):
            ProviderConfig(name="x", base_url="https://x.test", headers={"Authorization": "Bearer x"})

    def test_example_config_is_valid(self):
        config = load_config("masqai.json.example")
        self.assertFalse(config.security.allow_remote_security_model)

    def test_meta_lists_rules_and_prompt(self):
        with gateway() as (app, client, fakes):
            meta = api(client, "GET", "/api/config/meta").json()
            self.assertIn("pem_private_key", meta["detector_rules"])
            self.assertIn("Output JSON only.", meta["default_security_prompt"])
            self.assertEqual(meta["env_names"], ["FAKE_UPSTREAM_KEY"])


class Secrets(unittest.TestCase):
    def test_whole_private_key_never_reaches_upstream(self):
        with gateway() as (app, client, fakes):
            client.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "tool", "tool_call_id": "1", "content": f"cat key\n{PEM}\ndone"}]})
            sent = json.dumps(fakes.upstream_json())
            for line in PEM.splitlines():
                self.assertNotIn(line, sent)

    def test_security_trace_records_input_and_answer(self):
        with gateway(make_config(security=True)) as (app, client, fakes):
            fakes.security_answers = [[{"op": "mask", "item": "#1", "line": 1, "text": "Dana", "type": "USER", "reason": "a name"}]]
            client.post("/v1/chat/completions", json=chat("hi Dana"))
            [trace] = api(client, "GET", "/api/security").json()["traces"]
            self.assertEqual(trace["status"], "passed")
            self.assertEqual(trace["security"]["input"]["new_items"][0]["lines"][0]["raw"], "hi Dana")
            self.assertTrue(trace["security"]["attempts"][0]["raw_output"])


if __name__ == "__main__":
    unittest.main()
