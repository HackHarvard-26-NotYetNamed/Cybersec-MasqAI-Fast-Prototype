"""Security page traces: what the security model is given, what it answers, and the decision."""
import json
import unittest
from unittest.mock import patch

import httpx

from masqai.app import create_app
from masqai.config import DetectorConfig, GatewayConfig, ModelRoute, ProviderConfig, SecurityModelConfig

REAL_CLIENT = httpx.AsyncClient


def config(enabled=True):
    return GatewayConfig(
        providers=[ProviderConfig(name="up", base_url="http://upstream"), ProviderConfig(name="sec", base_url="http://127.0.0.1:1")],
        default_route=ModelRoute(provider="up"),
        security=SecurityModelConfig(enabled=enabled, provider="sec", model="guard"),
        detectors=DetectorConfig(detect_host_identifiers=False))


def security_model(answer):
    """Patch the security call with a fake model returning `answer` (dict or raw text)."""
    content = answer if isinstance(answer, str) else json.dumps(answer)

    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}], "usage": {"prompt_tokens": 10, "completion_tokens": 3}})
    return fake_security(handler)


def fake_security(handler):
    # masqai.sanitize.httpx is the shared httpx module: patch only while the request runs.
    return patch("masqai.sanitize.httpx.AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))


async def upstream(provider, path, body, headers, timeout, policy=None):
    upstream.body = body
    return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]}, headers={"content-type": "application/json"})


class Traces(unittest.IsolatedAsyncioTestCase):
    async def run_request(self, cfg, content, answer=None, security=None):
        app = create_app(cfg)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            with patch("masqai.app.upstream_request", upstream):
                fake = security or (security_model(answer) if answer is not None else None)
                body = {"model": "m", "messages": [{"role": "user", "content": content}]}
                if fake is None:
                    response = await client.post("/v1/chat/completions", json=body)
                else:
                    with fake:
                        response = await client.post("/v1/chat/completions", json=body)
            traces = (await client.get("/api/security")).json()["traces"]
            state = (await client.get("/api/state")).json()
        self.assertEqual(state["traces"], traces)
        return response, traces

    async def test_passed_trace_records_input_output_and_effect(self):
        answer = {"operations": [{"op": "mask", "item": "#1", "line": 1, "text": "Hollowbrook", "type": "CLIENT"}]}
        response, traces = await self.run_request(config(), "mail a@example.com about Hollowbrook", answer)
        self.assertEqual(response.status_code, 200)
        [t] = traces
        self.assertEqual(t["status"], "passed")
        self.assertEqual([e["type"] for e in t["detectors"]["found"]], ["EMAIL"])
        self.assertEqual(t["detectors"]["found"][0]["source"], "pattern")
        sec = t["security"]
        self.assertEqual(sec["model"], "guard")
        # The exact input the model was given: the new item with numbered raw lines, what is already masked, the mapping.
        [new] = sec["input"]["new_items"]
        self.assertEqual(new["lines"], [{"n": 1, "raw": "mail a@example.com about Hollowbrook"}])
        self.assertEqual(new["masked"][0]["text"], "a@example.com")
        self.assertEqual(sec["input"]["mapping"][0]["value"], "a@example.com")
        self.assertIn("MasqAI", sec["system_prompt"])
        [attempt] = sec["attempts"]
        self.assertEqual(json.loads(attempt["raw_output"]), answer)
        self.assertEqual(attempt["usage"]["prompt_tokens"], 10)
        self.assertTrue(attempt["results"][0]["ok"])
        self.assertTrue(t["validation"]["ok"])
        self.assertEqual([e["canonical"] for e in t["applied"]["new_entities"]], ["Hollowbrook"])
        self.assertEqual(len(t["applied"]["changed_items"]), 1)
        self.assertNotIn("Hollowbrook", json.dumps(upstream.body))

    async def test_rejected_operation_is_retried_once_then_blocks(self):
        answer = {"operations": [{"op": "mask", "item": "#1", "line": 1, "text": "not in the context", "type": "SECRET"}]}
        response, [t] = await self.run_request(config(), "hello", answer)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(t["status"], "blocked")
        self.assertEqual(len(t["security"]["attempts"]), 2)
        self.assertIn("does not contain", t["security"]["attempts"][1]["correction"])
        self.assertFalse(t["validation"]["ok"])
        self.assertIn("not in the context", t["security"]["attempts"][0]["raw_output"])

    async def test_correction_accepted(self):
        answers = iter([
            {"operations": [{"op": "mask", "item": "#1", "line": 2, "text": "Hollowbrook", "type": "CLIENT"}]},
            {"operations": [{"op": "mask", "item": "#1", "line": 1, "text": "Hollowbrook", "type": "CLIENT"}]},
        ])

        def handler(request):
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(next(answers))}}]})
        response, [t] = await self.run_request(config(), "about Hollowbrook", security=fake_security(handler))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(t["status"], "passed")
        self.assertTrue(t["validation"]["corrected"])
        self.assertNotIn("Hollowbrook", json.dumps(upstream.body))

    async def test_invalid_json_is_blocked_with_raw_output(self):
        response, [t] = await self.run_request(config(), "hello", "I think this is fine!")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(t["status"], "blocked")
        self.assertEqual(t["security"]["attempts"][0]["raw_output"], "I think this is fine!")
        self.assertFalse(t["validation"]["ok"])

    async def test_unreachable_model_blocks_without_output(self):
        def refuse(request):
            raise httpx.ConnectError("refused")
        response, [t] = await self.run_request(config(), "hello", security=fake_security(refuse))
        self.assertEqual(response.status_code, 502)
        self.assertEqual(t["status"], "blocked")
        self.assertNotIn("raw_output", t["security"]["attempts"][0])
        self.assertIn("refused", t["error"])

    async def test_disabled_model_is_skipped(self):
        response, [t] = await self.run_request(config(enabled=False), "mail a@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(t["status"], "skipped")
        self.assertIsNone(t["security"])
        self.assertEqual(len(t["detectors"]["found"]), 1)

    def test_trace_log_keeps_only_recent_and_notifies(self):
        from masqai.trace import TraceLog
        log = TraceLog(limit=2)
        seen = []
        for _ in range(3):
            trace = log.start("s", "/v1/x", lambda t: seen.append(t.as_dict()["status"]))
            trace.finish("skipped")
        self.assertEqual(len(log.as_list()), 2)
        self.assertEqual(seen, ["skipped"] * 3)


if __name__ == "__main__":
    unittest.main()
