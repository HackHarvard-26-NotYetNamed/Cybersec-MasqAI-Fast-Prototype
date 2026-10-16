import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from masqai.adapter import extract, serialize, restore_tool_arguments
from masqai.app import create_app
from masqai.config import GatewayConfig, ProviderConfig, ModelRoute, SecurityModelConfig, DetectorConfig
from masqai.model import ContextItem, Session
from masqai.sanitize import Sanitizer, SanitizationError
from masqai.session import SessionStore
from masqai.streaming import SSETransformer


def config():
    return GatewayConfig(providers=[ProviderConfig(name="test", base_url="http://fake")], default_route=ModelRoute(provider="test"), security=SecurityModelConfig(enabled=False), detectors=DetectorConfig(detect_host_identifiers=False))


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_content_lenses_preserve_protocol_and_reasoning(self):
        payload = {"model":"test", "messages":[{"role":"assistant", "content":[{"type":"thinking","thinking":"a@example.com","signature":"opaque"},{"type":"text","text":"a@example.com","cache_control":{"type":"ephemeral"}}],"extra":"kept"}], "tools":[{"name":"a@example.com","description":"mail a@example.com","input_schema":{"type":"object"}}], "unknown":{"abc":3}}
        items = extract(payload, "anthropic")
        session = Session("s")
        await Sanitizer(config()).sanitize(session, items)
        out = serialize(payload, items)
        self.assertEqual(out["messages"][0]["content"][0], payload["messages"][0]["content"][0])
        self.assertNotEqual(out["messages"][0]["content"][1]["text"], "a@example.com")
        self.assertEqual(out["messages"][0]["content"][1]["cache_control"], {"type":"ephemeral"})
        self.assertEqual(out["tools"][0]["name"], "a@example.com")
        self.assertEqual(out["unknown"], payload["unknown"])

    async def test_json_argument_restore_preserves_windows_paths(self):
        entities=[{"token":"<PATH_abcd1234>","canonical":'C:\\Users\\a"b'}]
        raw={"choices":[{"message":{"content":"<PATH_abcd1234>","tool_calls":[{"function":{"arguments":'{"path":"<PATH_abcd1234>"}'}}]}}]}
        out=restore_tool_arguments(raw, entities, "openai")
        self.assertEqual(json.loads(out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])["path"], entities[0]["canonical"])
        self.assertEqual(out["choices"][0]["message"]["content"], "<PATH_abcd1234>")

    async def test_stream_split_arguments_and_text_preservation(self):
        entity={"token":"<PATH_abcd1234>","canonical":"C:\\Users\\alice"}
        chunks=[{"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":None}]}, {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":'{"path":"<PATH_ab'}}]},"finish_reason":None}]}, {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":'cd1234>"}'}}]},"finish_reason":None}]}, {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}]
        wire=b"".join(b"data: "+json.dumps(c).encode()+b"\n\n" for c in chunks)+b"data: [DONE]\n\n"
        tr=SSETransformer([entity]); result=[]
        for offset in range(0,len(wire),7): result.extend(tr.feed(wire[offset:offset+7]))
        result.append(tr.finish())
        self.assertEqual(result[0], b"data: "+json.dumps(chunks[0]).encode()+b"\n\n")
        payloads=[json.loads(line[6:]) for line in b"".join(result).splitlines() if line.startswith(b"data: ") and line!=b"data: [DONE]"]
        arguments="".join(call["function"].get("arguments","") for p in payloads for c in p.get("choices",[]) for call in c.get("delta",{}).get("tool_calls",[]))
        self.assertEqual(json.loads(arguments)["path"], entity["canonical"])

    async def test_rephrase_anchors_checked(self):
        from masqai.ops import Applier, plan_all
        session = Session("s")
        items = extract({"messages": [{"role": "tool", "tool_call_id": "1", "content": "a\nb\nc"}]}, "openai")
        [bad, good] = Applier(session, items, False, 1).apply([
            {"op": "collapse", "item": "#1", "start": 1, "end": 2, "first": "wrong", "last": "b", "summary": "s"},
            {"op": "collapse", "item": "#1", "start": 2, "end": 2, "first": "b", "last": "b", "summary": "omitted"}])
        self.assertFalse(bad["ok"])
        self.assertTrue(good["ok"])
        plan_all(session, items)
        self.assertEqual(items[0].sanitized, "a\n…[MASQ_BLOCK: omitted]…\nc")

    async def test_full_proxy_sanitizes_and_preserves_unknown_fields(self):
        captured={}
        async def upstream(provider,path,body,headers,timeout,policy=None):
            captured.update(body)
            return httpx.Response(200, content=b'{"choices":[{"message":{"content":"exact text"}}],"custom":42}', headers={"content-type":"application/json","x-extra":"yes"})
        app=create_app(config())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://localhost") as client:
            with patch("masqai.app.upstream_request",upstream):
                result=await client.post("/v1/chat/completions",json={"model":"test","messages":[{"role":"user","content":"email a@example.com"}],"custom":42})
            self.assertEqual(result.status_code,200)
            self.assertNotIn("a@example.com",str(captured))
            self.assertEqual(captured["custom"],42)
            self.assertEqual(result.headers["x-extra"],"yes")
            self.assertEqual(result.content,b'{"choices":[{"message":{"content":"exact text"}}],"custom":42}')

    async def test_fail_closed_never_calls_upstream(self):
        c=config(); c.security.enabled=True
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(c)),base_url="http://localhost") as client:
            with patch("masqai.app.upstream_request",new_callable=AsyncMock) as upstream:
                result=await client.post("/v1/chat/completions",json={"model":"test","messages":[{"role":"user","content":"hello"}]})
                self.assertEqual(result.status_code,502)
                upstream.assert_not_called()

    async def test_session_prefix_and_hints(self):
        store=SessionStore(); first={"messages":[{"role":"user","content":"a"}]}
        a=store.resolve(first,{});store.remember(a,first)
        second={"messages":first["messages"]+[{"role":"assistant","content":"b"},{"role":"user","content":"c"}]}
        self.assertIs(store.resolve(second,{}),a)
        hinted=store.resolve(first,{"x-session-id":"unique"})
        self.assertIs(store.resolve({"messages":[]},{"x-session-id":"unique"}),hinted)


if __name__=="__main__": unittest.main()
