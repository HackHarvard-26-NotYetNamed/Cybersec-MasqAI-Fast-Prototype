"""Shared fixtures: a fake upstream and a fake security model behind one mock transport. Synthetic values only."""
from __future__ import annotations

import contextlib
import json
from typing import Any, Callable
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from masqai.app import create_app
from masqai.config import DetectorConfig, GatewayConfig, ModelRoute, ProviderConfig, SecurityModelConfig

REAL_ASYNC_CLIENT = httpx.AsyncClient
UPSTREAM = "http://upstream.test"
SECURITY = "http://127.0.0.1:11434"
TOKEN = "test-admin-token"
PORT = 8787


def make_config(*, security: bool = False, security_url: str = SECURITY, **overrides: Any) -> GatewayConfig:
    providers = [ProviderConfig(name="up", base_url=UPSTREAM, api_key_env="FAKE_UPSTREAM_KEY"),
                 ProviderConfig(name="sec", base_url=security_url)]
    data: dict[str, Any] = {
        "providers": providers,
        "default_route": ModelRoute(provider="up"),
        "security": SecurityModelConfig(enabled=security, provider="sec", model="fake-security", timeout_s=5),
        "detectors": DetectorConfig(detect_host_identifiers=False),
    }
    data.update(overrides)
    return GatewayConfig(**data)


class Fakes:
    """Records upstream and security-model calls; answers with configurable handlers."""

    def __init__(self) -> None:
        self.upstream_calls: list[httpx.Request] = []
        self.security_calls: list[dict[str, Any]] = []
        self.upstream: Callable[[httpx.Request], httpx.Response] = lambda r: httpx.Response(
            200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]})
        # Each call pops the next answer: a list of operations, a raw string, an httpx.Response, or a
        # function of the security model's input returning one of those.
        self.security_answers: list[Any] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(SECURITY) or "security" in request.url.host:
            body = json.loads(request.content)
            self.security_calls.append(body)
            answer = self.security_answers.pop(0) if self.security_answers else []
            if callable(answer):   # a function of the security model's input (the user message JSON)
                answer = answer(json.loads(body["messages"][-1]["content"]))
            if isinstance(answer, httpx.Response):
                return answer
            if isinstance(answer, dict) and "decision" in answer:
                content = json.dumps(answer)
            else:
                content = answer if isinstance(answer, str) else json.dumps({"operations": answer})
            return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": content}}]})
        self.upstream_calls.append(request)
        return self.upstream(request)

    def upstream_json(self, index: int = -1) -> dict[str, Any]:
        return json.loads(self.upstream_calls[index].content)


@contextlib.contextmanager
def gateway(config: GatewayConfig | None = None, *, playground: bool = False, frozen_env: set[str] | None = None):
    fakes = Fakes()
    app = create_app(config or make_config(), admin_token=TOKEN, playground=playground, frozen_env=frozen_env)
    factory = lambda **kw: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(fakes.handler), **{k: v for k, v in kw.items() if k != "transport"})
    with patch("httpx.AsyncClient", factory):
        client = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
        yield app, client, fakes


def api(client: TestClient, method: str, path: str, **kwargs: Any) -> httpx.Response:
    headers = {"x-masqai-token": TOKEN, **kwargs.pop("headers", {})}
    return client.request(method, path, headers=headers, **kwargs)


def sse(*events: dict[str, Any], named: bool = False) -> bytes:
    out = b""
    for event in events:
        head = f"event: {event['type']}\n" if named and "type" in event else ""
        out += (head + "data: " + json.dumps(event) + "\n\n").encode()
    return out


def sse_payloads(body: bytes) -> list[dict[str, Any]]:
    return [json.loads(line[6:]) for line in body.splitlines() if line.startswith(b"data: ") and line != b"data: [DONE]"]
