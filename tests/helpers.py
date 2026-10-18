"""Shared fixtures: a fake upstream and a fake security model behind one mock transport. Synthetic values only."""
from __future__ import annotations

import contextlib
import hashlib
import json
import re
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
def gateway(config: GatewayConfig | None = None, *, playground: bool = False, frozen_env: set[str] | None = None, keyring=None):
    fakes = Fakes()
    app = create_app(config or make_config(), admin_token=TOKEN, playground=playground, frozen_env=frozen_env, keyring=keyring)
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


# --- Key Enigma: a fake OpenRouter key-management API and a fake ManagementBackend -------------------------------

FAKE_MGMT_KEY = "sk-or-v1-FAKEFAKEFAKEFAKEFAKEFAKEmanagement"
FAKE_WORKSPACE = "0df9e665-d932-5740-b2c7-b52af166bc11"
FAKE_INSTANCE = "3f9a1c07"


class FakeOpenRouter:
    """OpenRouter's /api/v1/keys, /api/v1/key and workspace endpoints, in memory, behind an httpx.MockTransport.

    Keys are FAKE-marked. `fail` maps (method, path-prefix) to a list of status codes popped one per matching call,
    so tests can script failures. `revoke_delay` keeps a deleted key answering 200 for that many probes
    (propagation delay). Every request is recorded in `calls`.
    """

    def __init__(self, *, management_key: str = FAKE_MGMT_KEY, budgets: int = 1) -> None:
        self.management_key = management_key
        self.keys: dict[str, dict[str, Any]] = {}        # hash -> record (with the plaintext under "_key")
        self.calls: list[httpx.Request] = []
        self.fail: dict[tuple[str, str], list[int]] = {}
        self.revoke_delay = 0
        self.budgets = [{"id": "b0", "workspace_id": FAKE_WORKSPACE, "limit_usd": 20.0, "reset_interval": "monthly",
                         "created_at": "2026-10-01T00:00:00Z", "updated_at": None}][:budgets]
        self.workspaces = {FAKE_WORKSPACE}
        self.page_size = 100
        self.mangle_create: Callable[[dict[str, Any]], None] | None = None   # edits the created record (tests)
        self._seq = 0
        self._ghosts: dict[str, int] = {}                # deleted key value -> probes still answered 200

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def add_key(self, name: str, *, workspace_id: str = FAKE_WORKSPACE, disabled: bool = False) -> str:
        self._seq += 1
        key_hash = f"{self._seq:064x}"
        self.keys[key_hash] = {"hash": key_hash, "name": name, "label": name, "disabled": disabled, "limit": 1.0,
                               "limit_remaining": 1.0, "usage": 0.0, "expires_at": None, "workspace_id": workspace_id,
                               "_key": f"sk-or-v1-FAKEFAKEFAKE{self._seq:020d}"}
        return key_hash

    def _scripted(self, method: str, path: str) -> int | None:
        for (m, prefix), codes in self.fail.items():
            if m == method and path.startswith(prefix) and codes:
                return codes.pop(0)
        return None

    @staticmethod
    def _public(record: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in record.items() if not k.startswith("_")}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        method, path = request.method, request.url.path
        if request.url.host != "openrouter.ai" or not path.startswith("/api/v1/"):
            return httpx.Response(404, json={"error": {"code": 404, "message": "not found"}})
        path = path[len("/api/v1"):]
        code = self._scripted(method, path)
        if code is not None:
            headers = {"retry-after": "1"} if code == 429 else {}
            return httpx.Response(code, headers=headers, json={"error": {"code": code, "message": "scripted"}})
        bearer = request.headers.get("authorization", "").removeprefix("Bearer ")
        if path == "/key" and method == "GET":
            return self._whoami(bearer)
        if bearer != self.management_key:
            if any(r["_key"] == bearer for r in self.keys.values()):
                return httpx.Response(403, json={"error": {"code": 403, "message": "Only management keys can perform this operation"}})
            return httpx.Response(401, json={"error": {"code": 401, "message": "User not found."}})
        if path == "/keys" and method == "POST":
            return self._create(json.loads(request.content))
        if path == "/keys" and method == "GET":
            workspace = request.url.params.get("workspace_id", "default")
            offset = int(request.url.params.get("offset", "0"))
            include_disabled = request.url.params.get("include_disabled") == "true"
            rows = [self._public(r) for r in self.keys.values()
                    if r["workspace_id"] == workspace and (include_disabled or not r["disabled"])]
            return httpx.Response(200, json={"data": rows[offset:offset + self.page_size]})
        if path.startswith("/keys/"):
            record = self.keys.get(path[len("/keys/"):])
            if record is None:
                return httpx.Response(404, json={"error": {"code": 404, "message": "API key not found"}})
            if method == "GET":
                return httpx.Response(200, json={"data": self._public(record)})
            if method == "PATCH":
                record.update({k: v for k, v in json.loads(request.content).items() if k in {"disabled", "name", "limit"}})
                return httpx.Response(200, json={"data": self._public(record)})
            if method == "DELETE":
                del self.keys[record["hash"]]
                if self.revoke_delay:
                    self._ghosts[record["_key"]] = self.revoke_delay
                return httpx.Response(200, json={"deleted": True})
        if path.startswith("/workspaces/"):
            rest = path[len("/workspaces/"):]
            workspace, _, tail = rest.partition("/")
            if workspace not in self.workspaces:
                return httpx.Response(404, json={"error": {"code": 404, "message": "workspace not found"}})
            if tail == "budgets":
                return httpx.Response(200, json={"data": self.budgets})
            return httpx.Response(200, json={"data": {"id": workspace, "name": "masqai-enigma", "slug": "masqai-enigma"}})
        return httpx.Response(405, json={"error": {"code": 405, "message": "method not allowed"}})

    def _whoami(self, bearer: str) -> httpx.Response:
        if bearer == self.management_key:
            return httpx.Response(200, json={"data": {"label": "mgmt", "is_management_key": True, "expires_at": "2026-12-31T00:00:00Z"}})
        if bearer in self._ghosts:
            self._ghosts[bearer] -= 1
            if self._ghosts[bearer] <= 0:
                del self._ghosts[bearer]
            return httpx.Response(200, json={"data": {"label": "ghost", "is_management_key": False}})
        for record in self.keys.values():
            if record["_key"] == bearer and not record["disabled"]:
                return httpx.Response(200, json={"data": {"label": record["label"], "is_management_key": False,
                                                          "limit": record["limit"], "usage": record["usage"]}})
        return httpx.Response(401, json={"error": {"code": 401, "message": "User not found."}})

    def _create(self, body: dict[str, Any]) -> httpx.Response:
        expires = body.get("expires_at")
        if expires is not None and not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", expires):
            return httpx.Response(400, json={"error": {"code": 400, "message": "expires_at must include seconds"}})
        if not body.get("name"):
            return httpx.Response(400, json={"error": {"code": 400, "message": "name is required"}})
        key_hash = self.add_key(body["name"], workspace_id=body.get("workspace_id") or "default")
        record = self.keys[key_hash]
        record.update({"limit": body.get("limit"), "limit_remaining": body.get("limit"), "expires_at": expires})
        if self.mangle_create:
            self.mangle_create(record)
        return httpx.Response(201, json={"data": self._public(record), "key": record["_key"]})


class FakeBackend:
    """An in-memory ManagementBackend for rotation tests (build step 3 onward). No HTTP at all."""

    mode = "fake"

    def __init__(self, instance_id: str = FAKE_INSTANCE) -> None:
        from masqai.custody import BackendStatus, MintedKey
        self._status, self._minted = BackendStatus, MintedKey
        self.prefix = f"masqai-enigma-{instance_id}-"
        self.live: dict[str, Any] = {}          # hash -> MintedKey
        self.revoked: list[str] = []
        self.spend: dict[str, float] = {}
        self.leftovers: list[str] = []          # hashes cleanup() should report as removed
        self.mint_errors: list[Exception] = []  # popped one per mint
        self.healthy = True
        self.detail = ""
        self.management_expires_at = None
        self.closed = False
        self._seq = 0

    async def mint(self, *, suffix: str, expires_at, limit_usd: float):
        if self.mint_errors:
            raise self.mint_errors.pop(0)
        self._seq += 1
        key_hash = hashlib.sha256(f"fake-backend-{self._seq}".encode()).hexdigest()
        minted = self._minted(key=f"sk-or-v1-FAKEFAKEFAKE{self._seq:020d}", hash=key_hash, name=self.prefix + suffix,
                              expires_at=expires_at.replace(microsecond=0), limit_usd=limit_usd)
        self.live[key_hash] = minted
        return minted

    async def revoke(self, key_hash: str):
        if self.live.pop(key_hash, None) is None:
            return "already_gone"
        self.revoked.append(key_hash)
        return "deleted"

    async def usage(self, key_hash: str) -> float:
        return self.spend.get(key_hash, 0.0)

    async def cleanup(self) -> int:
        count, self.leftovers = len(self.leftovers), []
        return count

    async def status(self):
        return self._status(mode=self.mode, healthy=self.healthy, detail=self.detail,
                            management_expires_at=self.management_expires_at)

    async def aclose(self) -> None:
        self.closed = True
