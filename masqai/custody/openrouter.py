"""OpenRouter key management over HTTPS from the host (design: KeyEnigma.OpenRouter.doc.md §2, §3.3, §4, §6).

`OpenRouterKeys` is a thin client for the management endpoints. It holds the management key, so it is fenced in:
- its own `httpx.AsyncClient`, never shared with inference traffic;
- the origin is fixed to https://openrouter.ai, and only the management paths below can be requested;
- redirects are not followed, and `trust_env=False` (no proxy, netrc or CA-bundle settings from the environment);
- key hashes and workspace ids are validated before they are put in a URL;
- error messages are truncated and have anything key-shaped removed.

`probe_key` checks an *inference* key with a separate client. `DirectBackend` implements `ManagementBackend` on top of
`OpenRouterKeys`; the passphrase backend (build step 6) is "unseal the vault, then DirectBackend".
"""
from __future__ import annotations

import asyncio
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import httpx

from . import (BackendStatus, BackendUnavailable, CustodyError, KeyNotFound, ManagementAuthError, MintedKey,
               RateLimited, RevokeOutcome, WorkspaceUnbudgeted)

ORIGIN = "https://openrouter.ai"
API = ORIGIN + "/api/v1"
NAME_PREFIX = "masqai-enigma-"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_LIST_PAGES = 200          # 200 pages x 100 keys: far beyond any real account; stops a server that never ends a list

HASH_RE = re.compile(r"[0-9a-f]{64}")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
INSTANCE_RE = re.compile(r"[0-9a-f]{8}")
SUFFIX_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
# The only requests the management client may make: (method, path below /api/v1).
ALLOWED = [
    ("GET", re.compile(r"/key")),
    ("GET", re.compile(r"/keys")),
    ("POST", re.compile(r"/keys")),
    ("GET", re.compile(r"/keys/[0-9a-f]{64}")),
    ("PATCH", re.compile(r"/keys/[0-9a-f]{64}")),
    ("DELETE", re.compile(r"/keys/[0-9a-f]{64}")),
    ("GET", re.compile(r"/workspaces/[0-9a-f-]{36}")),
    ("GET", re.compile(r"/workspaces/[0-9a-f-]{36}/budgets")),
]
_KEYISH = re.compile(r"sk-[A-Za-z0-9_-]{8,}")


def format_expiry(when: datetime) -> str:
    """ISO 8601 UTC with seconds, as OpenRouter requires (minute precision is rejected)."""
    if when.tzinfo is None:
        raise ValueError("expires_at must be timezone-aware")
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def check_hash(key_hash: str) -> str:
    if not isinstance(key_hash, str) or not HASH_RE.fullmatch(key_hash):
        raise CustodyError("refusing a malformed key hash")
    return key_hash


def check_workspace(workspace_id: str) -> str:
    if not isinstance(workspace_id, str) or not UUID_RE.fullmatch(workspace_id):
        raise CustodyError("workspace_id must be a lowercase UUID")
    return workspace_id


def _error_text(response: httpx.Response, body: Any) -> str:
    message = ""
    if isinstance(body, dict):
        error = body.get("error")
        message = error.get("message", "") if isinstance(error, dict) else str(error or "")
    message = _KEYISH.sub("<redacted>", str(message))[:200]
    return f"OpenRouter {response.request.method} {response.request.url.path} -> {response.status_code}" + (f": {message}" if message else "")


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after", "")
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


class OpenRouterKeys:
    """Create, list, get, update and delete API keys with a management key. One instance per gateway."""

    def __init__(self, management_key: str, *, timeout: float = 20.0, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not management_key or not isinstance(management_key, str):
            raise CustodyError("no management key")
        self._key = management_key
        self._timeout = timeout
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    def __repr__(self) -> str:
        return "OpenRouterKeys(<management key hidden>)"

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            kwargs: dict[str, Any] = {"timeout": self._timeout, "follow_redirects": False, "trust_env": False}
            if self._transport is not None:
                kwargs["transport"] = self._transport
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            client, self._client = self._client, None
            await client.aclose()

    async def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None) -> Any:
        if not any(m == method and rx.fullmatch(path) for m, rx in ALLOWED):
            raise CustodyError(f"management client refuses {method} {path}")
        headers = {"authorization": f"Bearer {self._key}", "accept": "application/json"}
        try:
            async with self._http().stream(method, API + path, params=params, json=body, headers=headers) as response:
                declared = response.headers.get("content-length", "")
                if declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                    raise BackendUnavailable("OpenRouter management response too large")
                raw = b""
                async for chunk in response.aiter_bytes():
                    raw += chunk
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise BackendUnavailable("OpenRouter management response too large")
        except httpx.HTTPError as exc:
            raise BackendUnavailable(f"OpenRouter {method} {path}: {type(exc).__name__}") from None
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        status = response.status_code
        if 200 <= status < 300:
            if parsed is None and method != "DELETE":
                raise BackendUnavailable(f"OpenRouter {method} {path}: response is not JSON")
            return parsed
        text = _error_text(response, parsed)
        if status in (401, 403):
            raise ManagementAuthError(text)
        if status == 404:
            raise KeyNotFound(text)
        if status == 429:
            raise RateLimited(text, _retry_after(response))
        if status >= 500 or 300 <= status < 400:
            raise BackendUnavailable(text)
        raise CustodyError(text)

    @staticmethod
    def _data(payload: Any) -> Any:
        if not isinstance(payload, dict) or "data" not in payload:
            raise BackendUnavailable("OpenRouter response has no data")
        return payload["data"]

    async def current(self) -> dict[str, Any]:
        """GET /key with the management key: is it a management key, and when does it expire?"""
        data = self._data(await self._call("GET", "/key"))
        return data if isinstance(data, dict) else {}

    async def create(self, *, name: str, workspace_id: str, limit_usd: float, expires_at: datetime) -> dict[str, Any]:
        body = {"name": name, "workspace_id": check_workspace(workspace_id), "limit": limit_usd, "limit_reset": None,
                "include_byok_in_limit": True, "expires_at": format_expiry(expires_at)}
        payload = await self._call("POST", "/keys", body=body)
        if not isinstance(payload, dict) or not isinstance(payload.get("key"), str) or not isinstance(payload.get("data"), dict):
            raise BackendUnavailable("OpenRouter create response is missing the key or its data")
        return payload

    async def list(self, *, workspace_id: str, include_disabled: bool = True) -> list[dict[str, Any]]:
        """Every key in the workspace. Without workspace_id OpenRouter lists only the default workspace."""
        params: dict[str, Any] = {"workspace_id": check_workspace(workspace_id), "include_disabled": str(include_disabled).lower()}
        keys: list[dict[str, Any]] = []
        seen: set[str] = set()
        for _ in range(MAX_LIST_PAGES):
            page = self._data(await self._call("GET", "/keys", params={**params, "offset": len(keys)}))
            if not isinstance(page, list):
                raise BackendUnavailable("OpenRouter key list is not a list")
            fresh = [k for k in page if isinstance(k, dict) and k.get("hash") not in seen]
            if not fresh:
                return keys
            seen.update(k.get("hash") for k in fresh)
            keys.extend(fresh)
        raise BackendUnavailable("OpenRouter key list did not end")

    async def get(self, key_hash: str) -> dict[str, Any]:
        data = self._data(await self._call("GET", f"/keys/{check_hash(key_hash)}"))
        return data if isinstance(data, dict) else {}

    async def delete(self, key_hash: str) -> None:
        await self._call("DELETE", f"/keys/{check_hash(key_hash)}")

    async def disable(self, key_hash: str) -> None:
        await self._call("PATCH", f"/keys/{check_hash(key_hash)}", body={"disabled": True})

    async def workspace(self, workspace_id: str) -> dict[str, Any]:
        data = self._data(await self._call("GET", f"/workspaces/{check_workspace(workspace_id)}"))
        return data if isinstance(data, dict) else {}

    async def budgets(self, workspace_id: str) -> list[dict[str, Any]]:
        data = self._data(await self._call("GET", f"/workspaces/{check_workspace(workspace_id)}/budgets"))
        return [b for b in data if isinstance(b, dict)] if isinstance(data, list) else []


async def probe_key(key: str, *, timeout: float = 10.0, transport: httpx.AsyncBaseTransport | None = None) -> bool:
    """True if OpenRouter accepts this inference key (GET /api/v1/key -> 200), False on 401/403.

    Uses its own short-lived client, never the management one. Other answers raise, because "unknown" must not be
    read as either "valid" (a new key that is not live yet) or "dead" (a revocation that has not propagated).
    """
    kwargs: dict[str, Any] = {"timeout": timeout, "follow_redirects": False, "trust_env": False}
    if transport is not None:
        kwargs["transport"] = transport
    try:
        async with httpx.AsyncClient(**kwargs) as client:
            response = await client.get(API + "/key", headers={"authorization": f"Bearer {key}"})
    except httpx.HTTPError as exc:
        raise BackendUnavailable(f"key probe: {type(exc).__name__}") from None
    if response.status_code == 200:
        return True
    if response.status_code in (401, 403):
        return False
    if response.status_code == 429:
        raise RateLimited("key probe rate limited", _retry_after(response))
    raise BackendUnavailable(f"key probe -> {response.status_code}")


Sleep = Callable[[float], Awaitable[None]]


class DirectBackend:
    """`ManagementBackend` that calls OpenRouter from the host. Holds the management key in RAM (passphrase mode)."""

    mode = "passphrase"
    DELETE_ATTEMPTS = 3

    def __init__(self, keys: OpenRouterKeys, *, workspace_id: str, instance_id: str,
                 management_expires_at: datetime | None = None, sleep: Sleep = asyncio.sleep) -> None:
        if not INSTANCE_RE.fullmatch(instance_id or ""):
            raise CustodyError("instance_id must be 8 lowercase hex characters")
        self.keys = keys
        self.workspace_id = check_workspace(workspace_id)
        self.prefix = f"{NAME_PREFIX}{instance_id}-"
        self.management_expires_at = management_expires_at
        self._sleep = sleep

    def name_for(self, suffix: str) -> str:
        if not isinstance(suffix, str) or not SUFFIX_RE.fullmatch(suffix):
            raise CustodyError("key name suffix must be 1-32 of [a-z0-9-]")
        return self.prefix + suffix

    async def mint(self, *, suffix: str, expires_at: datetime, limit_usd: float) -> MintedKey:
        if not (isinstance(limit_usd, (int, float)) and math.isfinite(limit_usd) and limit_usd > 0):
            raise CustodyError("limit_usd must be a positive number")
        if expires_at <= datetime.now(timezone.utc):
            raise CustodyError("expires_at must be in the future")
        name = self.name_for(suffix)
        payload = await self.keys.create(name=name, workspace_id=self.workspace_id, limit_usd=limit_usd, expires_at=expires_at)
        data = payload["data"]
        key_hash = data.get("hash")
        if not isinstance(key_hash, str) or not HASH_RE.fullmatch(key_hash):
            raise BackendUnavailable("OpenRouter returned a key without a valid hash; it cannot be revoked, so it is not used")
        # The expiry, limit and workspace are the hard ceilings on a leaked key. If OpenRouter did not record what we
        # asked for, the key is revoked at once and not used.
        granted = parse_time(data.get("expires_at"))
        problems = []
        if granted is None or granted > expires_at.astimezone(timezone.utc).replace(microsecond=0):
            problems.append("expiry")
        limit = data.get("limit")
        if not isinstance(limit, (int, float)) or limit > limit_usd:
            problems.append("limit")
        if data.get("workspace_id") not in (None, self.workspace_id):
            problems.append("workspace")
        if problems:
            await self._revoke_quietly(key_hash)
            raise CustodyError(f"OpenRouter did not apply the requested {', '.join(problems)}; the new key was revoked")
        return MintedKey(key=payload["key"], hash=key_hash, name=name, expires_at=granted, limit_usd=float(limit))

    async def _revoke_quietly(self, key_hash: str) -> None:
        try:
            await self.revoke(key_hash)
        except CustodyError:
            pass   # it still dies at expires_at

    async def revoke(self, key_hash: str) -> RevokeOutcome:
        """DELETE, retried with backoff; then PATCH disabled. Raises if both fail (the key dies at expires_at)."""
        check_hash(key_hash)
        last: CustodyError | None = None
        for attempt in range(self.DELETE_ATTEMPTS):
            try:
                await self.keys.delete(key_hash)
                return "deleted"
            except KeyNotFound:
                return "already_gone"
            except ManagementAuthError:
                raise
            except RateLimited as exc:
                last = exc
                delay = exc.retry_after if exc.retry_after is not None else 2.0 * 2 ** attempt
            except CustodyError as exc:
                last = exc
                delay = 2.0 * 2 ** attempt
            if attempt + 1 < self.DELETE_ATTEMPTS:
                await self._sleep(min(delay, 60.0))
        try:
            await self.keys.disable(key_hash)
            return "disabled"
        except KeyNotFound:
            return "already_gone"
        except CustodyError as exc:
            raise CustodyError(f"revoke failed (delete: {last}; disable: {exc}); the key dies at its expires_at") from None

    async def usage(self, key_hash: str) -> float:
        data = await self.keys.get(key_hash)
        value = data.get("usage")
        if not isinstance(value, (int, float)):
            raise BackendUnavailable("OpenRouter key details have no usage")
        return float(value)

    async def cleanup(self) -> int:
        """Startup only: revoke every key with this install's prefix. Run before the first mint, since it would
        otherwise also revoke the keys of the current run. Keys of other installs are never touched."""
        count = 0
        for record in await self.keys.list(workspace_id=self.workspace_id, include_disabled=True):
            name, key_hash = record.get("name"), record.get("hash")
            if isinstance(name, str) and name.startswith(self.prefix) and isinstance(key_hash, str) and HASH_RE.fullmatch(key_hash):
                if await self.revoke(key_hash) != "already_gone":
                    count += 1
        return count

    async def status(self) -> BackendStatus:
        """Healthy only if the key is a management key and the workspace exists and has a budget (owner decision)."""
        def bad(detail: str) -> BackendStatus:
            return BackendStatus(mode=self.mode, healthy=False, detail=detail, management_expires_at=self.management_expires_at)
        try:
            current = await self.keys.current()
            if current.get("is_management_key") is not True:
                return bad("the configured key is not a management key")
            expires = parse_time(current.get("expires_at")) or self.management_expires_at
            await self.keys.workspace(self.workspace_id)
            if not await self.keys.budgets(self.workspace_id):
                raise WorkspaceUnbudgeted("the Key Enigma workspace has no budget; add one on OpenRouter (required)")
        except KeyNotFound:
            return bad("the Key Enigma workspace does not exist")
        except CustodyError as exc:
            return bad(str(exc))
        return BackendStatus(mode=self.mode, healthy=True, management_expires_at=expires)

    async def aclose(self) -> None:
        await self.keys.aclose()
