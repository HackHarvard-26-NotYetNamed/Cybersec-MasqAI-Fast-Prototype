from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from .config import HeaderPolicy, ProviderConfig

# The upstream is untrusted: bound what it can make the gateway hold in RAM.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class ResponseTooLarge(RuntimeError):
    pass


async def read_limited(response: httpx.Response, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    """Read a streamed response body, refusing to buffer more than `limit` bytes."""
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise ResponseTooLarge(f"upstream response declares {declared} bytes (limit {limit})")
    chunks, size = [], 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > limit:
            raise ResponseTooLarge(f"upstream response exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def endpoint_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    if base.endswith("/v1") and path.startswith("/v1/"):
        return base + path[3:]
    return base + path


def headers_for(provider: ProviderConfig, incoming: dict[str, str], policy: HeaderPolicy | None = None) -> dict[str, str]:
    policy = policy or HeaderPolicy()
    connection = next((v for k, v in incoming.items() if k.lower() == "connection"), "")
    hop_by_hop = {part.strip().lower() for part in connection.split(",") if part.strip()}
    result = {key: value for key, value in incoming.items() if key.lower() not in hop_by_hop and policy.allows(key)}
    if policy.user_agent:
        result["user-agent"] = policy.user_agent   # the client's own User-Agent identifies the agent and OS
    key = provider.resolved_key()
    if provider.format == "anthropic":
        if key:
            result["x-api-key"] = key
        result.setdefault("anthropic-version", "2023-06-01")
    elif key:
        result["authorization"] = f"Bearer {key}"
    result.update(provider.headers)
    return result


async def request(provider: ProviderConfig, path: str, body: dict[str, Any], incoming: dict[str, str], timeout: float, policy: HeaderPolicy | None = None) -> httpx.Response:
    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream("POST", endpoint_url(provider.base_url, path), json=body, headers=headers_for(provider, incoming, policy)) as response:
            content = await read_limited(response)
        # A detached copy: same status, headers and body, already read and decoded.
        headers = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in {"content-encoding", "content-length", "transfer-encoding"}]
        return httpx.Response(response.status_code, headers=headers, content=content, request=response.request)


async def stream_request(provider: ProviderConfig, path: str, body: dict[str, Any], incoming: dict[str, str], timeout: float, policy: HeaderPolicy | None = None) -> AsyncIterator[bytes]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream("POST", endpoint_url(provider.base_url, path), json=body, headers=headers_for(provider, incoming, policy)) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes():
                yield chunk


def model_path(api: str, requested: str) -> str:
    if api == "anthropic":
        return "/v1/messages"
    return "/v1/responses" if requested == "responses" else "/v1/chat/completions"
