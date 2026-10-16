from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import logs
from .adapter import extract, restore_tool_arguments, serialize
from .config import (ALWAYS_DROPPED_HEADERS, DEFAULT_HEADER_ALLOWLIST, DEFAULT_HEADER_BLOCKLIST, ENV_NAME_RE,
                     ConfigReferenceError, GatewayConfig, load_config, validation_errors)
from .detectors import PATTERNS, host_values
from .model import ContextItem, Session
from .observer import ResponseObserver
from .sanitize import SanitizationError, Sanitizer
from .session import SessionStore
from .streaming import SSETransformer
from .trace import TraceLog
from .upstream import MAX_RESPONSE_BYTES, ResponseTooLarge, endpoint_url, headers_for, read_limited, request as upstream_request, stream_request

# `testserver` (Starlette's TestClient default) is deliberately not accepted: tests use `localhost`.
LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}
GUI_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
           "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
# The catch-all /v1/* route forwards without sanitizing, so it only serves content-free metadata.
# Everything else (including /v1/chat/completions/ with a trailing slash) fails closed.
PASSTHROUGH_GET = re.compile(r"models(/.*)?")


def create_app(config: GatewayConfig) -> FastAPI:
    logs.configure()
    app = FastAPI(title="MasqAI Gateway", version="0.1.0")
    if config.host != "127.0.0.1":
        raise ValueError("Unauthenticated MasqAI must bind to 127.0.0.1")

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        host = request.url.hostname
        if host not in LOOPBACK_HOSTS:
            return JSONResponse({"error": "Loopback Host required"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.url.netloc}":
            return JSONResponse({"error": "Cross-origin requests are not allowed"}, status_code=403)
        # Top-level navigations and <script>/<img> loads carry no Origin header; browsers do send
        # Sec-Fetch-Site. Agents and SDKs send neither, so only browser traffic from other sites is refused.
        if request.headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}:
            return JSONResponse({"error": "Cross-site requests are not allowed"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/v1/"):
            # Upstream bytes are untrusted: never let them run as a page on the GUI's origin.
            response.headers["Content-Security-Policy"] = "sandbox; default-src 'none'; frame-ancestors 'none'"
        else:
            response.headers["Content-Security-Policy"] = GUI_CSP
        return response
    store = SessionStore()
    sanitizer = Sanitizer(config)
    traces = TraceLog()
    subscribers: set[asyncio.Queue] = set()
    locks: dict[str, asyncio.Lock] = {}

    def broadcast(event: dict[str, Any]) -> None:
        # Serialized now, so a subscriber sees the state at publish time, not at delivery.
        if not subscribers:
            return
        text = json.dumps(event, ensure_ascii=True)
        for queue in subscribers:
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(text)

    pending_sessions: dict[str, Session] = {}

    def flush_sessions() -> None:
        sessions = list(pending_sessions.values())
        pending_sessions.clear()
        for session in sessions:
            broadcast({"type": "session", "session": session.as_dict()})

    def publish(session):
        # Streaming responses publish on every token; coalesce into at most ~8 updates per second,
        # since each update serializes the whole session.
        first = not pending_sessions
        pending_sessions[session.id] = session
        if first:
            try:
                asyncio.get_running_loop().call_later(0.12, flush_sessions)
            except RuntimeError:
                flush_sessions()

    def publish_trace(trace):
        broadcast({"type": "trace", "trace": trace.as_dict()})

    async def process(api: str, payload: dict[str, Any], request: Request, current: dict | None = None) -> tuple[Session, Any, Any, Any]:
        session = store.resolve(payload, dict(request.headers))
        if current is not None:
            current["session"] = session
        original_payload = copy.deepcopy(payload)
        items = extract(payload, api)
        trace = traces.start(session.id, request.url.path, publish_trace)
        trace.update(request_id=logs.request_id.get(), model=payload.get("model"), stage="queued")
        # New request items are added as a revision; a complete current history is
        # represented by replacing matching item positions, preserving editable prefixes.
        async with locks.setdefault(session.id, asyncio.Lock()):
            if not request.url.path.endswith("count_tokens"):
                session.request_count += 1
                session.revision += 1
            trace.update(request_index=session.request_count)
            await sanitizer.sanitize(session, items, trace)
            if not request.url.path.endswith("count_tokens"):
                previous = {i.id: i for i in session.items}
                for item in items:
                    old = previous.get(item.id)
                    item.revision = (old.revision + int(old.sanitized != item.sanitized)) if old else 0
                session.items = items
                session.last_seen = time.time()
                store.remember(session, payload)
        sanitized_payload = serialize(payload, items)
        publish(session)
        return session, original_payload, sanitized_payload, items

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

    @app.get("/api/state")
    async def state() -> dict[str, Any]:
        return {"config": _public_config(config), "sessions": [session.as_dict() for session in store.sessions.values()],
                "traces": traces.as_list()}

    @app.get("/api/security")
    async def security_traces() -> dict[str, Any]:
        """Recent sanitize passes: the security model's input, raw output and decision (RAM only)."""
        return {"traces": traces.as_list(), "limit": traces.traces.maxlen}

    @app.get("/api/events")
    async def event_stream() -> StreamingResponse:
        async def generator() -> AsyncIterator[str]:
            queue = asyncio.Queue(maxsize=256)
            subscribers.add(queue)
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), 15)
                        yield f"data: {event}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                subscribers.discard(queue)
        return StreamingResponse(generator(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    @app.get("/api/config")
    async def get_config() -> dict[str, Any]:
        return _public_config(config)

    @app.get("/api/config/meta")
    async def config_meta() -> dict[str, Any]:
        """Read-only facts the config panel shows next to fields."""
        return {
            "always_dropped_headers": ALWAYS_DROPPED_HEADERS,
            "default_blocklist": DEFAULT_HEADER_BLOCKLIST,
            "default_allowlist": DEFAULT_HEADER_ALLOWLIST,
            "detector_patterns": [name for name, _ in PATTERNS],
            "host_identifiers": [{"type": t, "value": v} for t, v in host_values()],
            "default_security_prompt": Sanitizer._default_prompt(),
            "listen": f"http://{config.host}:{config.port}",
            # Optional settings this build supports; the panel hides sections for absent ones.
            "features": {"remote_security_check": True},
        }

    @app.get("/api/env/{name}")
    async def env_status(name: str) -> dict[str, Any]:
        """Whether an environment variable is set in the gateway process. Never returns the value."""
        if not ENV_NAME_RE.fullmatch(name):
            return JSONResponse({"error": "invalid variable name"}, status_code=400)
        return {"name": name, "set": bool(os.getenv(name))}

    @app.post("/api/config")
    async def update_config(body: dict[str, Any]) -> dict[str, Any]:
        try:
            # Literal api_key values are rejected by ProviderConfig; the "<configured>" marker
            # echoed by GET /api/config is accepted and dropped (keys live in env vars only).
            candidate = GatewayConfig.model_validate(body)
            if candidate.host != config.host or candidate.port != config.port:
                raise ConfigReferenceError(("port",), "host and port are fixed at startup; edit masqai.json and restart")
            for field in GatewayConfig.model_fields:
                setattr(config, field, getattr(candidate, field))
        except Exception as exc:
            errors = validation_errors(exc)
            return JSONResponse({"error": "; ".join(".".join(map(str, e["loc"])) + ": " + e["msg"] for e in errors), "errors": errors}, status_code=400)
        return _public_config(config)

    async def proxy(api: str, path: str, request: Request) -> Response:
        logs.begin()
        started = time.monotonic()
        try:
            payload = await request.json()
        except ValueError:
            return JSONResponse({"error": {"type": "masqai_bad_request", "message": "request body must be JSON"}}, status_code=400)
        if not isinstance(payload, dict):
            return JSONResponse({"error": {"type": "masqai_bad_request", "message": "request body must be a JSON object"}}, status_code=400)
        requested_model = payload.get("model")
        current: dict[str, Session] = {}

        def masked(text: str) -> str:
            # Upstream errors can echo request content; apply known mappings before logging.
            session = current.get("session")
            return restore_free_mask(text, session.known_values()) if session else text

        try:
            provider, upstream_model = config.route(requested_model)
            url = endpoint_url(provider.base_url, path)
            route_kind = "alias" if (requested_model or "") in config.routes else "default_route"
            logs.log.info("%s %s model=%r -> provider=%s model=%r via %s; url=%s stream=%s",
                          request.method, request.url.path, requested_model, provider.name, upstream_model,
                          route_kind, url, bool(payload.get("stream")))
            if upstream_model is None:
                logs.log.warning("no upstream model: the request has none and the route sets none")
            if provider.api_key_env and not provider.resolved_key():
                logs.log.warning("provider %s: env var %s is not set; sending without credentials",
                                 provider.name, provider.api_key_env)
            session, original, sanitized, items = await process(api, payload, request, current)
            changed = sum(1 for item in items if item.changed)
            logs.log.info("sanitized in %.0f ms: session=%s items=%d changed=%d entities=%d",
                          (time.monotonic() - started) * 1000, session.id, len(items), changed, len(session.entities))
            sanitized["model"] = upstream_model
            logs.log.info("upstream request: %s", logs.shape(sanitized))
            logs.debug_body("upstream body (sanitized)", sanitized)
            observer = ResponseObserver(session, publish)
            is_stream = bool(sanitized.get("stream"))
            sent = time.monotonic()
            if is_stream:
                import httpx
                client = httpx.AsyncClient(timeout=config.upstream_timeout_seconds)
                upstream_request_object = client.build_request("POST", url, params=request.query_params, json=sanitized, headers=headers_for(provider, dict(request.headers), config.headers))
                try:
                    upstream_stream = await client.send(upstream_request_object, stream=True)
                except Exception:
                    await client.aclose()
                    raise
                if upstream_stream.status_code >= 400:
                    try:
                        error_body = await read_limited(upstream_stream)
                    finally:
                        await upstream_stream.aclose()
                        await client.aclose()
                    _log_upstream_error(upstream_stream, error_body, provider.name, upstream_model, sent, masked)
                    return Response(error_body, status_code=upstream_stream.status_code, headers=_response_headers(upstream_stream.headers))
                logs.log.info("upstream %d, streaming started after %.0f ms", upstream_stream.status_code, (time.monotonic() - sent) * 1000)
                rid = logs.request_id.get()
                async def output():
                    logs.request_id.set(rid)
                    transformer = SSETransformer(session.restore_table(), observer.event)
                    status = "completed"
                    received = 0
                    try:
                        async for chunk in upstream_stream.aiter_bytes():
                            received += len(chunk)
                            if received > MAX_RESPONSE_BYTES:
                                raise ResponseTooLarge(f"upstream stream exceeds {MAX_RESPONSE_BYTES} bytes")
                            for frame in transformer.feed(chunk):
                                _log_stream_error(frame, masked)
                                yield frame
                        trailing = transformer.finish()
                        if trailing:
                            yield trailing
                    except BaseException as exc:
                        status = f"aborted ({exc.__class__.__name__}: {masked(str(exc))})"
                        raise
                    finally:
                        await upstream_stream.aclose()
                        await client.aclose()
                        log = logs.log.info if status == "completed" else logs.log.warning
                        log("stream %s after %.0f ms", status, (time.monotonic() - started) * 1000)
                return StreamingResponse(output(), status_code=upstream_stream.status_code, headers=_response_headers(upstream_stream.headers))
            upstream = await upstream_request(provider, path, sanitized, dict(request.headers), config.upstream_timeout_seconds, config.headers)
            if upstream.status_code >= 400:
                _log_upstream_error(upstream, upstream.content, provider.name, upstream_model, sent, masked)
            else:
                logs.log.info("upstream %d in %.0f ms", upstream.status_code, (time.monotonic() - sent) * 1000)
            if "application/json" not in upstream.headers.get("content-type", ""):
                return Response(upstream.content, status_code=upstream.status_code, headers=_response_headers(upstream.headers))
            body = upstream.json()
            observer.event(body)
            restored = restore_tool_arguments(body, session.restore_table(), api)
            if restored == body:
                return Response(upstream.content, status_code=upstream.status_code, headers=_response_headers(upstream.headers))
            return JSONResponse(restored, status_code=upstream.status_code, headers=_response_headers(upstream.headers))
        except SanitizationError as exc:
            logs.log.error("blocked (fail closed) after %.0f ms, nothing was sent upstream: %s", (time.monotonic() - started) * 1000, masked(str(exc)))
            return JSONResponse({"error": {"type": "masqai_sanitization_error", "message": masked(str(exc))}}, status_code=502)
        except Exception as exc:
            logs.log.exception("gateway error after %.0f ms: %s: %s", (time.monotonic() - started) * 1000,
                               exc.__class__.__name__, masked(str(exc)))
            return JSONResponse({"error": {"type": "masqai_gateway_error", "message": f"{exc.__class__.__name__}: {masked(str(exc))}"}}, status_code=500)

    @app.post("/v1/chat/completions")
    async def openai_chat(request: Request) -> Response:
        return await proxy("openai", "/v1/chat/completions", request)

    @app.post("/v1/responses")
    async def openai_responses(request: Request) -> Response:
        return await proxy("openai", "/v1/responses", request)

    @app.post("/v1/messages")
    async def anthropic_messages(request: Request) -> Response:
        return await proxy("anthropic", "/v1/messages", request)

    @app.post("/v1/messages/count_tokens")
    async def anthropic_count_tokens(request: Request) -> Response:
        return await proxy("anthropic", "/v1/messages/count_tokens", request)

    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def passthrough(path: str, request: Request):
        import httpx
        logs.begin()
        if request.method not in {"GET", "HEAD"} or not PASSTHROUGH_GET.fullmatch(path):
            # Fail closed: an endpoint MasqAI does not sanitize must not carry context upstream.
            logs.log.warning("refused %s /v1/%s: not a sanitized endpoint and not on the metadata passthrough list", request.method, path)
            return JSONResponse({"error": {"type": "masqai_unsupported_endpoint",
                                           "message": f"MasqAI does not sanitize {request.method} /v1/{path}; refused (fail closed)"}}, status_code=404)
        try:
            provider, _ = config.route(None)
            url = endpoint_url(provider.base_url, "/v1/" + path)
            async with httpx.AsyncClient(timeout=config.upstream_timeout_seconds) as client:
                async with client.stream(request.method, url, params=request.query_params, headers=headers_for(provider, dict(request.headers), config.headers)) as response:
                    content = await read_limited(response)
                level = logging.WARNING if response.status_code >= 400 else logging.INFO
                logs.log.log(level, "passthrough %s /v1/%s -> %s: HTTP %d%s", request.method, path, url, response.status_code,
                             ("\n    body: " + logs.error_text(content)) if response.status_code >= 400 else "")
                return Response(content, status_code=response.status_code, headers=_response_headers(response.headers))
        except Exception as exc:
            logs.log.error("passthrough %s /v1/%s failed: %s", request.method, path, exc.__class__.__name__)
            return JSONResponse({"error": {"type": "masqai_gateway_error", "message": f"passthrough failed: {exc.__class__.__name__}"}}, status_code=502)

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    return app


def _response_headers(headers: Any) -> dict[str, str]:
    # set-cookie: the upstream must not plant cookies on the gateway's origin (the GUI shares it).
    blocked = {"content-length", "content-encoding", "connection", "transfer-encoding", "keep-alive", "te", "trailer", "upgrade",
               "set-cookie", "set-cookie2", "content-security-policy", "x-content-type-options", "x-frame-options"}
    return {key: value for key, value in headers.items() if key.lower() not in blocked}


def restore_free_mask(text: str, values: list[tuple[str, str]]) -> str:
    """Replace known sensitive values with their placeholders, for log lines only.
    `values` is Session.known_values(): (value, placeholder) pairs, longest first. Logs are not context,
    so plain replacement is fine here: over-masking a log line hides nothing the user needs."""
    for value, token in values:
        if not value:
            continue
        # Also the JSON-escaped form, since error bodies are usually JSON.
        for form in {value, json.dumps(value, ensure_ascii=False)[1:-1]}:
            text = text.replace(form, token)
    return text


# Response headers worth seeing when an upstream rejects a request.
DIAGNOSTIC_HEADERS = ("x-request-id", "request-id", "cf-ray", "x-generation-id", "openrouter-provider", "retry-after",
                      "x-ratelimit-remaining-requests", "x-ratelimit-remaining-tokens")


def _log_upstream_error(response: Any, content: bytes, provider: str, model: Any, sent: float, masked) -> None:
    extra = {k: response.headers[k] for k in DIAGNOSTIC_HEADERS if k in response.headers}
    logs.log.error("upstream rejected the request: HTTP %d in %.0f ms (provider=%s model=%r)%s\n    body: %s",
                   response.status_code, (time.monotonic() - sent) * 1000, provider, model,
                   f" headers={extra}" if extra else "", masked(logs.error_text(content)))


def _log_stream_error(frame: bytes, masked) -> None:
    """Some upstreams (OpenRouter included) report failures as an SSE event after HTTP 200."""
    if b'"error"' not in frame:
        return
    for line in frame.decode("utf-8", "replace").splitlines():
        if not line.startswith("data:"):
            continue
        try:
            data = json.loads(line[5:])
        except ValueError:
            continue
        if isinstance(data, dict) and (data.get("error") or data.get("type") == "error"):
            logs.log.error("upstream error inside the stream: %s", masked(logs.error_text(json.dumps(data))))


def _public_config(config: GatewayConfig) -> dict[str, Any]:
    # Keys are env-var references only, so the config itself holds no secret values.
    return config.model_dump()


def app_from_file(path: str = "masqai.json") -> FastAPI:
    return create_app(load_config(path))
