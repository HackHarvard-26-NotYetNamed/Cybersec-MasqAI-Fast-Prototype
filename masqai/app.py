"""The MasqAI gateway: a local proxy for OpenAI- and Anthropic-compatible traffic.

Outbound: request hygiene → content extraction → detectors → auto masks → security model → upstream.
Inbound: placeholders in agent-run tool-call arguments are restored; assistant text is never modified.
Fail closed: if inspection can't complete, nothing is sent upstream.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, logs
from .adapter import API_ANTHROPIC, API_CHAT, API_RESPONSES, BadRequest, UnknownContent, extract_with_warnings, serialize
from .config import (ALWAYS_DROPPED_HEADERS, DEFAULT_HEADER_ALLOWLIST, DEFAULT_HEADER_BLOCKLIST, ENV_NAME_RE,
                     ConfigReferenceError, GatewayConfig, load_config, validation_errors)
from .detectors import host_values, rule_names
from .enigma import KeyRing, KeyUnavailable, rejection_reason
from .hygiene import pseudonymize, stripped_headers
from .model import Session
from .policy import CATEGORIES
from .observer import ResponseObserver
from .replay import ResponseRecorder, export, record_request
from .restore import extract_inbound_tool_calls, reject_inbound_tool_call, rejection_message, restore_map, restore_response
from .sanitize import SanitizationError, Sanitizer
from .session import SessionStore
from .streaming import SSETransformer
from .trace import TraceLog
from .upstream import MAX_RESPONSE_BYTES, ResponseTooLarge, endpoint_url, headers_for, read_limited, request as upstream_request

GUI_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
           "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
V1_CSP = "sandbox; default-src 'none'; frame-ancestors 'none'"
# GET/HEAD /v1/models[/...] is the only unsanitized passthrough: it carries no context.
PASSTHROUGH_GET = re.compile(r"models(/[^/]+)*")
RETENTION_INTERVAL_S = 60
class ToolRejected(Exception):
    """error-mode tool rejection before any byte of a stream was sent: answered as HTTP 400."""


BLOCK_STATUS = {"security_model_failed": 502, "invalid_correction": 502, "remote_security_model_refused": 502}


def create_app(config: GatewayConfig, *, admin_token: str | None = None, playground: bool = False,
               frozen_env: set[str] | None = None, keyring: KeyRing | None = None) -> FastAPI:
    logs.configure()
    if config.host != "127.0.0.1":
        raise ValueError("MasqAI binds to 127.0.0.1 only")
    token = admin_token or secrets.token_urlsafe(32)   # 256 random bits per start, RAM only
    # Env var NAMES referenced at startup. The GUI may reassign them between providers, never add new ones.
    env_names = set(frozen_env) if frozen_env is not None else {p.api_key_env for p in config.providers if p.api_key_env}
    allowed_hosts = {f"127.0.0.1:{config.port}", f"localhost:{config.port}"}

    store = SessionStore()
    keyring = keyring or KeyRing()
    # A provider configured for rotation must never fall back to its static env key (fail closed).
    missing = [p.name for p in config.providers if p.rotates and not keyring.rotates(p.name)]
    if missing:
        raise ValueError(f"key_enigma is enabled for {', '.join(missing)} but no rotating key source was given; "
                         "start the gateway with run_gateway.py, which opens the custody backend")
    # Key Enigma settings are fixed at startup: the custody backend was opened for exactly these.
    startup_enigma = enigma_blocks(config)
    sanitizer = Sanitizer(config, keyring)
    traces = TraceLog()
    subscribers: set[asyncio.Queue] = set()
    listeners: list = []   # in-process observers (tests, embedding); events are already RAM-only
    locks: dict[str, asyncio.Lock] = {}
    pending_sessions: dict[str, Session] = {}

    def broadcast(event: dict[str, Any]) -> None:
        for listener in listeners:
            listener(event)
        if not subscribers:
            return
        text = json.dumps(event, ensure_ascii=True, default=str)
        for queue in list(subscribers):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(text)

    def flush_sessions() -> None:
        sessions = list(pending_sessions.values())
        pending_sessions.clear()
        for session in sessions:
            if session.id in store.sessions:
                broadcast({"type": "session", "session": session_summary(session)})

    def publish(session: Session) -> None:
        # Streaming responses publish on every token; coalesce to at most ~8 updates per second.
        first = not pending_sessions
        pending_sessions[session.id] = session
        if first:
            try:
                asyncio.get_running_loop().call_later(0.12, flush_sessions)
            except RuntimeError:
                flush_sessions()

    def publish_trace(trace) -> None:
        broadcast({"type": "trace", "trace": trace.as_dict()})

    def forget(sid: str, reason: str) -> bool:
        if not store.forget(sid):
            return False
        locks.pop(sid, None)
        traces.forget(sid)
        broadcast({"type": "forget", "session": sid, "reason": reason})
        return True

    def enforce_retention() -> None:
        for sid in store.enforce(config.retention.idle_ttl_h, config.retention.max_sessions):
            locks.pop(sid, None)
            traces.forget(sid)
            broadcast({"type": "forget", "session": sid, "reason": "retention"})

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async def loop() -> None:
            while True:
                await asyncio.sleep(RETENTION_INTERVAL_S)
                enforce_retention()
        task = asyncio.create_task(loop())
        try:
            await keyring.start()   # rotating sources hold a validated key before the first request
            yield
        finally:
            task.cancel()
            await keyring.stop()

    app = FastAPI(title="MasqAI Gateway", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.admin_token = token
    app.state.store = store
    app.state.traces = traces
    app.state.listeners = listeners

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"error": "Loopback Host required"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.headers.get('host')}":
            return JSONResponse({"error": "Cross-origin requests are not allowed"}, status_code=403)
        # Browsers send Sec-Fetch-Site; agents and SDKs don't. Only same-origin or direct navigation pass.
        if request.headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}:
            return JSONResponse({"error": "Cross-site requests are not allowed"}, status_code=403)
        path = request.url.path
        if path.startswith("/api/"):
            supplied = request.headers.get("x-masqai-token", "")
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                return JSONResponse({"error": "admin token required (x-masqai-token)"}, status_code=401)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # Upstream bytes are untrusted: never let them run as a page on the GUI's origin.
        response.headers["Content-Security-Policy"] = V1_CSP if path.startswith("/v1/") else GUI_CSP
        return response

    # ---------- GUI and control API ----------
    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

    @app.get("/api/state")
    async def state() -> dict[str, Any]:
        return {"version": __version__, "playground": playground, "config": public_config(config),
                "sessions": [session_summary(s) for s in store.sessions.values()]}

    @app.get("/api/sessions/{sid}")
    async def session_detail(sid: str):
        session = store.sessions.get(sid)
        if session is None:
            return JSONResponse({"error": "unknown session"}, status_code=404)
        return session.as_dict()

    @app.post("/api/sessions/{sid}/forget")
    async def forget_session(sid: str):
        session = store.sessions.get(sid)
        if session is None:
            return JSONResponse({"error": "unknown session"}, status_code=404)
        if session.in_flight:
            # Forgetting now would drop the mapping a running stream still needs to restore tool calls.
            return JSONResponse({"error": "session is busy (a request or stream is in flight); try again when it ends"},
                                status_code=409)
        forget(sid, "user")
        return {"forgotten": sid}

    @app.get("/api/sessions/{sid}/replay")
    async def replay(sid: str, request: Request):
        if not playground:
            return JSONResponse({"error": "replay export is only available when the gateway runs with --playground "
                                          "(it contains raw values)"}, status_code=403)
        if request.query_params.get("synthetic") != "1":
            return JSONResponse({"error": "add synthetic=1: exports replace this machine's host identifiers with fake ones"}, status_code=400)
        session = store.sessions.get(sid)
        if session is None:
            return JSONResponse({"error": "unknown session"}, status_code=404)
        # Streamed to the caller; the gateway never writes the export to disk.
        return JSONResponse(export(session, synthetic=True))

    @app.get("/api/security")
    async def security_traces() -> dict[str, Any]:
        return {"traces": traces.as_list(), "limit": traces.traces.maxlen}

    @app.get("/api/enigma/status")
    async def enigma_status() -> dict[str, Any]:
        # Labels, states, times and 8-character hash prefixes only: never a key value or a full hash.
        return {"providers": keyring.status()}

    @app.get("/api/enigma/export")
    async def enigma_export() -> dict[str, Any]:
        exported = keyring.export_keys()
        if exported is None:
            return JSONResponse({"error": "no live Key Enigma source is configured"}, status_code=404)
        return exported

    @app.get("/api/events")
    async def event_stream() -> StreamingResponse:
        async def generator():
            queue: asyncio.Queue = asyncio.Queue(maxsize=256)
            subscribers.add(queue)
            try:
                yield "retry: 2000\n\n"
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
        return public_config(config)

    @app.get("/api/config/meta")
    async def config_meta() -> dict[str, Any]:
        return {
            "version": __version__,
            "always_dropped_headers": ALWAYS_DROPPED_HEADERS,
            "default_blocklist": DEFAULT_HEADER_BLOCKLIST,
            "default_allowlist": DEFAULT_HEADER_ALLOWLIST,
            "detector_rules": rule_names(config.detectors.rules_dir),
            "host_identifiers": [{"type": t, "value": v} for t, v in host_values()],
            "default_security_prompt": Sanitizer._default_prompt(),
            "protect_categories": [{"id": c.id, "label": c.label, "kind": c.kind, "description": c.description} for c in CATEGORIES],
            "env_names": sorted(env_names),
            "listen": f"http://{config.host}:{config.port}",
            "playground": playground,
        }

    @app.get("/api/env/{name}")
    async def env_status(name: str):
        """Whether a startup env var is set. Never returns the value; unknown names are 404."""
        if not ENV_NAME_RE.fullmatch(name) or name not in env_names:
            return JSONResponse({"error": "not one of the env var names referenced at startup"}, status_code=404)
        return {"name": name, "set": bool(os.getenv(name))}

    @app.post("/api/config")
    async def update_config(request: Request):
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "body must be JSON"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "body must be a JSON object"}, status_code=400)
        try:
            candidate = GatewayConfig.model_validate(body)
            if candidate.port != config.port:
                raise ConfigReferenceError(("port",), "port is fixed at startup; edit masqai.json and restart")
            for index, provider in enumerate(candidate.providers):
                if provider.api_key_env and provider.api_key_env not in env_names:
                    raise ConfigReferenceError(("providers", index, "api_key_env"),
                                               f"{provider.api_key_env!r} was not referenced in masqai.json at startup; "
                                               f"choose one of {sorted(env_names)} or restart")
            changed = enigma_blocks(candidate)
            if changed != startup_enigma:
                names = [p.name for p in candidate.providers]
                diff = [n for n in set(changed) | set(startup_enigma) if changed.get(n) != startup_enigma.get(n)]
                index = next((names.index(n) for n in diff if n in names), 0)
                raise ConfigReferenceError(("providers", index, "key_enigma"),
                                           "Key Enigma settings are fixed at startup (the custody backend was opened for "
                                           "them); edit masqai.json and restart")
            for field in GatewayConfig.model_fields:
                setattr(config, field, getattr(candidate, field))
        except Exception as exc:
            errors = validation_errors(exc)
            return JSONResponse({"error": "; ".join(".".join(map(str, e["loc"])) + ": " + e["msg"] for e in errors),
                                 "errors": errors}, status_code=400)
        enforce_retention()
        broadcast({"type": "config", "config": public_config(config)})
        return public_config(config)

    # ---------- the proxy ----------
    def error(status: int, kind: str, message: str, **extra: Any) -> JSONResponse:
        return JSONResponse({"error": {"type": kind, "message": message, **extra}}, status_code=status)

    async def proxy(api: str, path: str, request: Request) -> Response:
        rid = logs.begin()
        started = time.monotonic()
        try:
            payload = await request.json()
        except ValueError:
            return error(400, "masqai_bad_request", "request body must be JSON")
        if not isinstance(payload, dict):
            return error(400, "masqai_bad_request", "request body must be a JSON object")
        headers = {k.lower(): v for k, v in request.headers.items()}
        # Extraction first: unknown content is refused before any session or trace exists.
        try:
            items, warnings = extract_with_warnings(payload, api, config.pass_unknown)
        except UnknownContent as exc:
            logs.log.warning("refused (422): %s", exc)
            return error(422, "masqai_unknown_content", f"MasqAI can't inspect {exc.location} (type {exc.content_type!r}); refused before inspection",
                         location=exc.location, content_type=exc.content_type)
        except BadRequest as exc:
            return error(400, "masqai_bad_request", str(exc))
        session = store.resolve(payload, headers)
        session.in_flight += 1
        released = False
        streaming = False   # once a stream is handed back, its generator releases the session
        upstream_lease = None

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                session.in_flight -= 1

        def masked(text: str) -> str:
            own = [(value, f"<{kind}_enigma>") for value, kind in keyring.known_secrets()]
            return scrub(text, own + session.known_values())

        async def inspect_calls(calls: list[dict[str, Any]]) -> dict[Any, tuple[str, str]]:
            """The inbound tool calls the guardrail rejects: {index, or a stream's call key: (tool, reason)}."""
            rejected: dict[Any, tuple[str, str]] = {}
            for n, call in enumerate(calls):
                allowed, reason = await sanitizer.inspect_inbound_tool_call(session, call["tool"], call["arguments"], call["placeholders"], table)
                if not allowed:
                    logs.log.warning("rejected inbound tool call %s (%s): %s", call["tool"], config.security.tool_rejection, reason)
                    broadcast({"type": "warning", "session": session.id, "message": f"tool call {call['tool']} rejected: {reason}"})
                    rejected[call.get("key", n)] = (call["tool"], reason)
            return rejected

        try:
            for warning in warnings:
                logs.log.warning("pass_unknown: forwarding %s (type %r) raw", warning["location"], warning["type"])
                broadcast({"type": "warning", "session": session.id, "message": f"{warning['location']} ({warning['type']}) forwarded raw: pass_unknown is on"})
            provider, upstream_model = config.route(payload.get("model"))
            url = endpoint_url(provider.base_url, path)
            trace = traces.start(session.id, request.url.path, publish_trace)
            trace.update(request_id=rid, model=payload.get("model"), stage="queued")
            async with locks.setdefault(session.id, asyncio.Lock()):
                count_only = path.endswith("count_tokens")
                if not count_only:
                    session.request_count += 1
                    session.revision += 1
                trace.update(request_index=session.request_count)
                previous = {i.id: i for i in session.items}
                try:
                    await sanitizer.sanitize(session, items, trace)
                except SanitizationError as exc:
                    if not count_only:
                        record_request(session, items, set(previous), {"reason": exc.reason, "status": BLOCK_STATUS.get(exc.reason, 502)})
                    raise
                if not count_only:
                    remasked = 0
                    for item in items:
                        old = previous.get(item.id)
                        changed = old is not None and old.sanitized != item.sanitized
                        item.revision = (old.revision + int(changed)) if old else 0
                        remasked += int(changed)
                    session.remasks += remasked
                    record = record_request(session, items, set(previous), None)
                    session.items = items
                    store.remember(session, payload)
                else:
                    record = None
            sanitized = serialize(payload, items)
            sanitized["model"] = upstream_model
            pseudonymize(sanitized, session)
            session.headers_stripped.update(stripped_headers(headers, config.headers))
            publish(session)
            body_hash = hashlib.sha256(json.dumps(sanitized, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
            # Eval hook: one event per request that actually leaves for the upstream.
            broadcast({"type": "forwarded", "session": session.id, "request_index": session.request_count,
                       "endpoint": path, "sha256": body_hash})
            logs.log.info("forwarding to %s (provider=%s model=%r) after %.0f ms; %s", url, provider.name, upstream_model,
                          (time.monotonic() - started) * 1000, logs.shape(sanitized))
            table = restore_map(session.restore_table())
            upstream_lease = keyring.lease(provider)
            recorder = ResponseRecorder()
            observer = ResponseObserver(session, publish)

            def finish_record() -> None:
                if record is not None:
                    record["response"] = {**recorder.result(table), "at": time.time()}

            def rejected_key(status: int, body: bytes) -> bool:
                """Key Enigma (§8): if the upstream refused *our key*, retire it and lease a fresh one. True means the
                caller should retry once. Nothing has reached the client yet, and a 401/402 means the provider did
                not process the request, so the retry can't double-charge."""
                nonlocal upstream_lease
                reason = rejection_reason(status, body)
                if reason is None or not keyring.report_rejected(provider, upstream_lease.key, reason):
                    return False
                upstream_lease.release()
                upstream_lease = keyring.lease(provider)
                logs.log.warning("upstream refused the key (%s); retrying once with a fresh key", reason)
                return True

            if sanitized.get("stream"):
                for attempt in (1, 2):
                    outgoing = headers_for(provider, dict(request.headers), config.headers, key=upstream_lease.key)
                    client = httpx.AsyncClient(timeout=config.upstream_timeout_seconds)
                    try:
                        upstream = await client.send(client.build_request("POST", url, params=request.query_params, json=sanitized, headers=outgoing), stream=True)
                    except BaseException:
                        await client.aclose()
                        raise
                    if upstream.status_code < 400:
                        break
                    try:
                        body = await read_limited(upstream)
                    finally:
                        await upstream.aclose()
                        await client.aclose()
                    if attempt == 1 and rejected_key(upstream.status_code, body):
                        continue
                    upstream_lease.release()
                    release()
                    logs.log.error("upstream HTTP %d: %s", upstream.status_code, masked(logs.error_text(body)))
                    return Response(body, status_code=upstream.status_code, headers=response_headers(upstream.headers))

                def observe(event: dict[str, Any]) -> None:
                    recorder.event(event)
                    observer.event(event)

                async def output():
                    logs.request_id.set(rid)
                    transformer = SSETransformer(table, observe)
                    received = 0
                    try:
                        async for chunk in upstream.aiter_bytes():
                            received += len(chunk)
                            if received > MAX_RESPONSE_BYTES:
                                raise ResponseTooLarge(f"upstream stream exceeds {MAX_RESPONSE_BYTES} bytes")
                            for frame in transformer.feed(chunk):
                                yield frame
                        # Tool calls were held back until the stream ended: inspect them whole, then release.
                        rejected = await inspect_calls(transformer.pending_calls())
                        if rejected and config.security.tool_rejection == "error":
                            message = rejection_message(*next(iter(rejected.values())))
                            if not transformer.emitted:
                                raise ToolRejected(message)
                            for frame in transformer.error_frames(message):
                                yield frame
                            return
                        for frame in transformer.release(set(rejected)):
                            yield frame
                        tail = transformer.finish()
                        if tail:
                            yield tail
                    except ToolRejected:
                        raise
                    except Exception as exc:
                        logs.log.error("stream aborted: %s", exc.__class__.__name__)
                        raise
                    finally:
                        finish_record()
                        await upstream.aclose()
                        await client.aclose()
                        upstream_lease.release()
                        release()

                # Read the first frame before answering: a stream that would open with a rejected tool call
                # (error mode) can still become a plain HTTP 400.
                frames = output()
                try:
                    first = await frames.__anext__()
                except StopAsyncIteration:
                    first = b""
                except ToolRejected as exc:
                    return error(400, "masqai_tool_rejected", str(exc))

                async def chained():
                    if first:
                        yield first
                    async for frame in frames:
                        yield frame

                streaming = True
                return StreamingResponse(chained(), status_code=upstream.status_code, headers=response_headers(upstream.headers))

            try:
                for attempt in (1, 2):
                    response = await upstream_request(provider, path, sanitized, dict(request.headers), config.upstream_timeout_seconds, config.headers,
                                                      params=request.query_params, key=upstream_lease.key)
                    if not (attempt == 1 and response.status_code >= 400 and rejected_key(response.status_code, response.content)):
                        break
            finally:
                upstream_lease.release()
            if response.status_code >= 400:
                logs.log.error("upstream HTTP %d: %s", response.status_code, masked(logs.error_text(response.content)))
                return Response(response.content, status_code=response.status_code, headers=response_headers(response.headers))
            if "application/json" not in response.headers.get("content-type", ""):
                return Response(response.content, status_code=response.status_code, headers=response_headers(response.headers))
            data = response.json()
            if isinstance(data, dict):
                # Inbound tool guardrail: inspect tool calls that carry placeholders before restoring them.
                calls = extract_inbound_tool_calls(data)
                rejected = await inspect_calls(calls)
                if rejected and config.security.tool_rejection == "error":
                    finish_record()
                    return error(400, "masqai_tool_rejected", rejection_message(*next(iter(rejected.values()))))
                for n in rejected:
                    data = reject_inbound_tool_call(data, calls[n])

                recorder.body(data)
                observer.event(data)
                finish_record()
                restored = restore_response(data, table)
                return JSONResponse(restored, status_code=response.status_code, headers=response_headers(response.headers))
            return Response(response.content, status_code=response.status_code, headers=response_headers(response.headers))
        except SanitizationError as exc:
            logs.log.error("blocked (fail closed, %s) after %.0f ms; nothing was sent upstream", exc.reason, (time.monotonic() - started) * 1000)
            return error(BLOCK_STATUS.get(exc.reason, 502), "masqai_sanitization_error",
                         "MasqAI could not complete inspection, so nothing was sent (fail closed). Details are on the gateway's Security page.",
                         reason=exc.reason)
        except KeyUnavailable as exc:
            logs.log.error("refused (fail closed): %s; nothing was sent upstream", exc)
            return error(503, "masqai_key_unavailable", "no valid upstream key is available right now (Key Enigma, fail closed); nothing was sent")
        except Exception as exc:
            logs.log.exception("gateway error after %.0f ms: %s", (time.monotonic() - started) * 1000, exc.__class__.__name__)
            # Never echo exception text: it can contain request content.
            return error(500, "masqai_gateway_error", f"internal gateway error (request {rid}); see the gateway console")
        finally:
            if upstream_lease is not None and not streaming:
                upstream_lease.release()
            if not streaming:
                release()
            enforce_retention()

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        return await proxy(API_CHAT, "/v1/chat/completions", request)

    @app.post("/v1/responses")
    async def responses(request: Request) -> Response:
        return await proxy(API_RESPONSES, "/v1/responses", request)

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        return await proxy(API_ANTHROPIC, "/v1/messages", request)

    @app.post("/v1/messages/count_tokens")
    async def count_tokens(request: Request) -> Response:
        # Sanitized like any other request: it carries the full context.
        return await proxy(API_ANTHROPIC, "/v1/messages/count_tokens", request)

    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def other_v1(path: str, request: Request):
        logs.begin()
        if request.method not in {"GET", "HEAD"} or not PASSTHROUGH_GET.fullmatch(path):
            logs.log.warning("refused %s /v1/%s: not a sanitized endpoint (fail closed, nothing sent)", request.method, path)
            return error(404, "masqai_unsupported_endpoint", f"MasqAI does not sanitize {request.method} /v1/{path}; nothing was sent")
        try:
            provider, _ = config.route(None)
            with keyring.lease(provider) as key:
                async with httpx.AsyncClient(timeout=config.upstream_timeout_seconds) as client:
                    async with client.stream(request.method, endpoint_url(provider.base_url, "/v1/" + path), params=request.query_params,
                                             headers=headers_for(provider, dict(request.headers), config.headers, key=key)) as response:
                        content = await read_limited(response)
            return Response(content, status_code=response.status_code, headers=response_headers(response.headers))
        except KeyUnavailable:
            return error(503, "masqai_key_unavailable", "no valid upstream key is available right now (Key Enigma, fail closed)")
        except Exception as exc:
            logs.log.error("passthrough %s /v1/%s failed: %s", request.method, path, exc.__class__.__name__)
            return error(502, "masqai_gateway_error", "models passthrough failed")

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    return app


def session_summary(session: Session) -> dict[str, Any]:
    return {"id": session.id, "parent_id": session.parent_id, "hint": bool(session.hint), "request_count": session.request_count,
            "items": len(session.items), "entities": len(session.entities), "rollbacks": session.rollbacks,
            "remasks": session.remasks, "relinks": len(session.relinks), "created": session.created,
            "last_seen": session.last_seen, "in_flight": session.in_flight}


def response_headers(headers: Any) -> dict[str, str]:
    # The upstream must not plant cookies or its own CSP on the gateway's origin (the GUI shares it).
    blocked = {"content-length", "content-encoding", "connection", "transfer-encoding", "keep-alive", "te", "trailer", "upgrade",
               "set-cookie", "set-cookie2", "content-security-policy", "content-security-policy-report-only",
               "x-content-type-options", "x-frame-options"}
    return {key: value for key, value in headers.items() if key.lower() not in blocked}


def scrub(text: str, values: list[tuple[str, str]]) -> str:
    """Known sensitive values → placeholders, for log lines and errors only."""
    for value, placeholder in values:
        if value:
            for form in {value, json.dumps(value, ensure_ascii=False)[1:-1]}:
                text = text.replace(form, placeholder)
    return text


def enigma_blocks(config: GatewayConfig) -> dict[str, Any]:
    """{provider name: (its key_enigma block, base_url if it rotates)} for providers that have a key_enigma block."""
    return {p.name: (p.key_enigma.model_dump(), p.base_url if p.rotates else None) for p in config.providers if p.key_enigma}


def public_config(config: GatewayConfig) -> dict[str, Any]:
    # Keys are env var references only, so the config itself holds no secret values.
    return config.model_dump()


def app_from_file(path: str = "masqai.json", **kwargs: Any) -> FastAPI:
    return create_app(load_config(path), **kwargs)
