"""Eval GUI: configure and run a whole campaign from a browser, one click.

    python -m eval.gui [--port 8790] [--no-browser]

Binds to 127.0.0.1 only. A campaign runs in this process (one at a time); its services (relay, one
MasqAI gateway per masqai condition, fake models for self-test) are started and stopped by it. The page
streams progress over SSE. Every campaign lands in eval/out/campaigns/<id>/.

API (JSON):
  GET  /api/state                     presets, cases, env, current campaign, recent campaigns
  POST /api/check      {config}       validation + static problems (no network)
  POST /api/start      {config}       start a campaign
  POST /api/stop                      cancel the running campaign (sandboxes are deleted)
  GET  /api/events                    SSE: plan / status / run / log / results
  GET  /api/campaigns/{id}            config, meta, rows, results, report of a past campaign
  POST /api/campaigns/{id}/publish    write its results.json to web/public/data/
  POST /api/presets/{name}  {config}  save a preset (eval/presets/<name>.json)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import secrets
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from .cases import load_cases
from .run_eval import CAMPAIGNS, Campaign
from .settings import PRESETS_DIR, RunConfig, presets, problems

HERE = Path(__file__).parent
ENV_VARS = ["OPENROUTER_API_KEY", "DAYTONA_API_KEY"]
MAX_EVENTS = 20_000


def config_errors(exc: Exception) -> list[dict[str, str]]:
    from pydantic import ValidationError
    if isinstance(exc, ValidationError):
        return [{"level": "error", "where": ".".join(str(p) for p in e["loc"]) or "config",
                 "msg": e["msg"].removeprefix("Value error, ")} for e in exc.errors()]
    return [{"level": "error", "where": "config", "msg": str(exc)}]


def read_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def campaign_summary(path: Path) -> dict[str, Any]:
    meta = json.loads((path / "meta.json").read_text(encoding="utf-8")) if (path / "meta.json").exists() else {}
    rows = read_rows(path / "runs.jsonl")
    return {"id": path.name, "startedAt": meta.get("startedAt"), "selfTest": meta.get("selfTest", False),
            "conditions": [c["id"] for c in meta.get("conditions", [])], "runs": len(rows),
            "errors": sum(bool(r.get("error")) for r in rows), "hasResults": (path / "results.json").exists()}


class Hub:
    """The one campaign slot plus an event log that SSE clients replay from any offset."""

    def __init__(self) -> None:
        self.campaign: Campaign | None = None
        self.task: asyncio.Task | None = None
        self.events: list[dict[str, Any]] = []
        self.base = 0              # sequence number of events[0]
        self.changed = asyncio.Event()

    def emit(self, event: dict[str, Any]) -> None:
        event["seq"] = self.base + len(self.events)
        self.events.append(event)
        if len(self.events) > MAX_EVENTS:
            drop = len(self.events) - MAX_EVENTS
            del self.events[:drop]
            self.base += drop
        self.changed.set()
        self.changed = asyncio.Event()

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()


def create_app(token: str) -> FastAPI:
    hub = Hub()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        if hub.running:   # closing the GUI stops the campaign, its services and its sandboxes
            hub.task.cancel()
            await asyncio.gather(hub.task, return_exceptions=True)

    app = FastAPI(title="MasqAI eval GUI", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Same-machine only: refuse other Hosts (DNS rebinding) and, for /api, require the session token.
        host = (request.headers.get("host") or "").split(":")[0]
        if host not in {"127.0.0.1", "localhost"}:
            return JSONResponse({"error": "forbidden host"}, status_code=403)
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get("x-eval-token") or request.query_params.get("token") or ""
            if not secrets.compare_digest(supplied, token):
                return JSONResponse({"error": "missing or wrong token"}, status_code=401)
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return (HERE / "gui.html").read_text(encoding="utf-8")

    @app.get("/api/state")
    async def state() -> dict[str, Any]:
        cases = [{"id": c.id, "title": c.title, "expected": c.expected_block_status} for c in load_cases()]
        recent = sorted((p for p in CAMPAIGNS.glob("*") if p.is_dir()), reverse=True)[:30] if CAMPAIGNS.exists() else []
        current = hub.campaign
        return {
            "presets": presets(), "cases": cases,
            "env": {name: bool(os.getenv(name)) for name in ENV_VARS},
            "running": hub.running,
            "current": {"id": current.id, "status": current.status, "done": current.done, "total": current.total,
                        "error": current.error} if current else None,
            "eventSeq": hub.base + len(hub.events),
            "campaigns": [campaign_summary(p) for p in recent],
        }

    @app.post("/api/check")
    async def check(body: dict[str, Any]) -> dict[str, Any]:
        try:
            cfg = RunConfig.model_validate(body.get("config") or {})
        except Exception as exc:
            return {"ok": False, "problems": config_errors(exc)}
        found = await asyncio.to_thread(problems, cfg)
        cases = load_cases(cfg.cases if cfg.cases == "all" else ",".join(cfg.cases)) if not any(
            p["where"] == "cases" for p in found) else []
        jobs = len(cases) * len(cfg.active_conditions) * cfg.runs
        return {"ok": not any(p["level"] == "error" for p in found), "problems": found, "jobs": jobs,
                "ports": {c.id: cfg.gateway_port(c) for c in cfg.active_conditions if c.kind == "masqai"}}

    @app.post("/api/start")
    async def start(body: dict[str, Any]) -> dict[str, Any]:
        if hub.running:
            raise HTTPException(409, "a campaign is already running")
        try:
            cfg = RunConfig.model_validate(body.get("config") or {})
        except Exception as exc:
            raise HTTPException(422, {"problems": config_errors(exc)})
        blocking = [p for p in await asyncio.to_thread(problems, cfg) if p["level"] == "error"]
        if blocking:
            raise HTTPException(422, {"problems": blocking})
        hub.campaign = Campaign(cfg, hub.emit)
        hub.emit({"type": "campaign", "id": hub.campaign.id})
        hub.task = asyncio.create_task(hub.campaign.run())
        return {"id": hub.campaign.id}

    @app.post("/api/stop")
    async def stop() -> dict[str, Any]:
        if not hub.running:
            return {"stopped": False}
        hub.task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(hub.task), 60)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        except Exception:
            pass
        return {"stopped": True}

    @app.get("/api/events")
    async def events(request: Request, since: int = 0) -> StreamingResponse:
        async def stream():
            cursor = max(since, hub.base)
            yield "retry: 1500\n\n"
            while not await request.is_disconnected():
                waiter = hub.changed          # taken before reading, so nothing emitted after is missed
                start = max(cursor, hub.base)
                pending = hub.events[start - hub.base:]
                for event in pending:
                    yield f"id: {event['seq']}\ndata: {json.dumps(event)}\n\n"
                cursor = start + len(pending)
                if cursor < hub.base + len(hub.events):
                    continue
                try:
                    await asyncio.wait_for(waiter.wait(), 15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"cache-control": "no-cache", "x-accel-buffering": "no"})

    def campaign_dir(campaign_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", campaign_id) or campaign_id.startswith("."):
            raise HTTPException(400, "bad campaign id")
        path = CAMPAIGNS / campaign_id
        if not path.is_dir():
            raise HTTPException(404, "no such campaign")
        return path

    @app.get("/api/campaigns/{campaign_id}")
    async def campaign(campaign_id: str) -> dict[str, Any]:
        path = campaign_dir(campaign_id)
        load = lambda name: json.loads((path / name).read_text(encoding="utf-8")) if (path / name).exists() else None
        report = (path / "report.md").read_text(encoding="utf-8") if (path / "report.md").exists() else ""
        return {"id": campaign_id, "config": load("config.json"), "meta": load("meta.json"),
                "results": load("results.json"), "rows": read_rows(path / "runs.jsonl"), "report": report}

    @app.get("/api/campaigns/{campaign_id}/logs/{name}")
    async def campaign_log(campaign_id: str, name: str) -> dict[str, Any]:
        path = campaign_dir(campaign_id) / "logs"
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.log", name) or not (path / name).is_file():
            raise HTTPException(404, "no such log")
        lines = (path / name).read_text(encoding="utf-8", errors="replace").splitlines()
        return {"name": name, "text": "\n".join(lines[-400:]),
                "logs": sorted(p.name for p in path.glob("*.log"))}

    @app.post("/api/campaigns/{campaign_id}/publish")
    async def publish(campaign_id: str) -> dict[str, Any]:
        from .aggregate import site_view
        from .run_eval import WEB_RESULTS
        path = campaign_dir(campaign_id) / "results.json"
        if not path.exists():
            raise HTTPException(404, "this campaign has no results")
        try:
            view = site_view(json.loads(path.read_text(encoding="utf-8")))
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        WEB_RESULTS.write_text(json.dumps(view, indent=2), encoding="utf-8")
        return {"path": str(WEB_RESULTS)}

    @app.post("/api/presets/{name}")
    async def save_preset(name: str, body: dict[str, Any]) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}", name):
            raise HTTPException(400, "preset name: letters, digits, _ and -")
        try:
            cfg = RunConfig.model_validate(body.get("config") or {})
        except Exception as exc:
            raise HTTPException(422, {"problems": config_errors(exc)})
        PRESETS_DIR.mkdir(exist_ok=True)
        (PRESETS_DIR / f"{name}.json").write_text(cfg.model_dump_json(indent=2, exclude_defaults=False), encoding="utf-8")
        return {"saved": name}

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="MasqAI eval GUI")
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    token = secrets.token_urlsafe(24)
    url = f"http://127.0.0.1:{args.port}/#token={token}"
    print(f"\n  MasqAI eval GUI: {url}\n", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    uvicorn.run(create_app(token), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
