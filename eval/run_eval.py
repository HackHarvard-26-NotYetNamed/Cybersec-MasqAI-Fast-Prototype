"""Run one eval campaign: every case × condition × run, each in its own sandbox.

    python -m eval.run_eval --config selftest                  # a preset name from eval/presets/
    python -m eval.run_eval --config my-run.json --runs 5 --cases uc2-db-path,uc3-secret-roundtrip
    python -m eval.gui                                         # the same, from a browser

The campaign starts and stops its own services (relay, one MasqAI gateway per masqai condition, the fake
models for a self-test; see services.py) and writes everything to eval/out/campaigns/<id>/:
config.json, meta.json, runs.jsonl (canary TYPES only), results.json, report.md, logs/, gateways/.
Conditions are listed in the config: `raw(untrusted)` and any number of `masqai(security, untrusted)`.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import signal
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

from .agent import AgentLimits, run_agent
from .cases import Case, files, load_cases, make_canaries, render
from .leaks import leaked
from .sandbox import DaytonaBackend, LocalBackend
from .settings import PRESETS_DIR, ConditionSpec, RunConfig, load_run_config, problems

OUT = Path(__file__).parent / "out"
CAMPAIGNS = OUT / "campaigns"
WEB_RESULTS = Path(__file__).resolve().parent.parent / "web" / "public" / "data" / "results.json"


async def relay_records(http: httpx.AsyncClient, relay_url: str, run_id: str) -> list[dict[str, Any]]:
    response = await http.get(f"{relay_url}/relay/api/requests", params={"tag": run_id}, timeout=30)
    response.raise_for_status()
    return response.json()["requests"]


def base_url(cfg: RunConfig, condition: ConditionSpec) -> str:
    return f"{cfg.relay_url}/v1" if condition.kind == "raw" else f"http://127.0.0.1:{cfg.gateway_port(condition)}/v1"


async def one_run(case: Case, condition: ConditionSpec, cfg: RunConfig, backend, http: httpx.AsyncClient) -> dict[str, Any]:
    run_id = f"{case.id}.{condition.id}.{secrets.token_hex(4)}"
    row: dict[str, Any] = {"run_id": run_id, "case": case.id, "condition": condition.id, "kind": condition.kind,
                           "untrusted": condition.untrusted,
                           "security_model": condition.security.model if condition.security else None,
                           "task_ok": False, "expected_block_status": case.expected_block_status, "expected_block_met": False,
                           "leaked": [], "leaked_count": 0, "canary_count": 0, "relay_requests": 0, "blocked": False,
                           "block_status": None, "tool_calls_blocked": 0, "rate_limited": 0, "prompt_tokens": 0,
                           "completion_tokens": 0, "wall_ms": 0, "llm_ms_p50": None, "turns": 0, "commands": 0, "error": None}
    started = time.monotonic()
    sandbox = None
    canaries = []
    try:
        sandbox = await backend.create(run_id)
        root = sandbox.root
        canaries = make_canaries(case, root)
        values = {c.name: c.value for c in canaries}
        row["canary_count"] = sum(1 for c in canaries if c.scan)
        workdir = render(case.workdir, values, root)
        harness = f"{root}/.harness"
        env = {k: render(v, values, root) for k, v in case.env.items()}
        uploads = [(f"{workdir}/{rel}", render(data.decode("utf-8"), values, root).encode()) for rel, data in files(case)]
        uploads.append((f"{harness}/seed.sh", render((case.path / "seed.sh").read_text(), values, root).encode()))
        await sandbox.upload(uploads)
        seeded = await sandbox.exec(f"bash {harness}/seed.sh && rm -f {harness}/seed.sh", workdir, env, cfg.harness.seed_timeout_s)
        if seeded.exit_code != 0:
            raise RuntimeError(f"seed.sh failed with exit {seeded.exit_code}: {seeded.output.strip()[-160:]}")
        headers = {"x-masqai-session": run_id,
                   # The relay labels requests by their credential: "relay-direct" = the unprotected baseline.
                   "authorization": "Bearer relay-direct" if condition.kind == "raw" else "Bearer masqai-eval"}
        a = cfg.agent
        limits = AgentLimits(a.max_turns, a.command_timeout_s, a.run_timeout_s, a.max_tokens, a.temperature, a.rate_limit_retries)
        # The untrusted model rides in the model name, so one relay serves every condition.
        result = await run_agent(http, base_url(cfg, condition), f"eval/{run_id}/{condition.untrusted}", headers,
                                 render(case.task(), values, root), sandbox, workdir, env, a.stream, limits)
        row.update(turns=result.turns, commands=result.commands, blocked=result.blocked, block_status=result.block_status,
                   tool_calls_blocked=result.tool_calls_blocked, rate_limited=result.rate_limited, error=result.error,
                   llm_ms_p50=round(statistics.median(result.llm_ms)) if result.llm_ms else None)
        row["expected_block_met"] = (case.expected_block_status is not None and condition.kind == "masqai"
                                     and result.blocked and result.block_status == case.expected_block_status
                                     and result.error is None)
        # check.sh arrives only now, so the agent could never read the expected answer.
        await sandbox.upload([(f"{harness}/check.sh", render((case.path / "check.sh").read_text(), values, root).encode())])
        checked = await sandbox.exec(f"bash {harness}/check.sh", workdir, env, cfg.harness.check_timeout_s)
        row["task_ok"] = checked.exit_code == 0 and not result.blocked
    except asyncio.CancelledError:
        raise
    except Exception as exc:   # a broken run is reported, not hidden
        row["error"] = f"{exc.__class__.__name__}: {str(exc)[:240]}"
    finally:
        row["wall_ms"] = round((time.monotonic() - started) * 1000)
        if sandbox is not None:
            try:
                await sandbox.delete()
            except Exception as exc:
                print(f"warning: could not delete sandbox for {run_id}: {exc.__class__.__name__}", file=sys.stderr)
    try:
        records = await relay_records(http, cfg.relay_url, run_id)
    except Exception as exc:
        row["error"] = row["error"] or f"relay log unavailable: {exc.__class__.__name__}"
        return row
    names = leaked(canaries, records)
    usages = [r["usage"] for r in records if isinstance(r.get("usage"), dict)]
    row.update(leaked=names, leaked_count=len(names), relay_requests=len(records),
               prompt_tokens=sum(u.get("prompt_tokens") or u.get("input_tokens") or 0 for u in usages),
               completion_tokens=sum(u.get("completion_tokens") or u.get("output_tokens") or 0 for u in usages))
    return row


@dataclass
class Campaign:
    """A running or finished campaign. `emit` receives {"type": ..., ...} events (the GUI streams them)."""
    cfg: RunConfig
    emit: Callable[[dict[str, Any]], None] = lambda event: None
    id: str = ""
    dir: Path = field(default_factory=Path)
    total: int = 0
    done: int = 0
    status: str = "pending"     # pending → starting → running → finished | failed | cancelled
    error: str | None = None
    results: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + self.cfg.name
        self.dir = CAMPAIGNS / self.id

    def log(self, message: str, level: str = "info") -> None:
        self.emit({"type": "log", "level": level, "t": time.time(), "msg": message})

    def _status(self, status: str, error: str | None = None) -> None:
        self.status, self.error = status, error
        self.emit({"type": "status", "status": status, "error": error, "done": self.done, "total": self.total})

    async def run(self) -> int:
        from .aggregate import aggregate, report
        from .services import Services
        cfg = self.cfg
        cases = load_cases(cfg.cases if cfg.cases == "all" else ",".join(cfg.cases))
        conditions = cfg.active_conditions
        jobs = [(case, condition) for _ in range(cfg.runs) for case in cases for condition in conditions]
        self.total = len(jobs)
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "config.json").write_text(cfg.model_dump_json(indent=2), encoding="utf-8")
        meta = {
            "campaign": self.id, "startedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "runsPerCase": cfg.runs, "sandbox": "local" if cfg.sandbox == "local" else "Daytona",
            "agent": "MasqAI eval agent (Chat Completions + bash tool" + (", streaming)" if cfg.agent.stream else ")"),
            "stream": cfg.agent.stream, "selfTest": cfg.self_test,
            "conditions": [{"id": c.id, "kind": c.kind, "label": c.label, "untrusted": c.untrusted,
                            "security": c.security.model_dump() if c.security else None} for c in conditions],
            "cases": [c.id for c in cases],
        }
        (self.dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self.emit({"type": "plan", "id": self.id, "total": self.total, "cases": [c.id for c in cases],
                   "conditions": meta["conditions"]})
        blocking = [p for p in problems(cfg) if p["level"] == "error"]
        if blocking:
            self._status("failed", "; ".join(f"{p['where']}: {p['msg']}" for p in blocking))
            return 2
        self._status("starting")
        services = Services(cfg, self.dir, self.log)
        backend = None
        rows: list[dict[str, Any]] = []
        code = 0
        try:
            await services.start()
            if cfg.sandbox == "local":
                if cfg.allow_local_untrusted and not cfg.self_test:
                    os.environ["MASQAI_ALLOW_LOCAL_SANDBOX"] = "1"
                backend = LocalBackend(trusted_commands=cfg.self_test)
            else:
                backend = DaytonaBackend()
            self._status("running")
            semaphore = asyncio.Semaphore(cfg.concurrency)
            timeout = httpx.Timeout(cfg.agent.http_timeout_s, connect=10)
            async with httpx.AsyncClient(timeout=timeout) as http:

                async def guarded(index: int, case: Case, condition: ConditionSpec) -> None:
                    async with semaphore:
                        self.emit({"type": "run_start", "index": index, "case": case.id, "condition": condition.id})
                        row = await one_run(case, condition, cfg, backend, http)
                    rows.append(row)
                    with (self.dir / "runs.jsonl").open("a", encoding="utf-8") as out:
                        out.write(json.dumps(row) + "\n")
                    self.done += 1
                    self.emit({"type": "run", "index": index, "row": row, "done": self.done, "total": self.total})

                tasks = [asyncio.create_task(guarded(i, case, cond)) for i, (case, cond) in enumerate(jobs)]
                try:
                    await asyncio.gather(*tasks)
                except BaseException:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)   # each run deletes its sandbox in `finally`
                    raise
        except asyncio.CancelledError:
            swept = await backend.cleanup() if backend else 0
            self.log(f"cancelled: {self.done}/{self.total} runs written; {swept} leftover sandbox(es) deleted", "warn")
            self._status("cancelled")
            code = 130
        except BaseException as exc:   # SystemExit from a backend, a service that would not start, ...
            self.log(f"{exc.__class__.__name__}: {exc}", "error")
            self._status("failed", f"{exc.__class__.__name__}: {str(exc)[:600]}")
            code = 1
        finally:
            if backend:
                await backend.close()
            await asyncio.to_thread(services.stop)
        if rows:
            self.results = aggregate(rows, meta, [])
            (self.dir / "results.json").write_text(json.dumps(self.results, indent=2), encoding="utf-8")
            (self.dir / "report.md").write_text(report(rows, self.results), encoding="utf-8")
            self.emit({"type": "results", "results": self.results})
            if cfg.publish and code == 0:
                try:
                    self.publish()
                except ValueError as exc:
                    self.log(f"not published: {exc}", "warn")
        if code == 0:
            failed = sum(bool(r["error"]) for r in rows)
            self.log(f"{self.done} runs → {self.dir}" + (f" ({failed} with errors)" if failed else ""))
            self._status("finished")
        return code

    def publish(self) -> Path:
        from .aggregate import site_view
        if not self.results:
            raise ValueError("no results to publish yet")
        WEB_RESULTS.parent.mkdir(parents=True, exist_ok=True)
        WEB_RESULTS.write_text(json.dumps(site_view(self.results), indent=2), encoding="utf-8")
        self.log(f"published → {WEB_RESULTS}")
        return WEB_RESULTS


def resolve_config(name_or_path: str) -> RunConfig:
    path = Path(name_or_path)
    if not path.exists():
        path = PRESETS_DIR / f"{name_or_path.removesuffix('.json')}.json"
    if not path.exists():
        names = ", ".join(p.stem for p in sorted(PRESETS_DIR.glob("*.json")))
        raise SystemExit(f"no config file or preset {name_or_path!r} (presets: {names})")
    return load_run_config(path)


async def injection_mode(args: argparse.Namespace) -> int:
    """Run tests/injection through the security model in a MasqAI config."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tests.injection.run_injection import main_async as run_injection
    rows = await run_injection(args.masqai_config, args.runs or 20)
    OUT.mkdir(exist_ok=True)
    (OUT / "injection.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    for row in rows:
        print(f"{row['attack']}: {row['succeeded']}/{row['attempts']} succeeded ({row['blocked']} blocked)")
    print(f"→ {OUT / 'injection.json'}")
    return 0


def print_event(event: dict[str, Any]) -> None:
    kind = event["type"]
    if kind == "log":
        print(f"[{event['level']}] {event['msg']}", flush=True)
    elif kind == "status":
        print(f"== {event['status']}" + (f": {event['error']}" if event.get("error") else ""), flush=True)
    elif kind == "run":
        r = event["row"]
        status = "BLOCKED" if r["blocked"] else ("ok" if r["task_ok"] else "fail")
        print(f"[{event['done']}/{event['total']}] {r['case']:22} {r['condition']:12} task={status:7} "
              f"leaked={r['leaked'] or '-'}" + (f" error={r['error']}" if r["error"] else ""), flush=True)


async def main_async(args: argparse.Namespace) -> int:
    if args.injection:
        return await injection_mode(args)
    cfg = resolve_config(args.config)
    overrides = {k: v for k, v in {"runs": args.runs, "concurrency": args.concurrency, "publish": args.publish or None}.items() if v}
    if args.cases:
        overrides["cases"] = "all" if args.cases == "all" else [c.strip() for c in args.cases.split(",") if c.strip()]
    if overrides:
        cfg = RunConfig.model_validate({**cfg.model_dump(), **overrides})
    for p in problems(cfg):
        print(f"{p['level']}: {p['where']}: {p['msg']}", file=sys.stderr)
    campaign = Campaign(cfg, print_event)
    return await campaign.run()


def main() -> None:
    parser = argparse.ArgumentParser(description="MasqAI eval harness")
    parser.add_argument("--config", default="selftest", help="a run config JSON file or a preset name (eval/presets/)")
    parser.add_argument("--cases", default=None, help="override: comma-separated case ids, or all")
    parser.add_argument("--runs", type=int, default=None, help="override: runs per case per condition")
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--publish", action="store_true", help="copy results.json to web/public/data/ when done")
    parser.add_argument("--injection", action="store_true", help="run tests/injection through a security model instead")
    parser.add_argument("--masqai-config", default=str(Path(__file__).parent / "masqai.eval.json"))
    args = parser.parse_args()

    async def runner() -> int:
        task = asyncio.current_task()
        loop = asyncio.get_running_loop()
        previous: dict[signal.Signals, Any] = {}

        def cancel() -> None:
            loop.call_soon_threadsafe(task.cancel)

        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, cancel)
                except NotImplementedError:   # Windows' default event loop
                    previous[sig] = signal.getsignal(sig)
                    signal.signal(sig, lambda _s, _f: cancel())
            return await main_async(args)
        except asyncio.CancelledError:
            return 130
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)

    sys.exit(asyncio.run(runner()))


if __name__ == "__main__":
    main()
