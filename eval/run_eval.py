"""Run the eval: every case × condition × run, each in its own Daytona sandbox.

    python -m eval.run_eval --cases all --conditions raw,masqai --runs 10 --concurrency 8

Prerequisites (see eval/README.md): the relay on :8788 started with --eval-model, MasqAI on :8787 using
eval/masqai.eval.json, and DAYTONA_API_KEY. Conditions: `raw` = agent → relay (the untrusted endpoint);
`masqai` = agent → MasqAI → relay. Rows go to eval/out/runs.jsonl (append-only, canary TYPES only).
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from .agent import run_agent
from .cases import Case, files, load_cases, make_canaries, render
from .leaks import leaked
from .sandbox import DaytonaBackend, LocalBackend

OUT = Path(__file__).parent / "out"
RELAY = os.getenv("RELAY_URL", "http://127.0.0.1:8788")
MASQ = os.getenv("MASQ_URL", "http://127.0.0.1:8787")
BASE = {"raw": f"{RELAY}/v1", "masqai": f"{MASQ}/v1"}


async def relay_records(http: httpx.AsyncClient, run_id: str) -> list[dict[str, Any]]:
    response = await http.get(f"{RELAY}/relay/api/requests", params={"tag": run_id}, timeout=30)
    response.raise_for_status()
    return response.json()["requests"]


async def one_run(case: Case, condition: str, backend, http: httpx.AsyncClient) -> dict[str, Any]:
    run_id = f"{case.id}.{condition}.{secrets.token_hex(4)}"
    row: dict[str, Any] = {"run_id": run_id, "case": case.id, "condition": condition, "task_ok": False, "leaked": [],
                           "leaked_count": 0, "canary_count": 0, "relay_requests": 0, "blocked": False, "block_status": None,
                           "prompt_tokens": 0, "completion_tokens": 0, "wall_ms": 0, "llm_ms_p50": None, "turns": 0, "error": None}
    sandbox = await backend.create(run_id)
    canaries = []
    try:
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
        seeded = await sandbox.exec(f"bash {harness}/seed.sh && rm -f {harness}/seed.sh", workdir, env, 120)
        if seeded.exit_code != 0:
            raise RuntimeError(f"seed.sh failed with exit {seeded.exit_code}")
        headers = {"x-masqai-session": run_id,
                   # The relay labels requests by their credential: "relay-direct" = the unprotected baseline.
                   "authorization": "Bearer relay-direct" if condition == "raw" else "Bearer masqai-eval"}
        started = time.monotonic()
        result = await run_agent(http, BASE[condition], f"eval/{run_id}", headers, render(case.task(), values, root),
                                 sandbox, workdir, env)
        row["wall_ms"] = round((time.monotonic() - started) * 1000)
        row["turns"] = result.turns
        row["blocked"], row["block_status"] = result.blocked, result.block_status
        row["error"] = result.error
        row["llm_ms_p50"] = round(statistics.median(result.llm_ms)) if result.llm_ms else None
        # check.sh arrives only now, so the agent could never read the expected answer.
        await sandbox.upload([(f"{harness}/check.sh", render((case.path / "check.sh").read_text(), values, root).encode())])
        checked = await sandbox.exec(f"bash {harness}/check.sh", workdir, env, 60)
        row["task_ok"] = checked.exit_code == 0 and not result.blocked
    except asyncio.CancelledError:
        raise
    except Exception as exc:   # a broken run is reported, not hidden
        row["error"] = f"{exc.__class__.__name__}: {str(exc)[:200]}"
    finally:
        try:
            await sandbox.delete()
        except Exception as exc:
            print(f"warning: could not delete sandbox for {run_id}: {exc.__class__.__name__}", file=sys.stderr)
    records = await relay_records(http, run_id)
    names = leaked(canaries, records)
    usages = [r["usage"] for r in records if isinstance(r.get("usage"), dict)]
    row.update(leaked=names, leaked_count=len(names), relay_requests=len(records),
               prompt_tokens=sum(u.get("prompt_tokens") or u.get("input_tokens") or 0 for u in usages),
               completion_tokens=sum(u.get("completion_tokens") or u.get("output_tokens") or 0 for u in usages))
    return row


async def preflight(http: httpx.AsyncClient, conditions: list[str]) -> None:
    for name, url in (("relay", f"{RELAY}/relay/api/requests?tag=preflight"), ("MasqAI", f"{MASQ}/")):
        if name == "MasqAI" and "masqai" not in conditions:
            continue
        try:
            (await http.get(url, timeout=5)).raise_for_status()
        except Exception as exc:
            raise SystemExit(f"{name} is not reachable at {url} ({exc.__class__.__name__}); see eval/README.md")


async def injection_mode(args: argparse.Namespace) -> int:
    """Run tests/injection through the security model in the eval's MasqAI config."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tests.injection.run_injection import main_async as run_injection
    rows = await run_injection(args.masqai_config, args.runs)
    OUT.mkdir(exist_ok=True)
    (OUT / "injection.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    for row in rows:
        print(f"{row['attack']}: {row['succeeded']}/{row['attempts']} succeeded ({row['blocked']} blocked)")
    print(f"→ {OUT / 'injection.json'} (aggregate picks it up)")
    return 0


async def main_async(args: argparse.Namespace) -> int:
    if args.injection:
        return await injection_mode(args)
    cases = load_cases(args.cases)
    conditions = [c.strip() for c in args.conditions.split(",") if c.strip()]
    unknown = set(conditions) - set(BASE)
    if unknown:
        raise SystemExit(f"unknown condition(s): {', '.join(sorted(unknown))}")
    backend = LocalBackend(trusted_commands=args.self_test) if args.sandbox == "local" else DaytonaBackend()
    OUT.mkdir(exist_ok=True)
    (OUT / "meta.json").write_text(json.dumps({
        "startedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runsPerCase": args.runs, "securityModel": args.security_model, "untrustedModel": args.untrusted_model,
        "agent": "MasqAI eval agent (Chat Completions + bash tool)", "sandbox": backend.name,
        "selfTest": bool(args.self_test),
    }, indent=2), encoding="utf-8")
    semaphore = asyncio.Semaphore(args.concurrency)
    done = failed = 0
    async with httpx.AsyncClient(timeout=httpx.Timeout(300, connect=10)) as http:
        await preflight(http, conditions)

        async def guarded(case: Case, condition: str) -> None:
            nonlocal done, failed
            async with semaphore:
                row = await one_run(case, condition, backend, http)
            with (OUT / "runs.jsonl").open("a", encoding="utf-8") as out:
                out.write(json.dumps(row) + "\n")
            done += 1
            failed += bool(row["error"])
            status = "BLOCKED" if row["blocked"] else ("ok" if row["task_ok"] else "fail")
            print(f"[{done}/{total}] {row['case']:22} {row['condition']:6} task={status:7} leaked={row['leaked'] or '-'}"
                  + (f" error={row['error']}" if row["error"] else ""), flush=True)

        jobs = [(case, condition) for case in cases for condition in conditions for _ in range(args.runs)]
        total = len(jobs)
        tasks = [asyncio.create_task(guarded(case, condition)) for case, condition in jobs]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)   # each run deletes its sandbox in `finally`
            swept = await backend.cleanup()                         # and a label sweep catches the rest
            print(f"\ninterrupted: {done}/{total} runs written; {swept} leftover sandbox(es) deleted", file=sys.stderr)
            return 130
        finally:
            await backend.close()
    print(f"\n{done} runs → {OUT / 'runs.jsonl'}" + (f" ({failed} with errors)" if failed else ""))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="MasqAI eval harness (Daytona)")
    parser.add_argument("--cases", default="all", help="comma-separated case ids, or all")
    parser.add_argument("--conditions", default="raw,masqai")
    parser.add_argument("--runs", type=int, default=10, help="runs per case per condition")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--untrusted-model", default=os.getenv("EVAL_MODEL", "unknown"), help="the model the relay forwards to (relay --eval-model)")
    parser.add_argument("--security-model", default=os.getenv("EVAL_SECURITY_MODEL", "qwen2.5:7b (local)"))
    parser.add_argument("--sandbox", choices=["daytona", "local"], default="daytona")
    parser.add_argument("--self-test", action="store_true", help="with --sandbox local: commands come from eval/fake_llm.py only")
    parser.add_argument("--injection", action="store_true", help="run tests/injection through the security model instead")
    parser.add_argument("--masqai-config", default=str(Path(__file__).parent / "masqai.eval.json"))
    args = parser.parse_args()

    async def runner() -> int:
        task = asyncio.current_task()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, task.cancel)
        try:
            return await main_async(args)
        except asyncio.CancelledError:
            return 130

    sys.exit(asyncio.run(runner()))


if __name__ == "__main__":
    main()
