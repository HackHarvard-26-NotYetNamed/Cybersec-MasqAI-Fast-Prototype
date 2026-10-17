"""Quick security-model check, no Daytona or upstream key needed.

    python -m eval.model_check [--config eval/masqai.eval.json] [--runs 3] [--cases all]

For each case, builds the context an agent would send after reading the case's seeded files (each file
as a tool result, plus the env dump for uc1 and the git log for uc5), with fresh canaries, and runs it
through the real Sanitizer and security model. Reports per case: canary recall (canaries kept out of the
outbound payload, by the eval's leak rule), block rate (fail closed), latency per sanitize pass, and how
many security-model operations were accepted, rejected, or needed the correction round.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from masqai.adapter import extract, serialize  # noqa: E402
from masqai.config import load_config  # noqa: E402
from masqai.model import Session  # noqa: E402
from masqai.sanitize import SanitizationError, Sanitizer  # noqa: E402
from masqai.trace import Trace  # noqa: E402

from .agent import SYSTEM  # noqa: E402
from .cases import Case, files, load_cases, make_canaries, render  # noqa: E402
from .leaks import leaked  # noqa: E402

ROOT = "/tmp/masq"


def context(case: Case, values: dict[str, str]) -> list[dict[str, Any]]:
    """Chat messages as the agent would send them after reading the seeded files."""
    outputs: list[tuple[str, str]] = []
    workdir = render(case.workdir, values, ROOT)
    if case.env:
        env = {k: render(v, values, ROOT) for k, v in case.env.items()}
        env |= {"PATH": "/usr/local/bin:/usr/bin:/bin", "PWD": workdir, "SHLVL": "1"}
        outputs.append(("env | sort", "\n".join(f"{k}={v}" for k, v in sorted(env.items()))))
    for rel, data in files(case):
        outputs.append((f"cat {rel}", render(data.decode("utf-8"), values, ROOT)))
    if case.id == "uc5-identity":
        outputs.append(("git log -1 -- bot/standup.py", render(
            "commit 9c41e2a7b3d0\nAuthor: {{CANARY_NAME}} <{{CANARY_EMAIL}}>\nDate:   Thu Oct 16 21:14:02 2026 -0400\n\n"
            "    standup: send the summary to my own chat while I test (ping {{CANARY_HANDLE}} if this breaks)", values, ROOT)))
    messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM},
                                      {"role": "user", "content": render(case.task(), values, ROOT)}]
    for n, (command, output) in enumerate(outputs):
        call_id = f"call_{n}"
        messages.append({"role": "assistant", "content": None, "tool_calls": [
            {"id": call_id, "type": "function", "function": {"name": "bash", "arguments": json.dumps({"command": command})}}]})
        messages.append({"role": "tool", "tool_call_id": call_id, "content": f"exit 0\n{output}"})
    return messages


async def one(config, case: Case) -> dict[str, Any]:
    canaries = make_canaries(case, ROOT)
    values = {c.name: c.value for c in canaries}
    payload = {"model": "eval/check", "messages": context(case, values)}
    items = extract(payload, "chat")
    session, trace = Session("check"), Trace("check", "/check")
    started = time.monotonic()
    blocked, reason = False, None
    try:
        await Sanitizer(config).sanitize(session, items, trace)
    except SanitizationError as exc:
        blocked, reason = True, exc.reason
    elapsed = (time.monotonic() - started) * 1000
    attempts = (trace.data.get("security") or {}).get("attempts", [])
    results = [r for a in attempts for r in a.get("results", [])]
    scanned = [c for c in canaries if c.scan]
    names = [] if blocked else leaked(canaries, [{"body": serialize(payload, items)}])
    return {"blocked": blocked, "reason": reason, "ms": elapsed, "canaries": len(scanned), "leaked": names,
            "accepted": sum(r["ok"] for r in results), "rejected": sum(not r["ok"] for r in results),
            "corrected": len(attempts) > 1,
            # Prompt tokens per call: a value stuck at the server's context window means Ollama truncated the input.
            "prompt_tokens": max(((a.get("usage") or {}).get("prompt_tokens") or 0) for a in attempts) if attempts else 0}


async def main_async(config_path: str, runs: int, selection: str) -> None:
    config = load_config(config_path)
    print(f"security model: {config.security.model} at {config.provider(config.security.provider).base_url} · {runs} runs per case\n")
    header = f"{'case':22} {'recall':>7} {'blocked':>8} {'p50 ms':>8} {'max ms':>8} {'ops ok':>7} {'ops ✗':>6} {'corrected':>10} {'max ctx':>8}  missed (types)"
    print(header + "\n" + "-" * len(header))
    totals = {"canaries": 0, "kept": 0, "blocked": 0, "runs": 0}
    for case in load_cases(selection):
        rows = []
        for _ in range(runs):
            rows.append(await one(config, case))
        done = [r for r in rows if not r["blocked"]]
        canaries = sum(r["canaries"] for r in done)
        kept = canaries - sum(len(r["leaked"]) for r in done)
        missed = sorted({n for r in done for n in r["leaked"]})
        totals["canaries"] += canaries
        totals["kept"] += kept
        totals["blocked"] += len(rows) - len(done)
        totals["runs"] += len(rows)
        print(f"{case.id:22} {kept / canaries if canaries else float('nan'):>7.0%} {len(rows) - len(done):>4}/{len(rows):<3} "
              f"{statistics.median(r['ms'] for r in rows):>8.0f} {max(r['ms'] for r in rows):>8.0f} "
              f"{sum(r['accepted'] for r in rows):>7} {sum(r['rejected'] for r in rows):>6} "
              f"{sum(r['corrected'] for r in rows):>6}/{len(rows):<3} {max(r['prompt_tokens'] for r in rows):>8}  {', '.join(missed) or '-'}"
              + (f"  [{', '.join(sorted({r['reason'] for r in rows if r['reason']}))}]" if len(done) < len(rows) else ""), flush=True)
    recall = totals["kept"] / totals["canaries"] if totals["canaries"] else float("nan")
    print(f"\noverall: canary recall {recall:.0%} (of runs that weren't blocked) · blocked {totals['blocked']}/{totals['runs']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", default=str(Path(__file__).parent / "masqai.eval.json"))
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--cases", default="all")
    args = parser.parse_args()
    asyncio.run(main_async(args.config, args.runs, args.cases))


if __name__ == "__main__":
    main()
