"""Smoke test: one case, one run per condition, pass/fail. Under 3 minutes.

    python -m eval.smoke [--case uc2-db-path] [--sandbox daytona|local --self-test]
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time

import httpx

from .cases import load_cases
from .run_eval import one_run, preflight
from .sandbox import DaytonaBackend, LocalBackend


async def smoke(case_id: str, sandbox: str, self_test: bool) -> int:
    [case] = load_cases(case_id)
    backend = LocalBackend(trusted_commands=self_test) if sandbox == "local" else DaytonaBackend()
    ok = True
    started = time.monotonic()
    async with httpx.AsyncClient(timeout=httpx.Timeout(300, connect=10)) as http:
        await preflight(http, ["raw", "masqai"])
        try:
            for condition in ("raw", "masqai"):
                row = await one_run(case, condition, backend, http)
                # raw is expected to leak; masqai is expected to finish the task without leaking.
                expect = row["leaked_count"] > 0 if condition == "raw" else (row["task_ok"] and row["leaked_count"] == 0)
                ok &= bool(expect) and not row["error"]
                print(f"{'PASS' if expect and not row['error'] else 'FAIL'}  {condition:6} task_ok={row['task_ok']} leaked={row['leaked'] or '-'} "
                      f"relay_requests={row['relay_requests']} blocked={row['blocked']} tool_calls_blocked={row.get('tool_calls_blocked', 0)}" + (f" error={row['error']}" if row["error"] else ""))
        finally:
            await backend.close()
    print(f"{'PASS' if ok else 'FAIL'} in {time.monotonic() - started:.0f} s ({backend.name})")
    return 0 if ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--case", default="uc2-db-path")
    parser.add_argument("--sandbox", choices=["daytona", "local"], default="daytona")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sys.exit(asyncio.run(smoke(args.case, args.sandbox, args.self_test)))


if __name__ == "__main__":
    main()
