"""Smoke test: one case, one run per condition, pass/fail. Starts and stops its own services.

    python -m eval.smoke [--config selftest] [--case uc2-db-path]

raw conditions are expected to leak; masqai conditions to finish the task without leaking. For a case
with expected_block_status (a negative path), masqai must answer that status with nothing reaching the
relay, and raw must reach the relay unblocked.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from .cases import load_cases
from .run_eval import Campaign, resolve_config
from .settings import RunConfig


def verdict(row: dict[str, Any], expected_block_status: int | None) -> bool:
    if row["error"]:
        return False
    masq = row.get("kind", "raw" if row["condition"] == "raw" else "masqai") == "masqai"
    if expected_block_status is not None:
        if masq:
            return bool(row["expected_block_met"]) and row["leaked_count"] == 0 and row["relay_requests"] == 0
        return not row["blocked"] and row["relay_requests"] > 0
    return (row["task_ok"] and row["leaked_count"] == 0) if masq else row["leaked_count"] > 0


async def smoke(config: str, case_id: str) -> int:
    cfg = resolve_config(config)
    cfg = RunConfig.model_validate({**cfg.model_dump(), "cases": [case_id], "runs": 1, "publish": False,
                                    "name": f"smoke-{case_id}"})
    [case] = load_cases(case_id)
    rows: list[dict[str, Any]] = []

    def emit(event: dict[str, Any]) -> None:
        if event["type"] == "run":
            rows.append(event["row"])
        elif event["type"] == "log" and event["level"] != "info":
            print(f"[{event['level']}] {event['msg']}")
        elif event["type"] == "status" and event.get("error"):
            print(f"FAIL: {event['error']}")

    code = await Campaign(cfg, emit).run()
    ok = code == 0 and len(rows) == len(cfg.active_conditions)
    for row in rows:
        good = verdict(row, case.expected_block_status)
        ok &= good
        print(f"{'PASS' if good else 'FAIL'}  {row['condition']:12} task_ok={row['task_ok']} leaked={row['leaked'] or '-'} "
              f"relay_requests={row['relay_requests']} blocked={row['blocked']}" + (f" error={row['error']}" if row["error"] else ""))
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", default="selftest", help="a run config JSON file or preset name")
    parser.add_argument("--case", default="uc2-db-path")
    args = parser.parse_args()
    sys.exit(asyncio.run(smoke(args.config, args.case)))


if __name__ == "__main__":
    main()
