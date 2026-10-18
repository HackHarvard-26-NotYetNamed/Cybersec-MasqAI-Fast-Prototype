"""Opt-in, bounded measurements of OpenRouter management-key behavior.

The management credential is loaded from OPENROUTER_MANAGEMENT_KEY in ormanagement.env (or the process environment). This script
never prints credentials or inference keys. It is intentionally excluded from CI.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from masqai.custody import CustodyError
from masqai.custody.openrouter import OpenRouterKeys, probe_key

ENV_KEY = "OPENROUTER_MANAGEMENT_KEY"
ENV_FILE = "ormanagement.env"
MAX_SAMPLES = 20
MAX_RATE_MINUTES = 5
MIN_RATE_INTERVAL = 10
MAX_LIMIT_USD = 0.10


def _args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Dedicated, budgeted OpenRouter workspace UUID")
    parser.add_argument("--execute", action="store_true", help="Actually create and delete low-limit probe keys")
    parser.add_argument("--check-cleanup", action="store_true", help="Read-only check for leftover enigma-probe keys")
    parser.add_argument("--samples", type=int, default=20, help=f"Create/revoke samples (1-{MAX_SAMPLES}; default 20)")
    parser.add_argument("--rate-minutes", type=int, default=5, help=f"Read-only rate observation (0-{MAX_RATE_MINUTES}; default 5)")
    parser.add_argument("--rate-interval", type=int, default=10, help=f"Seconds between mint requests ({MIN_RATE_INTERVAL}-{MIN_RATE_INTERVAL}; default 10)")
    parser.add_argument("--confirm-budget", action="store_true", help="Confirm workspace budget and account spend limits were reviewed")
    return parser.parse_args(argv)


def _validate(args: argparse.Namespace) -> None:
    from masqai.custody.openrouter import check_workspace

    check_workspace(args.workspace)
    if not 1 <= args.samples <= MAX_SAMPLES:
        raise ValueError(f"--samples must be between 1 and {MAX_SAMPLES}")
    if not 0 <= args.rate_minutes <= MAX_RATE_MINUTES:
        raise ValueError(f"--rate-minutes must be between 0 and {MAX_RATE_MINUTES}")
    if args.rate_interval != MIN_RATE_INTERVAL:
        raise ValueError(f"--rate-interval must be exactly {MIN_RATE_INTERVAL} seconds")
    if args.execute and not args.confirm_budget:
        raise ValueError("live execution requires --confirm-budget")


def _load_management_key(env_file: str = ENV_FILE) -> str:
    """Load only the named assignment; never parse or print unrelated environment values."""
    injected = os.environ.get(ENV_KEY, "")
    if injected:
        return injected
    try:
        lines = open(env_file, encoding="utf-8").read().splitlines()
    except FileNotFoundError:
        return ""
    for line in lines:
        match = re.fullmatch(r"\s*OPENROUTER_MANAGEMENT_KEY\s*=\s*(.*?)\s*", line)
        if not match:
            continue
        value = match.group(1)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        return value
    return ""


async def _until(key: str, *, expected: bool, timeout_s: float = 60.0) -> float | None:
    start = time.monotonic()
    while time.monotonic() - start <= timeout_s:
        try:
            accepted = await probe_key(key)
        except CustodyError:
            await asyncio.sleep(1)
            continue
        if accepted is expected:
            return time.monotonic() - start
        await asyncio.sleep(1)
    return None


async def run(args: argparse.Namespace, management_key: str) -> dict[str, Any]:
    keys = OpenRouterKeys(management_key, timeout=20)
    result: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "workspace_id": args.workspace,
        "key_limit_usd": MAX_LIMIT_USD,
        "samples": [],
        "rate_observation": [],
        "patch_expires_at": "not tested: OpenRouter does not expose expires_at as a patchable key field",
    }
    probe_hashes: list[str] = []
    try:
        current = await keys.current()
        if current.get("is_management_key") is not True:
            raise ValueError("injected credential is not recognized as a management key")
        await keys.workspace(args.workspace)
        budgets = await keys.budgets(args.workspace)
        if not budgets:
            raise ValueError("workspace has no configured budget")
        result["management_key_valid"] = True
        result["workspace_budget_present"] = True
        if args.check_cleanup:
            records = await keys.list(workspace_id=args.workspace, include_disabled=True)
            result["probe_named_keys_remaining"] = sum(
                isinstance(row.get("name"), str) and row["name"].startswith("enigma-probe-") for row in records
            )
            return result
        if not args.execute:
            return result

        for index in range(args.samples):
            name = f"enigma-probe-{secrets.token_hex(6)}-{index:02d}"
            created_at = time.monotonic()
            payload = await keys.create(
                name=name,
                workspace_id=args.workspace,
                limit_usd=MAX_LIMIT_USD,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
            )
            data = payload["data"]
            key = payload["key"]
            key_hash = data["hash"]
            probe_hashes.append(key_hash)
            ready_delay = await _until(key, expected=True)
            deleted_at = time.monotonic()
            await keys.delete(key_hash)
            dead_delay = await _until(key, expected=False)
            result["samples"].append({
                "create_to_accepted_s": round(ready_delay, 3) if ready_delay is not None else None,
                "delete_to_rejected_s": round(dead_delay, 3) if dead_delay is not None else None,
                "management_create_s": round(deleted_at - created_at, 3),
            })
            key = ""

        interval = args.rate_interval
        rate_start = time.monotonic()
        rate_end = rate_start + args.rate_minutes * 60
        while time.monotonic() < rate_end:
            tick = time.monotonic()
            rate_name = f"enigma-probe-rate-{secrets.token_hex(6)}"
            rate_hash: str | None = None
            try:
                payload = await keys.create(
                    name=rate_name,
                    workspace_id=args.workspace,
                    limit_usd=MAX_LIMIT_USD,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
                )
                rate_hash = payload["data"]["hash"]
                probe_hashes.append(rate_hash)
                result["rate_observation"].append({"elapsed_s": round(tick - rate_start, 2), "status": "ok"})
            except CustodyError as exc:
                from masqai.custody import RateLimited
                if isinstance(exc, RateLimited):
                    result["rate_observation"].append({"elapsed_s": round(tick - rate_start, 2), "status": "429"})
                    break
                raise
            if rate_hash is not None:
                try:
                    await keys.delete(rate_hash)
                    probe_hashes.remove(rate_hash)
                except CustodyError:
                    pass
            await asyncio.sleep(min(interval, max(0, rate_end - time.monotonic())))
        return result
    finally:
        for key_hash in probe_hashes:
            try:
                await keys.delete(key_hash)
            except CustodyError:
                pass
        await keys.aclose()


def main(argv: list[str] | None = None) -> int:
    args = _args(argv)
    try:
        _validate(args)
        credential = _load_management_key()
        if not credential:
            raise ValueError(f"{ENV_KEY} is required")
        if args.execute:
            rate_cap = args.rate_minutes * 60 // args.rate_interval
            total_cap = args.samples + rate_cap
            print(f"Live probe: up to {total_cap} keys at ${MAX_LIMIT_USD:.2f} each, including the rate phase.", file=sys.stderr)
            print("Confirm this is a dedicated workspace with a reviewed budget and a disposable management key.", file=sys.stderr)
        report = asyncio.run(run(args, credential))
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (ValueError, CustodyError) as exc:
        print(f"Probe stopped: {exc}", file=sys.stderr)
        return 2
    finally:
        credential = ""


if __name__ == "__main__":
    raise SystemExit(main())
