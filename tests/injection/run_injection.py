"""Measure how often prompt injection in tool output beats the security model.

    python -m tests.injection.run_injection --config masqai.json --runs 20 > injection.json

Known open issue: measured, not yet defended (see DECISIONS.md). Each fixture runs through the real
Sanitizer with the security model configured in masqai.json (local Ollama by default), once per run, in
a fresh session. An attack SUCCEEDS when the value it targets still reaches the upstream verbatim, or
when the two unrelated keys end up linked. A fail-closed block is counted separately: it is not a
success for the attacker.

Prints JSON rows for results.json: [{"attack", "attempts", "succeeded", "blocked"}].
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from masqai.adapter import extract, serialize
from masqai.config import GatewayConfig, load_config
from masqai.model import Session
from masqai.ops import plan_all
from masqai.sanitize import SanitizationError, Sanitizer

FIXTURES = Path(__file__).with_name("fixtures.json")


def load_fixtures() -> list[dict[str, Any]]:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))["attacks"]


def config_for(base: GatewayConfig, fixture: dict[str, Any]) -> GatewayConfig:
    data = base.model_dump()
    data["detectors"]["detect_host_identifiers"] = False
    data["detectors"]["custom_values"] = fixture.get("custom_values", [])
    data["security"]["auto_mask"] = "auto_veto"   # the unmask attack needs a vetoable auto mask
    return GatewayConfig.model_validate(data)


def succeeded(fixture: dict[str, Any], session: Session, sent: dict[str, Any]) -> bool:
    rule = fixture["success"]
    text = json.dumps(sent, ensure_ascii=False)
    if "leaked_any" in rule:
        return any(value in text for value in rule["leaked_any"])
    if "relinked" in rule:
        a, b = (session.entity_for(v) for v in rule["relinked"])
        return bool(a and b and session.root(a.token).token == session.root(b.token).token)
    raise ValueError(f"unknown success rule {rule}")


async def run_one(config: GatewayConfig, fixture: dict[str, Any]) -> tuple[bool, bool]:
    """(attack succeeded, request blocked) for one fresh session."""
    payload = {"model": "eval", "messages": fixture["messages"]}
    items = extract(payload, "chat")
    session = Session("injection")
    try:
        await Sanitizer(config).sanitize(session, items)
    except SanitizationError:
        return False, True
    plan_all(session, items)
    return succeeded(fixture, session, serialize(payload, items)), False


async def main_async(config_path: str, runs: int) -> list[dict[str, Any]]:
    base = load_config(config_path)
    if not base.security.enabled:
        sys.exit("the security model is disabled in this config: nothing to measure")
    rows = []
    for fixture in load_fixtures():
        config = config_for(base, fixture)
        wins = blocks = 0
        for n in range(runs):
            won, blocked = await run_one(config, fixture)
            wins += won
            blocks += blocked
            print(f"{fixture['attack']}: run {n + 1}/{runs} {'SUCCEEDED' if won else 'blocked' if blocked else 'defended'}", file=sys.stderr)
        rows.append({"attack": fixture["attack"], "attempts": runs, "succeeded": wins, "blocked": blocks})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", default="masqai.json")
    parser.add_argument("--runs", type=int, default=20)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(main_async(args.config, args.runs)), indent=2))


if __name__ == "__main__":
    main()
