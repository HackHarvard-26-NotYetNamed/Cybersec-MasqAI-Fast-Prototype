"""Small helpers for the playground. Talks to the running MasqAI (:8787) and relay (:8788).

    python playground/tools.py status            # what is running, which security model is active
    python playground/tools.py break-security    # point the security model at a model that does not exist (UC6)
    python playground/tools.py restore-security  # undo break-security
    python playground/tools.py detector-only     # security.enabled = false (regex + host identifiers only)
    python playground/tools.py llm-on            # security.enabled = true
    python playground/tools.py report [--since N]  # leak report over the relay log, per use case
    python playground/tools.py reset             # clear the relay log

Config changes go through MasqAI's own /api/config (the same thing the GUI's Apply does), so they
live in RAM and vanish when MasqAI restarts.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

import httpx

MASQ = os.getenv("MASQ_URL", "http://127.0.0.1:8787")
RELAY = os.getenv("RELAY_URL", "http://127.0.0.1:8788")
STATE = Path(__file__).resolve().parent / ".state"
BLACKHOLE = "masq-playground-blackhole"   # security provider at an unrouted URL, answers 404 (UC6)
SAVED = STATE / "security-before-break.json"


def admin_headers() -> dict:
    """MasqAI's control API needs the admin token printed at startup (MASQAI_ADMIN_TOKEN=…)."""
    token = os.getenv("MASQAI_ADMIN_TOKEN")
    if not token:
        sys.exit("set MASQAI_ADMIN_TOKEN to the token MasqAI printed when it started")
    return {"x-masqai-token": token}


def get_config() -> dict:
    return httpx.get(f"{MASQ}/api/config", headers=admin_headers(), timeout=5).raise_for_status().json()


def put_config(config: dict) -> None:
    response = httpx.post(f"{MASQ}/api/config", json=config, headers=admin_headers(), timeout=10)
    if response.status_code != 200:
        sys.exit(f"MasqAI rejected the change: {response.text}")


def status() -> None:
    try:
        sec = get_config()["security"]
        state = "ON" if sec["enabled"] else "OFF (detector-only)"
        broken = " [BROKEN on purpose: security model unreachable]" if sec["provider"] == BLACKHOLE else ""
        print(f"MasqAI   up   security LLM {state}: {sec['provider']} / {sec['model']}{broken}  context_mode={sec['context_mode']}")
    except Exception as exc:
        print(f"MasqAI   DOWN ({exc.__class__.__name__})")
    try:
        data = httpx.get(f"{RELAY}/relay/api/requests", timeout=5).json()
        leaking = sum(1 for r in data["requests"] if r["hits"])
        print(f"relay    up   {len(data['requests'])} requests logged, {leaking} leaking")
    except Exception as exc:
        print(f"relay    DOWN ({exc.__class__.__name__})")
    try:
        models = httpx.get("http://127.0.0.1:11434/api/tags", timeout=3).json().get("models", [])
        print("ollama   up   models: " + (", ".join(m["name"] for m in models) or "(none pulled)"))
    except Exception:
        print("ollama   down (fine if the security model is remote)")


def set_security(mutate) -> None:
    config = get_config()
    mutate(config["security"])
    put_config(config)
    status()


def break_security() -> None:
    """Simulate the security model dying: point it at a provider on a closed port."""
    config = get_config()
    if config["security"]["provider"] != BLACKHOLE:
        STATE.mkdir(exist_ok=True)
        SAVED.write_text(json.dumps(config["security"]), encoding="utf-8")
    config["providers"] = [p for p in config["providers"] if p["name"] != BLACKHOLE]
    config["providers"].append({"name": BLACKHOLE, "base_url": f"{MASQ}/{BLACKHOLE}", "format": "openai", "headers": {}})
    config["security"].update(enabled=True, provider=BLACKHOLE)
    put_config(config)
    status()


def restore_security() -> None:
    config = get_config()
    if SAVED.exists():
        config["security"] = json.loads(SAVED.read_text(encoding="utf-8"))
        SAVED.unlink()
    elif config["security"]["provider"] == BLACKHOLE:
        sys.exit("no saved security settings; restart MasqAI to reload its config file")
    config["providers"] = [p for p in config["providers"] if p["name"] != BLACKHOLE]
    put_config(config)
    status()


def report(since: int) -> None:
    data = httpx.get(f"{RELAY}/relay/api/requests", params={"since": since}, timeout=10).json()
    requests = data["requests"]
    if not requests:
        print("relay log is empty")
        return
    by_route: dict[str, list] = defaultdict(list)
    for r in requests:
        by_route[r["route"]].append(r)
    for route, items in by_route.items():
        leaked = defaultdict(set)
        for r in items:
            for hit in r["hits"]:
                leaked[hit["label"]].add(r["id"])
        chars = sum(r["chars"] for r in items)
        print(f"\n== route {route}: {len(items)} requests, {chars:,} bytes, {sum(1 for r in items if r['hits'])} leaking")
        if not leaked:
            print("   no planted value or host identifier reached the relay")
        for label, ids in sorted(leaked.items()):
            print(f"   LEAK {label:<34} in request(s) {', '.join('#' + str(i) for i in sorted(ids))}")
    values_path = STATE / "values.json"
    if values_path.exists():
        short = json.loads(values_path.read_text(encoding="utf-8")).get("UC4_PARTIAL_SHORT")
        if short:
            hits = [r["id"] for r in requests if short in json.dumps(r["body"])]
            if hits:
                print(f"\n   note: the short UC4 alias {short!r} appears in request(s) {', '.join('#' + str(i) for i in hits)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["status", "break-security", "restore-security", "detector-only", "llm-on", "report", "reset"])
    parser.add_argument("--since", type=int, default=0, help="report: only requests with id > N")
    args = parser.parse_args()
    if args.command == "status":
        status()
    elif args.command == "break-security":
        break_security()
    elif args.command == "restore-security":
        restore_security()
    elif args.command == "detector-only":
        set_security(lambda s: s.update(enabled=False))
    elif args.command == "llm-on":
        set_security(lambda s: s.update(enabled=True))
    elif args.command == "report":
        report(args.since)
    elif args.command == "reset":
        httpx.post(f"{RELAY}/relay/api/reset", timeout=5).raise_for_status()
        print("relay log cleared")


if __name__ == "__main__":
    main()
