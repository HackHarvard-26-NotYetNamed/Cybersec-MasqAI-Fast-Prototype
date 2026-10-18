"""BENCH ONLY driver: runs the real host code (masqai.custody.device) against the board over tcp://<board>:7777, with
the fake OpenRouter on this PC. Secrets are the FAKE-marked test values; nothing real is typed or printed.

    python firmware/esp32/bench/drive.py enroll|run|soak|real [--board 192.168.219.225]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from masqai.custody import CustodyError, RateLimited  # noqa: E402
from masqai.custody import device as D  # noqa: E402
from tests.helpers import FAKE_INSTANCE, FAKE_MGMT_KEY, FAKE_WORKSPACE  # noqa: E402

PAIR = Path.home() / ".masqai-bench" / "bench-device.pair"
CONTROL = "http://127.0.0.1:8444"


def control(script: dict | None = None) -> dict:
    if script is None:
        return json.loads(urllib.request.urlopen(CONTROL + "/state", timeout=5).read())
    req = urllib.request.Request(CONTROL + "/script", data=json.dumps(script).encode(), method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=5).read())


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(("PASS " if ok else "FAIL ") + label + (f"  ({detail})" if detail else ""), flush=True)
    return ok


def enroll(spec: str) -> int:
    answers = iter(["yes", FAKE_WORKSPACE, FAKE_INSTANCE, "", "", ""])
    secrets_ = iter([FAKE_MGMT_KEY])
    said: list[str] = []
    console = D.Console(secret=lambda p: next(secrets_), ask=lambda p: (print(p.strip()), next(answers))[1], say=said.append)
    started = time.monotonic()
    code = D.main(["enroll", "--port", spec, "--pairing-file", str(PAIR)], console)
    for line in said:
        print("   |", line)
    print(f"enroll exit {code} in {time.monotonic() - started:.1f} s")
    return code


async def run(spec: str) -> int:
    results = []
    pairing = D.read_pairing(PAIR)
    link = D.open_transport(spec)
    backend = D.DeviceBackend(pairing, link, workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE)
    t = time.monotonic()
    await asyncio.to_thread(backend._connect)
    results.append(check("HELLO + UNLOCK over the authenticated session", True, f"{time.monotonic() - t:.1f} s"))
    status = await backend.status()
    results.append(check("CHECK: management key, workspace, budget (via the board's TLS)", status.healthy, status.detail))
    print("   cleanup of earlier bench keys:", await backend.cleanup())
    expires = datetime.now(timezone.utc) + timedelta(seconds=1900)
    t = time.monotonic()
    minted = await backend.mint(suffix="bench-1", expires_at=expires, limit_usd=2.0)
    results.append(check("MINT: key delivered encrypted, name built on the device", minted.name == f"masqai-enigma-{FAKE_INSTANCE}-bench-1",
                         f"{time.monotonic() - t:.1f} s, expires {minted.expires_at:%H:%M:%S}Z"))
    state = control()
    record = next((k for k in state["keys"] if k["hash"] == minted.hash), None)
    results.append(check("OpenRouter recorded the device's limit and expiry", bool(record) and record["limit"] == 2.0
                         and record["expires_at"] == minted.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"), str(record and record["expires_at"])))
    results.append(check("the minted key is a FAKE test key", "FAKE" in minted.key))
    results.append(check("USAGE", await backend.usage(minted.hash) == 0.0))
    for label, kwargs, code in (("policy: limit above $2 refused by the board", {"limit_usd": 2.5}, "POLICY_LIMIT"),
                                ("policy: ttl above 1900 s refused by the board", {"expires_at": expires + timedelta(seconds=600)}, "POLICY_TTL")):
        try:
            await backend.mint(suffix="bench-x", **{"expires_at": expires, "limit_usd": 1.0, **kwargs})
            results.append(check(label, False, "minted"))
        except CustodyError as exc:
            results.append(check(label, code in str(exc), str(exc)))
    control({"add_key": "the owner's own key"})
    foreign_hash = control()["keys"][-1]["hash"]
    try:
        await backend.revoke(foreign_hash)
        results.append(check("revoke scope: a key the device did not mint is refused", False))
    except CustodyError as exc:
        results.append(check("revoke scope: a key the device did not mint is refused", "NOT_IN_JOURNAL" in str(exc)))
    burst = 0
    burst_hashes: set[str] = set()
    try:
        for i in range(5):
            burst_hashes.add((await backend.mint(suffix=f"bench-b{i}", expires_at=expires, limit_usd=0.5)).hash)
            burst += 1
        results.append(check("rate limit: early mints capped", False, f"{burst} minted"))
    except RateLimited as exc:
        results.append(check("rate limit: early mints capped by the board", burst == 3, f"{burst} burst mints, then {exc}"))
    t = time.monotonic()
    outcome = await backend.revoke(minted.hash)
    results.append(check("REVOKE", outcome == "deleted", f"{outcome}, {time.monotonic() - t:.1f} s"))
    control({"fail": [["DELETE", "/keys/", [500]]]})
    # A burst key from THIS run that is still live (earlier runs leave disabled keys in the fake's list).
    hashes = [k["hash"] for k in control()["keys"] if k["name"].startswith(f"masqai-enigma-{FAKE_INSTANCE}-bench-b")
              and not k.get("disabled") and k["hash"] in burst_hashes]
    outcome = await backend.revoke(hashes[0])
    results.append(check("REVOKE falls back to PATCH disabled when DELETE fails", outcome == "disabled", outcome))
    revoked = await backend.cleanup()
    left = [k for k in control()["keys"] if k["name"].startswith(f"masqai-enigma-{FAKE_INSTANCE}-") and not k.get("disabled")]
    results.append(check("CLEANUP revokes every journal key; the owner's key survives", not left and any(
        k["hash"] == foreign_hash for k in control()["keys"]), f"{revoked} revoked"))
    # The device reboots (power loss): the backend authenticates again and continues.
    status_line = await asyncio.to_thread(backend.client.call, "STATUS")
    print("   board status:", json.dumps({k: status_line.get(k) for k in ("state", "mem_free", "live", "minted_24h", "server_time")}))
    control({"management_key": "sk-or-v1-FAKEFAKEFAKErevokedonopenrouter"})
    # CHECK, not MINT: by now the burst allowance is used up, and the policy rightly refuses a mint before it would
    # reach OpenRouter (RATE_GAP). CHECK is not rate-limited and calls OpenRouter with the stored key.
    status = await backend.status()
    results.append(check("a revoked management key: CHECK reports it, unhealthy", not status.healthy and "MGMT_AUTH" in status.detail,
                         status.detail))
    control({"management_key": FAKE_MGMT_KEY})
    await backend.aclose()
    results.append(check("aclose sends LOCK and wipes the host's pairing copy", bytes(pairing.k_mac) == b""))
    # A forged session: right device, wrong k_mac.
    import secrets as s
    bad = D.read_pairing(PAIR)
    bad.k_mac = bytearray(s.token_bytes(32))
    try:
        D.DeviceBackend(bad, D.open_transport(spec), workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE)._connect()
        results.append(check("a host without the pairing secret cannot drive the board", False))
    except CustodyError as exc:
        results.append(check("a host without the pairing secret cannot drive the board", "authenticate" in str(exc), str(exc)))
    bad = D.read_pairing(PAIR)
    bad.unlock_secret = bytearray(s.token_bytes(32))
    try:
        D.DeviceBackend(bad, D.open_transport(spec), workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE)._connect()
        results.append(check("a wrong unlock secret cannot unlock the management key", False))
    except CustodyError as exc:
        results.append(check("a wrong unlock secret cannot unlock the management key", "UNLOCK_FAILED" in str(exc), str(exc)))
    print(f"{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


async def soak(spec: str, cycles: int) -> int:
    """Mint/revoke cycles. The board's policy allows a mint every 240 s, plus 3 early ones per 10 min, so a fast soak
    re-enrolls with a bench policy (min_mint_gap_s=60 is the floor)... instead we count TLS handshakes: every
    USAGE/CHECK call is one full handshake on the board."""
    pairing = D.read_pairing(PAIR)
    backend = D.DeviceBackend(pairing, D.open_transport(spec), workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE)
    await asyncio.to_thread(backend._connect)
    mem = []
    started = time.monotonic()
    for i in range(cycles):
        status = await backend.status()
        if not status.healthy:
            print("unhealthy at", i, status.detail)
            return 1
        if i % 10 == 0:
            info = await asyncio.to_thread(backend.client.call, "STATUS")
            mem.append(info.get("mem_free"))
            print(f"   cycle {i}: board mem_free {info.get('mem_free')}", flush=True)
    info = await asyncio.to_thread(backend.client.call, "STATUS")
    mem.append(info.get("mem_free"))
    await backend.aclose()
    # Each CHECK is 3 HTTPS requests (key, workspace, budgets) = 3 TLS handshakes on the board.
    print(f"{cycles} CHECKs = {cycles * 3} TLS handshakes in {time.monotonic() - started:.0f} s; mem_free samples {mem}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["enroll", "run", "soak"])
    parser.add_argument("--board", default="192.168.219.225")
    parser.add_argument("--cycles", type=int, default=34)
    args = parser.parse_args()
    spec = f"tcp://{args.board}:7777"
    if args.command == "enroll":
        return enroll(spec)
    if args.command == "run":
        return asyncio.run(run(spec))
    return asyncio.run(soak(spec, args.cycles))


if __name__ == "__main__":
    sys.exit(main())
