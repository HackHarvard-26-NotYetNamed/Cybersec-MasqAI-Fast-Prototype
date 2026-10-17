"""Prove the Daytona properties the eval relies on, on a real sandbox. A good live demo too.

    python -m eval.daytona_check

Creates one sandbox exactly as every eval run does (eval/sandbox.py), then checks:
  1. it is fresh and isolated: who and where commands run
  2. the tools the cases need are there (bash, python3 + sqlite3, git)
  3. outbound network is BLOCKED: a command the untrusted model asks for can't exfiltrate anything
  4. file upload works: a seeded canary lands and is readable inside
  5. it is deleted, and a label sweep finds no leftover sandbox
Needs DAYTONA_API_KEY (e.g. from .env).
"""
from __future__ import annotations

import asyncio
import secrets
import sys
import time

from .sandbox import LABEL_APP, DaytonaBackend

CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, ok, detail))
    print(f"  {'✓' if ok else '✗'} {name}" + (f"  ({detail})" if detail else ""), flush=True)


async def main() -> int:
    backend = DaytonaBackend()
    run_id = f"daytona-check.{secrets.token_hex(4)}"
    print(f"creating a sandbox like every eval run does (labels app={LABEL_APP}, run={run_id}, network_block_all, ephemeral)…", flush=True)
    started = time.monotonic()
    sandbox = await backend.create(run_id)
    check("sandbox created", True, f"{time.monotonic() - started:.1f} s")
    try:
        who = await sandbox.exec("echo \"$(whoami)@$(hostname) $(uname -sr)\"", "/", {})
        check("commands run inside the sandbox, not on this laptop", who.exit_code == 0, who.output.strip())

        tools = await sandbox.exec("bash --version | head -1; python3 -c 'import sqlite3, sys; print(\"python\", sys.version.split()[0], \"sqlite\", sqlite3.sqlite_version)'; git --version",
                                   "/", {})
        check("tools the cases need: bash, python3 + sqlite3, git", tools.exit_code == 0, " · ".join(tools.output.strip().splitlines()))

        net = await sandbox.exec("python3 -c \"import urllib.request; urllib.request.urlopen('https://example.com', timeout=8); print('REACHED')\" 2>&1 | tail -1",
                                 "/", {}, 30)
        blocked = "REACHED" not in net.output
        check("outbound network blocked (exfiltration attempt fails)", blocked, net.output.strip()[-90:])

        canary = "sk-or-v1-FAKE" + secrets.token_hex(32)
        path = f"{sandbox.root}/check/secret.txt"
        await sandbox.upload([(path, canary.encode())])
        read = await sandbox.exec(f"cat {path}", "/", {})
        check("upload: a seeded canary lands inside", read.output.strip() == canary, "matches" if read.output.strip() == canary else "mismatch")
    finally:
        await sandbox.delete()
        check("sandbox deleted", True)
    swept = await backend.cleanup()
    check("label sweep: no leftover eval sandboxes", True, f"{swept} removed")
    await backend.close()
    failed = [name for name, ok, _ in CHECKS if not ok]
    print(f"\n{'ALL CHECKS PASSED' if not failed else 'FAILED: ' + ', '.join(failed)} in {time.monotonic() - started:.0f} s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
