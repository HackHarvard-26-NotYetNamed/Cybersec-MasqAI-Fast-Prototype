"""Where the untrusted model's commands run. Daytona in every real eval run.

MasqAI protects what goes OUT to the untrusted model (context); it can't stop that model from asking the
agent to run a harmful command. So every command runs in a fresh Daytona sandbox (one per run, network
blocked, labeled, deleted in `finally`), never on the laptop. The agent loop itself stays on the laptop,
because the gateway is localhost-only.

LocalBackend exists only for the harness's own self-test with the scripted fake model (eval/fake_llm.py):
it runs commands on this machine, so it refuses to start unless the caller passes trusted_commands=True.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

LABEL_APP = "masqai-eval"
COMMAND_TIMEOUT_S = 120
MAX_OUTPUT = 12_000


@dataclass
class ExecResult:
    exit_code: int
    output: str


class Sandbox(Protocol):
    root: str

    async def upload(self, files: list[tuple[str, bytes]]) -> None: ...
    async def exec(self, command: str, cwd: str, env: dict[str, str], timeout: int = COMMAND_TIMEOUT_S) -> ExecResult: ...
    async def delete(self) -> None: ...


# ---------- Daytona ----------

class DaytonaSandbox:
    root = "/tmp/masq"

    def __init__(self, sandbox) -> None:
        self.sandbox = sandbox

    async def upload(self, files: list[tuple[str, bytes]]) -> None:
        from daytona import FileUpload
        dirs = sorted({str(Path(path).parent) for path, _ in files})
        if dirs:
            await self.exec("mkdir -p " + " ".join(_quote(d) for d in dirs), "/", {})
        await self.sandbox.fs.upload_files([FileUpload(source=data, destination=path) for path, data in files])

    async def exec(self, command: str, cwd: str, env: dict[str, str], timeout: int = COMMAND_TIMEOUT_S) -> ExecResult:
        # Run through bash so pipes, redirects and `cd` work like a terminal.
        response = await self.sandbox.process.exec(f"bash -lc {_quote(command)}", cwd=cwd, env=env or None, timeout=timeout)
        return ExecResult(int(response.exit_code or 0), (response.result or "")[-MAX_OUTPUT:])

    async def delete(self) -> None:
        await self.sandbox.delete()


class DaytonaBackend:
    """One fresh sandbox per run. Needs DAYTONA_API_KEY (the SDK reads it from the environment)."""

    name = "Daytona"

    def __init__(self) -> None:
        if not os.getenv("DAYTONA_API_KEY"):
            raise SystemExit("DAYTONA_API_KEY is not set: the eval runs every command in a Daytona sandbox")
        from daytona import AsyncDaytona
        self.client = AsyncDaytona()

    async def create(self, run_id: str) -> DaytonaSandbox:
        from daytona import CreateSandboxFromSnapshotParams
        params = CreateSandboxFromSnapshotParams(
            language="python",
            labels={"app": LABEL_APP, "run": run_id},
            # Containment: whatever the untrusted model makes the agent run can't reach the network.
            network_block_all=True,
            ephemeral=True,            # gone as soon as it stops, even if the harness dies
            auto_stop_interval=20,     # minutes of inactivity; backstop for a crashed harness
        )
        return DaytonaSandbox(await self.client.create(params, timeout=120))

    async def cleanup(self) -> int:
        """Delete every sandbox carrying the harness label (e.g. after a crash)."""
        from daytona import ListSandboxesQuery
        deleted = 0
        async for sandbox in self.client.list(ListSandboxesQuery(labels={"app": LABEL_APP})):
            try:
                await self.client.delete(sandbox)
                deleted += 1
            except Exception:
                pass
        return deleted

    async def close(self) -> None:
        close = getattr(self.client, "close", None)
        if close:
            await close()


# ---------- local (self-test only) ----------

class LocalSandbox:
    def __init__(self) -> None:
        self.root = tempfile.mkdtemp(prefix="masq-eval-")

    async def upload(self, files: list[tuple[str, bytes]]) -> None:
        for path, data in files:
            target = Path(path)
            if not str(target).startswith(self.root):
                raise ValueError("local sandbox: upload outside its root")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

    async def exec(self, command: str, cwd: str, env: dict[str, str], timeout: int = COMMAND_TIMEOUT_S) -> ExecResult:
        Path(cwd).mkdir(parents=True, exist_ok=True)
        process = await asyncio.create_subprocess_exec("bash", "-c", command, cwd=cwd, env={**os.environ, **env},
                                                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            out, _ = await asyncio.wait_for(process.communicate(), timeout)
        except asyncio.TimeoutError:
            process.kill()
            return ExecResult(124, f"timed out after {timeout} s")
        return ExecResult(process.returncode or 0, out.decode("utf-8", "replace")[-MAX_OUTPUT:])

    async def delete(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


class LocalBackend:
    name = "local (self-test only)"

    def __init__(self, trusted_commands: bool = False) -> None:
        if not trusted_commands:
            raise SystemExit("the local backend runs commands on this machine; it is only for the scripted self-test model")

    async def create(self, run_id: str) -> LocalSandbox:
        return LocalSandbox()

    async def cleanup(self) -> int:
        return 0

    async def close(self) -> None:
        pass


def _quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"
