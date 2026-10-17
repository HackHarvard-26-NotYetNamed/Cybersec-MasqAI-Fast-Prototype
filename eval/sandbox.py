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
import subprocess
import sys
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
        self.host_root = tempfile.mkdtemp(prefix="masq-eval-")
        self.bash_bin = _find_bash()
        self.root = _to_bash_path(self.host_root) if os.name == "nt" else self.host_root
        self.env = os.environ.copy()
        if os.name == "nt":
            shim_dir = Path(self.host_root) / ".harness" / "bin"
            shim_dir.mkdir(parents=True)
            python_path = _to_bash_path(sys.executable)
            shim = shim_dir / "python3"
            shim.write_text(f'#!/usr/bin/env bash\nexec "{python_path}" "$@"\n', encoding="utf-8")
            bash_dir = _to_bash_path(str(Path(self.bash_bin).parent))
            self.env["PATH"] = f"{_to_bash_path(str(shim_dir))}:{bash_dir}:{self.env.get('PATH', '')}"

    async def upload(self, files: list[tuple[str, bytes]]) -> None:
        for path, data in files:
            if not path.startswith(self.root.rstrip("/") + "/") and path != self.root:
                raise ValueError("local sandbox: upload outside its root")
            target = Path(_from_bash_path(path) if os.name == "nt" else path)
            if os.path.commonpath((self.host_root, str(target.resolve()))) != os.path.commonpath((self.host_root, self.host_root)):
                raise ValueError("local sandbox: upload outside its root")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

    async def exec(self, command: str, cwd: str, env: dict[str, str], timeout: int = COMMAND_TIMEOUT_S) -> ExecResult:
        host_cwd = _from_bash_path(cwd) if os.name == "nt" else cwd
        Path(host_cwd).mkdir(parents=True, exist_ok=True)
        command_env = {**self.env, **env}
        if os.name == "nt":
            command_env["PATH"] = f"{self.env['PATH']}:{env.get('PATH', '')}"
        process = await asyncio.create_subprocess_exec(self.bash_bin, "-c", command, cwd=host_cwd,
                                                       env=command_env,
                                                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            out, _ = await asyncio.wait_for(process.communicate(), timeout)
        except asyncio.TimeoutError:
            process.kill()
            return ExecResult(124, f"timed out after {timeout} s")
        return ExecResult(process.returncode or 0, out.decode("utf-8", "replace")[-MAX_OUTPUT:])

    async def delete(self) -> None:
        shutil.rmtree(self.host_root, ignore_errors=True)


def _find_bash() -> str:
    bash = shutil.which("bash")
    if bash:
        return bash
    candidates = (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    )
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    raise RuntimeError("Local sandbox requires Bash; install Git for Windows and ensure bash.exe is available")


def _cygpath(flag: str, path: str) -> str:
    bash_dir = Path(_find_bash()).parent
    candidates = (bash_dir / "cygpath.exe", bash_dir.parent / "usr" / "bin" / "cygpath.exe", Path(shutil.which("cygpath") or ""))
    cygpath = next((str(candidate) for candidate in candidates if candidate.is_file()), None)
    if not cygpath:
        raise RuntimeError("Git for Windows cygpath.exe is required to map local sandbox paths")
    return subprocess.check_output([cygpath, flag, path], text=True).strip()


def _to_bash_path(path: str) -> str:
    return _cygpath("-u", path) if os.name == "nt" else path


def _from_bash_path(path: str) -> str:
    return _cygpath("-w", path) if os.name == "nt" else path


class LocalBackend:
    name = "local"

    def __init__(self, trusted_commands: bool = False) -> None:
        allow_untrusted = os.getenv("MASQAI_ALLOW_LOCAL_SANDBOX", "0").lower() in ("1", "true", "yes")
        if not trusted_commands and not allow_untrusted:
            raise SystemExit("the local backend runs commands on this machine; set MASQAI_ALLOW_LOCAL_SANDBOX=1 or pass --self-test to permit it")
        if not trusted_commands:
            import warnings
            warnings.warn("LocalBackend: executing untrusted commands locally on the host machine.")

    async def create(self, run_id: str) -> LocalSandbox:
        return LocalSandbox()

    async def cleanup(self) -> int:
        return 0

    async def close(self) -> None:
        pass


def _quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"
