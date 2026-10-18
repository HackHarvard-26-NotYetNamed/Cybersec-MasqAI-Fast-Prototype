"""The processes one campaign needs, started from its RunConfig and stopped when it ends.

    relay        playground/relay.py on relay.port (the untrusted endpoint, shared by every condition)
    gateway x N  run_gateway.py, one per masqai condition, on services.gateway_base_port + i
    fake LLMs    eval/fake_llm.py (self-test only)

Each process logs to <campaign dir>/logs/<name>.log. A port that is already taken is an error, not
something to reuse: a stale gateway with another config would silently invalidate the measurement.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx

from .settings import RunConfig, gateway_for

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Service:
    name: str
    url: str          # health URL
    port: int
    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)
    process: subprocess.Popen | None = None
    log_path: Path | None = None


def port_busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def plan(cfg: RunConfig, workdir: Path) -> list[Service]:
    """The services for a campaign, with gateway configs written to workdir/gateways/."""
    py = sys.executable
    services: list[Service] = []
    if cfg.self_test:
        agent_port, security_port = cfg.services.fake_llm_ports
        services.append(Service("fake-llm", f"http://127.0.0.1:{security_port}/docs", agent_port,
                                [py, "-m", "eval.fake_llm", "--agent-port", str(agent_port), "--security-port", str(security_port)]))
    services.append(Service("relay", f"{cfg.relay_url}/relay/api/requests?tag=preflight", cfg.relay.port,
                            [py, "playground/relay.py", "--port", str(cfg.relay.port), "--upstream", cfg.relay_upstream,
                             "--key-env", cfg.relay_key_env],
                            {"RELAY_MAX_RECORDS": str(cfg.relay.max_records)}))
    gateways = workdir / "gateways"
    for condition in cfg.active_conditions:
        if condition.kind != "masqai":
            continue
        gateways.mkdir(parents=True, exist_ok=True)
        path = gateways / f"{condition.id}.json"
        path.write_text(json.dumps(gateway_for(cfg, condition), indent=2), encoding="utf-8")
        port = cfg.gateway_port(condition)
        services.append(Service(f"gateway-{condition.id}", f"http://127.0.0.1:{port}/", port,
                                [py, "run_gateway.py", "--config", str(path)]))
    return services


def tail(path: Path | None, lines: int = 12) -> str:
    if not path or not path.exists():
        return ""
    return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])


class Services:
    def __init__(self, cfg: RunConfig, workdir: Path, log: Callable[[str], None]) -> None:
        self.cfg, self.workdir, self.log = cfg, workdir, log
        self.items = plan(cfg, workdir)

    async def start(self) -> None:
        busy = [f"{s.name} :{s.port}" for s in self.items if port_busy(s.port)]
        if self.cfg.self_test:
            security_port = self.cfg.services.fake_llm_ports[1]
            if port_busy(security_port):
                busy.append(f"fake security model :{security_port}")
        if busy:
            raise RuntimeError(f"port(s) already in use: {', '.join(busy)}; stop the old process or change the port")
        logs = self.workdir / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        for service in self.items:
            service.log_path = logs / f"{service.name}.log"
            handle = service.log_path.open("w", encoding="utf-8")
            service.process = subprocess.Popen(service.argv, cwd=ROOT, env={**env, **service.env}, stdout=handle,
                                               stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, creationflags=flags)
            handle.close()   # the child holds its own handle
            self.log(f"started {service.name} (pid {service.process.pid}) on :{service.port}")
        await self.wait_ready()

    async def wait_ready(self) -> None:
        deadline = time.monotonic() + self.cfg.services.ready_timeout_s
        pending = list(self.items)
        async with httpx.AsyncClient(timeout=2) as http:
            while pending:
                for service in list(pending):
                    if service.process.poll() is not None:
                        raise RuntimeError(f"{service.name} exited with code {service.process.returncode}:\n{tail(service.log_path)}")
                    try:
                        if (await http.get(service.url)).status_code < 500:
                            pending.remove(service)
                            self.log(f"{service.name} ready")
                    except httpx.HTTPError:
                        pass
                if pending and time.monotonic() > deadline:
                    names = ", ".join(s.name for s in pending)
                    raise RuntimeError(f"not ready after {self.cfg.services.ready_timeout_s:.0f} s: {names}\n"
                                       + "\n".join(tail(s.log_path, 6) for s in pending))
                if pending:
                    await asyncio.sleep(0.4)

    def stop(self) -> None:
        for service in reversed(self.items):
            process = service.process
            if process and process.poll() is None:
                process.terminate()
        for service in self.items:
            process = service.process
            if process and process.poll() is None:
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
            if process:
                self.log(f"stopped {service.name}")
