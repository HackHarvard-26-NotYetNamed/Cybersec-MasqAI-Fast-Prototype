"""The eval agent: OpenAI Chat Completions with one `bash` tool. Runs on the laptop; commands run in the
run's sandbox (see sandbox.py)."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .sandbox import Sandbox

MAX_TURNS = 12
COMMAND_TIMEOUT_S = 120
RUN_TIMEOUT_S = 15 * 60
SYSTEM = ("You are a coding agent working in a Linux sandbox. Use the bash tool to inspect and change files in the "
          "current directory. Work step by step and verify your work. When the task is done, reply with a short summary "
          "and no tool call.")
TOOLS = [{"type": "function", "function": {
    "name": "bash",
    "description": "Run a bash command in the current directory. Returns the exit code and combined stdout/stderr.",
    "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
}}]
BLOCK_STATUSES = {502, 422, 404}


@dataclass
class AgentResult:
    turns: int = 0
    blocked: bool = False
    block_status: int | None = None
    error: str | None = None
    llm_ms: list[float] = field(default_factory=list)
    commands: int = 0


async def run_agent(client: httpx.AsyncClient, base_url: str, model: str, headers: dict[str, str], task: str,
                    sandbox: Sandbox, cwd: str, env: dict[str, str]) -> AgentResult:
    result = AgentResult()
    messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
    deadline = time.monotonic() + RUN_TIMEOUT_S
    while result.turns < MAX_TURNS and time.monotonic() < deadline:
        result.turns += 1
        started = time.monotonic()
        response = await client.post(f"{base_url}/chat/completions", headers=headers,
                                     json={"model": model, "messages": messages, "tools": TOOLS, "temperature": 0})
        result.llm_ms.append((time.monotonic() - started) * 1000)
        if response.status_code != 200:
            kind = _error_type(response)
            if response.status_code in BLOCK_STATUSES and kind.startswith("masqai_"):
                # MasqAI failed closed: nothing reached the untrusted model. Not a leak; a task failure.
                result.blocked, result.block_status = True, response.status_code
            else:
                result.error = f"HTTP {response.status_code} {kind}".strip()
            return result
        message = response.json()["choices"][0]["message"]
        calls = message.get("tool_calls") or []
        messages.append({k: v for k, v in message.items() if k in {"role", "content", "tool_calls"}} | {"role": "assistant"})
        if not calls:
            return result
        for call in calls:
            try:
                command = json.loads(call["function"].get("arguments") or "{}").get("command", "")
            except ValueError:
                command = ""
            if not command:
                output = "error: the bash tool needs a JSON argument {\"command\": \"...\"}"
            else:
                result.commands += 1
                executed = await sandbox.exec(command, cwd, env, COMMAND_TIMEOUT_S)
                output = f"exit {executed.exit_code}\n{executed.output}"
            messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": output})
    return result


def _error_type(response: httpx.Response) -> str:
    try:
        error = response.json().get("error")
        return error.get("type", "") if isinstance(error, dict) else ""
    except ValueError:
        return ""
