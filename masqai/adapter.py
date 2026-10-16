"""Lossless request lenses: edit content leaves, never reconstruct protocol objects."""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from .model import ContextItem


def extract(payload: dict[str, Any], api: str) -> list[ContextItem]:
    items: list[ContextItem] = []

    def add(path: tuple, value: str, role: str, kind: str, eligible=True, reasoning=False):
        digest = hashlib.sha256(json.dumps([path, value], ensure_ascii=True).encode()).hexdigest()[:24]
        item = ContextItem(digest, kind, role, value, value, eligible, reasoning)
        item.path = path
        items.append(item)

    def content(value, path, role, kind="message", eligible=True):
        if isinstance(value, str):
            add(path, value, role, kind, eligible)
        elif isinstance(value, list):
            for i, block in enumerate(value):
                if not isinstance(block, dict):
                    continue
                p = path + (i,)
                typ = block.get("type", "")
                if typ in {"thinking", "redacted_thinking", "reasoning"}:
                    add(p, json.dumps(block, ensure_ascii=False), role, "reasoning", False, True)
                elif typ == "tool_result":
                    content(block.get("content"), p + ("content",), role, "tool_result")
                elif typ == "tool_use":
                    add(p + ("input",), json.dumps(block.get("input", {}), ensure_ascii=False), role, "tool_arguments")
                    items[-1].json_value = True
                elif isinstance(block.get("text"), str):
                    add(p + ("text",), block["text"], role, kind, eligible)
                # Images, audio, unknown block types and signatures remain opaque.

    for key in ("system", "instructions"):
        if key in payload:
            content(payload[key], (key,), "system", "system", False)
    for i, tool in enumerate(payload.get("tools", [])):
        def schema_walk(value, path):
            if isinstance(value, str):
                # Descriptions only: names, enum values and schema structure are protocol.
                if path[-1] == "description":
                    add(path, value, "system", "tool_definition", False)
            elif isinstance(value, dict):
                for k, v in value.items():
                    schema_walk(v, path + (k,))
            elif isinstance(value, list):
                for j, v in enumerate(value):
                    schema_walk(v, path + (j,))
        schema_walk(tool, ("tools", i))
    source = "messages" if "messages" in payload else "input"
    messages = payload.get(source, [])
    if isinstance(messages, str):
        add((source,), messages, "user", "message")
        return items
    for i, message in enumerate(messages):
        p = (source, i)
        if not isinstance(message, dict):
            continue
        role = message.get("role", "assistant")
        typ = message.get("type", "")
        if typ == "reasoning":
            add(p, json.dumps(message, ensure_ascii=False), role, "reasoning", False, True)
            continue
        if typ == "function_call_output":
            content(message.get("output"), p + ("output",), "tool", "tool_result")
        elif typ == "function_call":
            if isinstance(message.get("arguments"), str):
                add(p + ("arguments",), message["arguments"], role, "tool_arguments")
        else:
            eligible = role not in {"system", "developer"}
            content(message.get("content"), p + ("content",), role, "tool_result" if role == "tool" else "message", eligible)
            for j, call in enumerate(message.get("tool_calls", [])):
                fn = call.get("function", {})
                if isinstance(fn.get("arguments"), str):
                    add(p + ("tool_calls", j, "function", "arguments"), fn["arguments"], "assistant", "tool_arguments")
            for key in ("reasoning", "reasoning_content", "reasoning_details"):
                if key in message:
                    add(p + (key,), json.dumps(message[key], ensure_ascii=False), role, "reasoning", False, True)
    return items


def serialize(payload: dict[str, Any], items: list[ContextItem]) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    for item in items:
        if item.reasoning:
            continue
        target = result
        for part in item.path[:-1]:
            target = target[part]
        value = item.sanitized
        if getattr(item, "json_value", False):
            value = json.loads(value)
        target[item.path[-1]] = value
    return result


def restore_text(value: str, entities) -> str:
    for entity in entities:
        value = value.replace(entity["token"], entity["canonical"])
        value = value.replace(entity["token"].replace("<", "<$", 1), entity["canonical"])
    return value


def restore_value(value, entities):
    if isinstance(value, str):
        return restore_text(value, entities)
    if isinstance(value, list):
        return [restore_value(v, entities) for v in value]
    if isinstance(value, dict):
        return {k: restore_value(v, entities) for k, v in value.items()}
    return value


def restore_arguments(arguments: str, entities) -> str:
    # Restore decoded string values, then encode JSON. Textual replacement into
    # serialized JSON would corrupt quotes and Windows path backslashes.
    try:
        value = json.loads(arguments)
    except (ValueError, TypeError):
        return restore_text(arguments, entities)
    restored = restore_value(value, entities)
    return arguments if restored == value else json.dumps(restored, ensure_ascii=False)


def restore_tool_arguments(data: dict[str, Any], entities, api: str) -> dict[str, Any]:
    output = copy.deepcopy(data)
    for choice in output.get("choices", []):
        message = choice.get("message", {})
        for call in message.get("tool_calls", []):
            fn = call.get("function", {})
            if isinstance(fn.get("arguments"), str):
                fn["arguments"] = restore_arguments(fn["arguments"], entities)
    for block in output.get("content", []):
        if block.get("type") == "tool_use":
            block["input"] = restore_value(block.get("input", {}), entities)
    for item in output.get("output", []):
        if item.get("type") == "function_call":
            item["arguments"] = restore_arguments(item.get("arguments", ""), entities)
    return output
