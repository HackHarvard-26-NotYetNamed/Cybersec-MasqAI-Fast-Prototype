"""Strict, lossless request lenses: find every content leaf of a request, per API, and write the
sanitized text back. Protocol objects are never rebuilt; only known text leaves are replaced.

Each API accepts only its own block / item types (Anthropic blocks on /v1/messages, Responses items on
/v1/responses). Anything else is unknown content: refused with 422 before a session or trace exists,
unless `pass_unknown` is on (then forwarded raw, with a warning). Whitelisted opaque content (images,
base64 / URL documents) is forwarded unread and shown only as a description.
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from .model import ContextItem

API_CHAT, API_RESPONSES, API_ANTHROPIC = "chat", "responses", "anthropic"


class UnknownContent(ValueError):
    """Content MasqAI can't inspect. Says where and what type, never the content itself."""

    def __init__(self, location: str, content_type: str) -> None:
        super().__init__(f"{location}: unrecognized content type {content_type!r}")
        self.location = location
        self.content_type = content_type


class BadRequest(ValueError):
    pass


class Extractor:
    def __init__(self, api: str, pass_unknown: bool) -> None:
        self.api = api
        self.pass_unknown = pass_unknown
        self.items: list[ContextItem] = []
        self.warnings: list[dict[str, str]] = []

    # ---------- leaves ----------
    def add(self, path: tuple, value: str, role: str, kind: str, *, mask_only: bool = True, json_value: bool = False) -> None:
        digest = hashlib.sha256(json.dumps([path, value], ensure_ascii=True).encode()).hexdigest()[:24]
        item = ContextItem(digest, kind, role, value, value, eligible=True)
        item.path, item.mask_only, item.json_value = path, mask_only, json_value
        self.items.append(item)

    def json_leaf(self, path: tuple, value: Any, role: str) -> None:
        """A structured tool input (Anthropic tool_use.input): sanitized as JSON text, written back as JSON."""
        self.add(path, json.dumps(value, ensure_ascii=False), role, "tool_arguments", json_value=True)

    def args(self, path: tuple, value: Any, role: str = "assistant") -> None:
        if isinstance(value, str):
            self.add(path, value, role, "tool_arguments")

    def passthrough(self, path: tuple, block: Any, role: str) -> None:
        """Reasoning: signed / encrypted, forwarded untouched, shown in the GUI only."""
        item = ContextItem(hashlib.sha256(json.dumps([path], ensure_ascii=True).encode()).hexdigest()[:24], "reasoning", role,
                           json.dumps(block, ensure_ascii=False), json.dumps(block, ensure_ascii=False), eligible=False, reasoning=True)
        item.path = path
        self.items.append(item)

    def opaque(self, path: tuple, description: str, role: str) -> None:
        item = ContextItem(hashlib.sha256(json.dumps([path, description], ensure_ascii=True).encode()).hexdigest()[:24], "opaque", role,
                           description, description, eligible=False)
        item.path, item.opaque = path, True
        self.items.append(item)

    def unknown(self, path: tuple, content_type: Any, role: str) -> None:
        location = locate_path(path)
        if not self.pass_unknown:
            raise UnknownContent(location, str(content_type))
        self.warnings.append({"location": location, "type": str(content_type)})
        self.opaque(path, f"unknown content type {content_type!r}, forwarded raw (pass_unknown)", role)

    # ---------- tool definitions ----------
    def tool_descriptions(self, value: Any, path: tuple) -> None:
        """Descriptions only: names, enum values and schema structure are protocol."""
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "description" and isinstance(child, str):
                    self.add(path + (key,), child, "system", "tool_definition")
                else:
                    self.tool_descriptions(child, path + (key,))
        elif isinstance(value, list):
            for i, child in enumerate(value):
                self.tool_descriptions(child, path + (i,))

    # ---------- per API ----------
    def chat(self, payload: dict[str, Any]) -> None:
        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            raise BadRequest("messages must be a list")
        for i, message in enumerate(messages):
            path = ("messages", i)
            if not isinstance(message, dict):
                raise BadRequest(f"messages[{i}] must be an object")
            role = message.get("role", "user")
            kind = "tool_result" if role in {"tool", "function"} else "system" if role in {"system", "developer"} else "message"
            self.chat_content(message.get("content"), path + ("content",), role, kind)
            if isinstance(message.get("refusal"), str):
                self.add(path + ("refusal",), message["refusal"], role, "message")
            for j, call in enumerate(message.get("tool_calls") or []):
                if not isinstance(call, dict):
                    continue
                if call.get("type", "function") != "function":
                    # e.g. a `custom` tool call: its free-form input is not a known leaf.
                    self.unknown(path + ("tool_calls", j), call.get("type"), role)
                    continue
                self.args(path + ("tool_calls", j, "function", "arguments"), (call.get("function") or {}).get("arguments"))
            if isinstance(message.get("function_call"), dict):
                self.args(path + ("function_call", "arguments"), message["function_call"].get("arguments"))
            for key in ("reasoning", "reasoning_content", "reasoning_details"):
                if key in message:
                    self.passthrough(path + (key,), message[key], role)
        for i, tool in enumerate(payload.get("tools") or []):
            self.tool_descriptions(tool, ("tools", i))
        for i, fn in enumerate(payload.get("functions") or []):
            self.tool_descriptions(fn, ("functions", i))

    def chat_content(self, content: Any, path: tuple, role: str, kind: str) -> None:
        if content is None:
            return
        if isinstance(content, str):
            self.add(path, content, role, kind, mask_only=kind != "tool_result")
            return
        if not isinstance(content, list):
            raise BadRequest(f"{locate_path(path)} must be a string or a list of parts")
        for j, part in enumerate(content):
            p = path + (j,)
            if not isinstance(part, dict):
                raise BadRequest(f"{locate_path(p)} must be an object")
            typ = part.get("type")
            if typ == "text" and isinstance(part.get("text"), str):
                self.add(p + ("text",), part["text"], role, kind, mask_only=kind != "tool_result")
            elif typ == "refusal" and isinstance(part.get("refusal"), str):
                self.add(p + ("refusal",), part["refusal"], role, "message")
            else:
                # image_url, input_audio, file, ...: MasqAI can't inspect them.
                self.unknown(p, typ, role)

    def responses(self, payload: dict[str, Any]) -> None:
        if isinstance(payload.get("instructions"), str):
            self.add(("instructions",), payload["instructions"], "system", "system")
        source = payload.get("input")
        if isinstance(source, str):
            self.add(("input",), source, "user", "message")
        elif isinstance(source, list):
            for i, item in enumerate(source):
                self.responses_item(item, ("input", i))
        elif source is not None:
            raise BadRequest("input must be a string or a list")
        for i, tool in enumerate(payload.get("tools") or []):
            self.tool_descriptions(tool, ("tools", i))

    def responses_item(self, item: Any, path: tuple) -> None:
        if not isinstance(item, dict):
            raise BadRequest(f"{locate_path(path)} must be an object")
        typ = item.get("type", "message" if "role" in item else None)
        role = item.get("role", "assistant")
        if typ == "message":
            kind = "system" if role in {"system", "developer"} else "message"
            content = item.get("content")
            if isinstance(content, str):
                self.add(path + ("content",), content, role, kind)
            elif isinstance(content, list):
                for j, part in enumerate(content):
                    p = path + ("content", j)
                    ptype = part.get("type") if isinstance(part, dict) else None
                    if ptype in {"input_text", "output_text"} and isinstance(part.get("text"), str):
                        self.add(p + ("text",), part["text"], role, kind)
                    elif ptype == "refusal" and isinstance(part.get("refusal"), str):
                        self.add(p + ("refusal",), part["refusal"], role, "message")
                    else:
                        self.unknown(p, ptype, role)
        elif typ == "function_call":
            self.args(path + ("arguments",), item.get("arguments"))
        elif typ == "function_call_output":
            self.tool_output(item.get("output"), path + ("output",))
        elif typ == "reasoning":
            self.passthrough(path, item, "assistant")   # carries encrypted_content: never touched
        elif typ == "custom_tool_call":
            self.args(path + ("input",), item.get("input"))
        elif typ == "custom_tool_call_output":
            self.tool_output(item.get("output"), path + ("output",))
        elif typ == "mcp_call":
            self.args(path + ("arguments",), item.get("arguments"))
            for key in ("output", "error"):
                if isinstance(item.get(key), str):
                    self.add(path + (key,), item[key], "tool", "tool_result", mask_only=False)
        elif typ == "mcp_list_tools":
            for j, tool in enumerate(item.get("tools") or []):
                self.tool_descriptions(tool, path + ("tools", j))
            if isinstance(item.get("error"), str):
                self.add(path + ("error",), item["error"], "tool", "tool_result", mask_only=False)
        elif typ == "mcp_approval_request":
            self.args(path + ("arguments",), item.get("arguments"))
        elif typ == "mcp_approval_response":
            if isinstance(item.get("reason"), str):
                self.add(path + ("reason",), item["reason"], "user", "message")
        elif typ == "local_shell_call":
            command = (item.get("action") or {}).get("command")
            for j, part in enumerate(command or []):
                if isinstance(part, str):
                    self.add(path + ("action", "command", j), part, "assistant", "tool_arguments")
        elif typ == "local_shell_call_output":
            self.tool_output(item.get("output"), path + ("output",))
        else:
            # web/file search calls, computer calls, input_image/input_file items, item_reference, ...
            self.unknown(path, typ, role)

    def tool_output(self, value: Any, path: tuple) -> None:
        if isinstance(value, str):
            self.add(path, value, "tool", "tool_result", mask_only=False)
        elif isinstance(value, list):
            for j, part in enumerate(value):
                ptype = part.get("type") if isinstance(part, dict) else None
                if ptype in {"input_text", "output_text", "text"} and isinstance(part.get("text"), str):
                    self.add(path + (j, "text"), part["text"], "tool", "tool_result", mask_only=False)
                else:
                    self.unknown(path + (j,), ptype, "tool")
        elif value is not None:
            self.unknown(path, type(value).__name__, "tool")

    def anthropic(self, payload: dict[str, Any]) -> None:
        system = payload.get("system")
        if isinstance(system, str):
            self.add(("system",), system, "system", "system")
        elif isinstance(system, list):
            for i, block in enumerate(system):
                if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                    self.add(("system", i, "text"), block["text"], "system", "system")
                else:
                    self.unknown(("system", i), block.get("type") if isinstance(block, dict) else None, "system")
        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            raise BadRequest("messages must be a list")
        for i, message in enumerate(messages):
            if not isinstance(message, dict):
                raise BadRequest(f"messages[{i}] must be an object")
            role = message.get("role", "user")
            content = message.get("content")
            if isinstance(content, str):
                self.add(("messages", i, "content"), content, role, "message")
            elif isinstance(content, list):
                for j, block in enumerate(content):
                    self.anthropic_block(block, ("messages", i, "content", j), role)
            elif content is not None:
                raise BadRequest(f"messages[{i}].content must be a string or a list of blocks")
        for i, tool in enumerate(payload.get("tools") or []):
            self.tool_descriptions(tool, ("tools", i))

    def anthropic_block(self, block: Any, path: tuple, role: str, *, inside_result: bool = False) -> None:
        if not isinstance(block, dict):
            raise BadRequest(f"{locate_path(path)} must be an object")
        typ = block.get("type")
        kind = "tool_result" if inside_result else "message"
        if typ == "text":
            if isinstance(block.get("text"), str):
                self.add(path + ("text",), block["text"], role, kind, mask_only=not inside_result)
            for k, citation in enumerate(block.get("citations") or []):
                if isinstance(citation, dict) and isinstance(citation.get("cited_text"), str):
                    self.add(path + ("citations", k, "cited_text"), citation["cited_text"], role, kind, mask_only=not inside_result)
        elif typ == "tool_result":
            content = block.get("content")
            if isinstance(content, str):
                self.add(path + ("content",), content, "tool", "tool_result", mask_only=False)
            elif isinstance(content, list):
                for k, inner in enumerate(content):
                    self.anthropic_block(inner, path + ("content", k), "tool", inside_result=True)
        elif typ in {"tool_use", "server_tool_use", "mcp_tool_use"}:
            if "input" in block:
                self.json_leaf(path + ("input",), block["input"], role)
        elif typ == "mcp_tool_result":
            content = block.get("content")
            if isinstance(content, str):
                self.add(path + ("content",), content, "tool", "tool_result", mask_only=False)
            elif isinstance(content, list):
                for k, inner in enumerate(content):
                    self.anthropic_block(inner, path + ("content", k), "tool", inside_result=True)
        elif typ in {"thinking", "redacted_thinking"}:
            self.passthrough(path, block, role)   # signed: forwarded untouched
        elif typ == "document":
            source = block.get("source") or {}
            stype = source.get("type") if isinstance(source, dict) else None
            if stype == "text" and isinstance(source.get("data"), str):
                self.add(path + ("source", "data"), source["data"], role, kind, mask_only=not inside_result)
            elif stype == "content":
                # Custom-content document: its own text/image blocks, read like a message's blocks.
                content = source.get("content")
                if isinstance(content, str):
                    self.add(path + ("source", "content"), content, role, kind, mask_only=not inside_result)
                elif isinstance(content, list):
                    for k, inner in enumerate(content):
                        self.anthropic_block(inner, path + ("source", "content", k), role, inside_result=inside_result)
                else:
                    self.unknown(path + ("source",), "content", role)
            elif stype in {"base64", "url", "file"}:
                self.opaque(path, f"document ({stype} source, {source.get('media_type', 'unknown type')})", role)
            else:
                self.unknown(path + ("source",), stype, role)
            for key in ("title", "context"):
                if isinstance(block.get(key), str):
                    self.add(path + (key,), block[key], role, kind)
        elif typ == "image":
            source = block.get("source") or {}
            size = len(source.get("data", "")) * 3 // 4 if isinstance(source.get("data"), str) else None
            self.opaque(path, f"image ({source.get('media_type', source.get('type', '?'))}" + (f", ~{size // 1024} KB)" if size else ")"), role)
        else:
            self.unknown(path, typ, role)


def locate_path(path: tuple) -> str:
    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else str(part))
    return out


def extract(payload: dict[str, Any], api: str, pass_unknown: bool = False) -> list[ContextItem]:
    """Content items of a request. Raises UnknownContent (→ 422) or BadRequest (→ 400)."""
    return extract_with_warnings(payload, api, pass_unknown)[0]


def extract_with_warnings(payload: dict[str, Any], api: str, pass_unknown: bool) -> tuple[list[ContextItem], list[dict[str, str]]]:
    extractor = Extractor(_api(api), pass_unknown)
    getattr(extractor, extractor.api)(payload)
    if payload.get("prompt") is not None:
        # Legacy completions text or a Responses prompt template (with variables): not a known leaf.
        extractor.unknown(("prompt",), "prompt", "user")
    return extractor.items, extractor.warnings


def _api(api: str) -> str:
    # Older callers passed "openai" for Chat Completions.
    return {"openai": API_CHAT}.get(api, api)


def serialize(payload: dict[str, Any], items: list[ContextItem]) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    for item in items:
        if item.reasoning or item.opaque:
            continue
        target = result
        for part in item.path[:-1]:
            target = target[part]
        value = item.sanitized
        if item.json_value:
            value = json.loads(value)
        target[item.path[-1]] = value
    return result
