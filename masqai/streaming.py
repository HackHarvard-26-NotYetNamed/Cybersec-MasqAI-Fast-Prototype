"""SSE forwarding with streaming restore.

Frames pass through unchanged unless they carry agent tool-call arguments. Those are restored as they
stream (restore.ArgumentStream): only a trailing fragment that could start a placeholder is held back,
and flushed as one extra delta right before the call ends. A placeholder split across SSE frames, or
across JSON-escaped argument deltas, is restored whole. Frames that are not valid UTF-8 are forwarded
unchanged rather than breaking the stream.

Inbound tool guardrail: once a tool call starts, every later frame is held back (restored as usual)
until the upstream stream ends. The caller then inspects the complete calls (pending_calls) and either
releases the held frames or rejects calls: `rewrite` turns their arguments into a harmless command
(restore.REJECTION_TEXT), `error` drops the held frames for an error event. Text before the first tool
call streams without delay.
"""
from __future__ import annotations

import copy
import json
from typing import Any, Callable

from .restore import (AGENT_ANTHROPIC, AGENT_RESPONSES, REJECTED_COMMAND, ArgumentStream, StreamLimitError, find_placeholders,
                      rejected_arguments, rejected_shell_action, rejected_value, restore_arguments, restore_responses_item,
                      restore_value)

# The upstream is untrusted: one SSE frame may not grow without bound.
MAX_FRAME_BYTES = 8 * 1024 * 1024

__all__ = ["SSETransformer", "StreamLimitError", "MAX_FRAME_BYTES"]



class SSETransformer:
    def __init__(self, table: dict[str, str], observe: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.table = table
        self.observe = observe
        self.buffer = b""
        self.streams: dict[tuple, ArgumentStream] = {}
        self.anthropic_types: dict[int, str] = {}      # content block index -> block type
        self.responses_types: dict[str, str] = {}      # item id -> item type
        # Guardrail: frames held back since the first tool call, and each call's raw (placeholder) arguments.
        self.holding = False
        self.held: list[bytes] = []
        self.calls: dict[tuple, dict[str, Any]] = {}
        self.emitted = False      # whether any frame has gone to the client yet

    # ---------- framing ----------
    def feed(self, chunk: bytes) -> list[bytes]:
        self.buffer += chunk
        output: list[bytes] = []
        while True:
            lf, crlf = self.buffer.find(b"\n\n"), self.buffer.find(b"\r\n\r\n")
            if lf < 0 and crlf < 0:
                break
            index, size = (crlf, 4) if crlf >= 0 and (lf < 0 or crlf < lf) else (lf, 2)
            frame, self.buffer = self.buffer[:index + size], self.buffer[index + size:]
            output.extend(self.frame(frame))
        if len(self.buffer) > MAX_FRAME_BYTES:
            raise StreamLimitError(f"upstream SSE frame exceeds {MAX_FRAME_BYTES} bytes")
        return output

    def finish(self) -> bytes:
        return self.buffer

    def stream(self, key: tuple, json_mode: bool = True) -> ArgumentStream:
        if key not in self.streams:
            self.streams[key] = ArgumentStream(self.table, json_mode)
        return self.streams[key]

    def flush(self, key: tuple) -> str:
        stream = self.streams.pop(key, None)
        return stream.flush() if stream else ""

    @staticmethod
    def encode(value: dict[str, Any], event: str | None = None) -> bytes:
        head = f"event: {event}\n" if event else ""
        return (head + "data: " + json.dumps(value, ensure_ascii=False) + "\n\n").encode()

    # ---------- guardrail ----------
    def _call(self, key: tuple, api: str, tool: str | None = None) -> dict[str, Any]:
        self.holding = True
        call = self.calls.setdefault(key, {"api": api, "tool": tool or "tool", "raw": "", "final": None})
        if tool:
            call["tool"] = tool
        return call

    def pending_calls(self) -> list[dict[str, Any]]:
        """Complete tool calls held back that carry placeholders: what the guardrail must inspect."""
        out = []
        for key, call in self.calls.items():
            arguments = call["final"] if call["final"] is not None else call["raw"]
            placeholders = find_placeholders(arguments)
            if placeholders:
                out.append({"key": key, "api": call["api"], "tool": call["tool"], "arguments": arguments, "placeholders": placeholders})
        return out

    def release(self, rejected: set[tuple] | None = None) -> list[bytes]:
        """The held frames, with the `rejected` calls' arguments rewritten (restore.REJECTION_TEXT)."""
        held, self.held, self.holding = self.held, [], False
        if not rejected:
            return held
        first: set[tuple] = set()
        out: list[bytes] = []
        for frame in held:
            parsed = self._parse(frame)
            if parsed is None:
                out.append(frame)
                continue
            event, value = parsed
            out.append(self.encode(value, event) if self._reject(value, rejected, first) else frame)
        return out

    def error_frames(self, message: str) -> list[bytes]:
        """`error` mode after text was already streamed: drop the held frames, end with an error event."""
        self.held, self.holding = [], False
        body = {"type": "masqai_tool_rejected", "message": message}
        if any(c["api"] == "anthropic" for c in self.calls.values()):
            return [self.encode({"type": "error", "error": body}, "error")]
        if any(c["api"] == "responses" for c in self.calls.values()):
            return [self.encode({"type": "error", "code": "masqai_tool_rejected", "message": message, "param": None}, "error")]
        return [self.encode({"error": body})]

    def _reject(self, value: dict[str, Any], rejected: set[tuple], first: set[tuple]) -> bool:
        """Rewrite one held frame's fragments of rejected calls. The first fragment of each call carries the
        whole rewritten arguments, later fragments become empty. Returns whether anything changed."""
        changed = False

        def fragment(key: tuple) -> str:
            nonlocal changed
            changed = True
            if key in first:
                return ""
            first.add(key)
            call = self.calls[key]
            return rejected_arguments(call["final"] if call["final"] is not None else call["raw"])

        for choice in value.get("choices") or []:
            ci = choice.get("index", 0)
            delta = choice.get("delta") or {}
            for tc in delta.get("tool_calls") or []:
                key = ("chat", ci, tc.get("index", 0))
                if key in rejected and isinstance((tc.get("function") or {}).get("arguments"), str):
                    tc["function"]["arguments"] = fragment(key)
            fc = delta.get("function_call") or {}
            if ("chat-fc", ci) in rejected and isinstance(fc.get("arguments"), str):
                fc["arguments"] = fragment(("chat-fc", ci))
        typ = value.get("type", "")
        key = ("anthropic", value.get("index", 0))
        if key in rejected:
            if typ == "content_block_start" and (value.get("content_block") or {}).get("input"):
                value["content_block"]["input"] = rejected_value(value["content_block"]["input"])
                first.add(key)
                changed = True
            elif typ == "content_block_delta" and (value.get("delta") or {}).get("type") == "input_json_delta":
                value["delta"]["partial_json"] = fragment(key)
        if typ.startswith("response."):
            item_key = ("responses", value.get("item_id") or (value.get("item") or {}).get("id"))
            if item_key in rejected:
                if typ in {"response.function_call_arguments.delta", "response.custom_tool_call_input.delta"}:
                    custom = "custom" in typ
                    value["delta"] = (REJECTED_COMMAND if item_key not in first else "") if custom else fragment(item_key)
                    first.add(item_key)
                    changed = True
                elif typ == "response.function_call_arguments.done":
                    value["arguments"] = rejected_arguments(value.get("arguments") or "")
                    changed = True
                elif typ == "response.custom_tool_call_input.done":
                    value["input"] = REJECTED_COMMAND
                    changed = True
            for item in [value.get("item")] + list((value.get("response") or {}).get("output") or []):
                if isinstance(item, dict) and ("responses", item.get("id")) in rejected:
                    self._reject_item(item, typ == "response.output_item.added")
                    changed = True
        return changed

    @staticmethod
    def _reject_item(item: dict[str, Any], added: bool) -> None:
        if item.get("type") == "function_call" and isinstance(item.get("arguments"), str):
            item["arguments"] = "" if added else rejected_arguments(item["arguments"])
        elif item.get("type") == "custom_tool_call" and isinstance(item.get("input"), str):
            item["input"] = "" if added else REJECTED_COMMAND
        elif item.get("type") == "local_shell_call":
            item["action"] = rejected_shell_action(item.get("action"))

    @staticmethod
    def _parse(frame: bytes) -> tuple[str | None, dict[str, Any]] | None:
        try:
            lines = frame.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            return None
        data = "\n".join(line[5:].lstrip(" ") for line in lines if line.startswith("data:"))
        try:
            value = json.loads(data)
        except ValueError:
            return None
        if not isinstance(value, dict):
            return None
        return next((line[6:].strip() for line in lines if line.startswith("event:")), None), value

    # ---------- one frame ----------
    def frame(self, frame: bytes) -> list[bytes]:
        out = self._frame(frame)
        if self.holding:
            self.held.extend(out)
            return []
        if out:
            self.emitted = True
        return out

    def _frame(self, frame: bytes) -> list[bytes]:
        try:
            lines = frame.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            return [frame]
        event = next((line[6:].strip() for line in lines if line.startswith("event:")), None)
        data = "\n".join(line[5:].lstrip(" ") for line in lines if line.startswith("data:"))
        if not data or data == "[DONE]":
            return [frame]
        try:
            value = json.loads(data)
        except ValueError:
            return [frame]
        if not isinstance(value, dict):
            return [frame]
        if self.observe:
            self.observe(copy.deepcopy(value))
        original = copy.deepcopy(value)
        before: list[bytes] = []
        if "choices" in value:
            before += self.chat(value)
        typ = value.get("type", "")
        if typ.startswith(("content_block", "message")):
            before += self.anthropic(value, event)
        if typ.startswith("response."):
            before += self.responses(value, event)
        if value == original:
            return before + [frame]
        return before + [self.encode(value, event)]

    # ---------- Chat Completions ----------
    def chat(self, value: dict[str, Any]) -> list[bytes]:
        before: list[bytes] = []
        for choice in value.get("choices") or []:
            ci = choice.get("index", 0)
            delta = choice.get("delta") or {}
            for call in delta.get("tool_calls") or []:
                fn = call.get("function") or {}
                record = self._call(("chat", ci, call.get("index", 0)), "chat", fn.get("name"))
                if isinstance(fn.get("arguments"), str):
                    record["raw"] += fn["arguments"]
                    fn["arguments"] = self.stream(("chat", ci, call.get("index", 0))).feed(fn["arguments"])
            if isinstance(delta.get("function_call"), dict):
                fc = delta["function_call"]
                record = self._call(("chat-fc", ci), "chat", fc.get("name"))
                if isinstance(fc.get("arguments"), str):
                    record["raw"] += fc["arguments"]
                    fc["arguments"] = self.stream(("chat-fc", ci)).feed(fc["arguments"])
            if choice.get("finish_reason"):
                for key in [k for k in self.streams if k[0] in {"chat", "chat-fc"} and k[1] == ci]:
                    rest = self.flush(key)
                    if not rest:
                        continue
                    flush = {k: v for k, v in value.items() if k not in {"choices", "usage"}}
                    if key[0] == "chat":
                        flush["choices"] = [{"index": ci, "delta": {"tool_calls": [{"index": key[2], "function": {"arguments": rest}}]}, "finish_reason": None}]
                    else:
                        flush["choices"] = [{"index": ci, "delta": {"function_call": {"arguments": rest}}, "finish_reason": None}]
                    before.append(self.encode(flush))
        return before

    # ---------- Anthropic Messages ----------
    def anthropic(self, value: dict[str, Any], event: str | None) -> list[bytes]:
        typ = value["type"]
        index = value.get("index", 0)
        if typ == "content_block_start":
            block = value.get("content_block") or {}
            self.anthropic_types[index] = block.get("type", "")
            if block.get("type") in AGENT_ANTHROPIC:
                record = self._call(("anthropic", index), "anthropic", block.get("name"))
                if block.get("input"):
                    record["final"] = json.dumps(block["input"], ensure_ascii=False)
            if block.get("type") in AGENT_ANTHROPIC and "input" in block:
                block["input"] = restore_value(block["input"], self.table)
        elif typ == "content_block_delta":
            delta = value.get("delta") or {}
            if delta.get("type") == "input_json_delta" and self.anthropic_types.get(index) in AGENT_ANTHROPIC:
                record = self._call(("anthropic", index), "anthropic")
                record["raw"] += delta.get("partial_json", "")
                if record["final"] is not None and record["raw"]:
                    record["final"] = None      # the deltas carry the input
                delta["partial_json"] = self.stream(("anthropic", index)).feed(delta.get("partial_json", ""))
        elif typ == "content_block_stop":
            rest = self.flush(("anthropic", index))
            if rest:
                return [self.encode({"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": rest}},
                                    "content_block_delta")]
        return []

    # ---------- Responses ----------
    def responses(self, value: dict[str, Any], event: str | None) -> list[bytes]:
        typ = value["type"]
        item_id = value.get("item_id")
        if typ in {"response.output_item.added", "response.output_item.done"}:
            item = value.get("item") or {}
            if item.get("type") in AGENT_RESPONSES and item.get("id"):
                record = self._call(("responses", item["id"]), "responses", item.get("name") or item["type"])
                payload = item.get("action") if item["type"] == "local_shell_call" else item.get("arguments", item.get("input"))
                if payload and typ == "response.output_item.done" or item["type"] == "local_shell_call":
                    record["final"] = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
        if item_id and typ in {"response.function_call_arguments.delta", "response.custom_tool_call_input.delta"}:
            self._call(("responses", item_id), "responses")["raw"] += value.get("delta", "")
        if typ == "response.output_item.added":
            item = value.get("item") or {}
            if item.get("id"):
                self.responses_types[item["id"]] = item.get("type", "")
            restore_responses_item(item, self.table)
        elif typ == "response.function_call_arguments.delta" and self.responses_types.get(item_id, "function_call") == "function_call":
            value["delta"] = self.stream(("responses", item_id), True).feed(value.get("delta", ""))
        elif typ == "response.custom_tool_call_input.delta":
            value["delta"] = self.stream(("responses-custom", item_id), False).feed(value.get("delta", ""))
        elif typ in {"response.function_call_arguments.done", "response.custom_tool_call_input.done"}:
            custom = "custom" in typ
            rest = self.flush(("responses-custom" if custom else "responses", item_id))
            field = "input" if custom else "arguments"
            if isinstance(value.get(field), str):
                value[field] = restore_arguments(value[field], self.table) if not custom else self._text(value[field])
            if rest:
                delta = {k: v for k, v in value.items() if k not in {"arguments", "input"}}
                delta["type"] = typ.replace(".done", ".delta")
                delta["delta"] = rest
                return [self.encode(delta, delta["type"])]
        elif typ == "response.output_item.done":
            restore_responses_item(value.get("item"), self.table)
        if isinstance(value.get("response"), dict):
            for item in value["response"].get("output") or []:
                restore_responses_item(item, self.table)
        return []

    def _text(self, text: str) -> str:
        from .restore import restore_text
        return restore_text(text, self.table)
