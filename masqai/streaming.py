"""SSE forwarding with streaming restore.

Frames pass through unchanged unless they carry agent tool-call arguments. Those are restored as they
stream (restore.ArgumentStream): only a trailing fragment that could start a placeholder is held back,
and flushed as one extra delta right before the call ends. A placeholder split across SSE frames, or
across JSON-escaped argument deltas, is restored whole. Frames that are not valid UTF-8 are forwarded
unchanged rather than breaking the stream.
"""
from __future__ import annotations

import copy
import json
from typing import Any, Callable

from .restore import AGENT_ANTHROPIC, ArgumentStream, StreamLimitError, restore_arguments, restore_responses_item, restore_text, restore_value

# The upstream is untrusted: one SSE frame may not grow without bound.
MAX_FRAME_BYTES = 8 * 1024 * 1024

__all__ = ["SSETransformer", "StreamLimitError", "MAX_FRAME_BYTES"]


class SSETransformer:
    def __init__(self, table: dict[str, str], observe: Callable[[dict[str, Any]], None] | None = None,
                 guardrail_check: Callable[[str, str], bool] | None = None) -> None:
        self.table = table
        self.observe = observe
        self.guardrail_check = guardrail_check
        self.buffer = b""
        self.streams: dict[tuple, ArgumentStream] = {}
        self.anthropic_types: dict[int, str] = {}      # content block index -> block type
        self.responses_types: dict[str, str] = {}      # item id -> item type
        self.chat_template: dict[str, Any] = {}
        self.held_frames: dict[int, list[dict[str, Any]]] = {}  # choice_idx -> accumulated events if has placeholders
        self.blocked_choices: set[int] = set()

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

    # ---------- one frame ----------
    def frame(self, frame: bytes) -> list[bytes]:
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
        if not value:
            return before
        return before + [self.encode(value, event)]

    # ---------- Chat Completions ----------
    def chat(self, value: dict[str, Any]) -> list[bytes]:
        before: list[bytes] = []
        for choice in value.get("choices") or []:
            ci = choice.get("index", 0)
            if ci in self.blocked_choices:
                value.clear()
                return []
            delta = choice.get("delta") or {}
            has_tool_delta = bool(delta.get("tool_calls") or delta.get("function_call"))

            # If tool calls are present, buffer frames until the tool call finishes so we can inspect
            if has_tool_delta or ci in self.held_frames:
                self.held_frames.setdefault(ci, []).append(copy.deepcopy(value))
                for call in delta.get("tool_calls") or []:
                    fn = call.get("function") or {}
                    call_idx = call.get("index", 0)
                    if isinstance(fn.get("arguments"), str):
                        self.stream(("chat", ci, call_idx)).feed(fn["arguments"])
                if isinstance((delta.get("function_call") or {}).get("arguments"), str):
                    self.stream(("chat-fc", ci)).feed(delta["function_call"]["arguments"])

                if choice.get("finish_reason"):
                    all_args = ""
                    for key in [k for k in list(self.streams.keys()) if k[0] in {"chat", "chat-fc"} and k[1] == ci]:
                        stream_obj = self.streams.pop(key, None)
                        rest = stream_obj.flush() if stream_obj else ""
                        all_args += rest

                    has_secret = any(v in all_args for v in self.table.values() if v)
                    is_net = any(x in all_args.lower() for x in (
                        "http://", "https://", "ftp://", "ssh://", "curl", "wget", "fetch", "requests", "nc ", "netcat", "/dev/tcp", "socket", "git push"
                    ))
                    if has_secret and is_net:
                        self.blocked_choices.add(ci)
                        self.held_frames.pop(ci, None)
                        notice = "> [MasqAI] Blocked streamed tool call: exfiltration attempt detected"
                        block_msg = {k: v for k, v in value.items() if k not in {"choices", "usage"}}
                        block_msg["choices"] = [{"index": ci, "delta": {"role": "assistant", "content": notice}, "finish_reason": "stop"}]
                        value.clear()
                        return [self.encode(block_msg)]

                    # Safe: emit the frames normally with restore_arguments applied to full arguments
                    frames = self.held_frames.pop(ci, [])
                    out_bytes = []
                    for f in frames:
                        for ch in f.get("choices") or []:
                            if ch.get("index") == ci:
                                d = ch.get("delta") or {}
                                for tc in d.get("tool_calls") or []:
                                    fn = tc.get("function") or {}
                                    if isinstance(fn.get("arguments"), str):
                                        fn["arguments"] = ArgumentStream(self.table, True).feed(fn["arguments"])
                                if isinstance((d.get("function_call") or {}).get("arguments"), str):
                                    d["function_call"]["arguments"] = ArgumentStream(self.table, True).feed(d["function_call"]["arguments"])
                        out_bytes.append(self.encode(f))
                    if rest:
                        flush = {k: v for k, v in value.items() if k not in {"choices", "usage"}}
                        flush["choices"] = [{"index": ci, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": rest}}]}, "finish_reason": None}]
                        out_bytes.append(self.encode(flush))
                    value.clear()
                    return out_bytes
                value.clear()
                return []

            for call in delta.get("tool_calls") or []:
                fn = call.get("function") or {}
                if isinstance(fn.get("arguments"), str):
                    fn["arguments"] = self.stream(("chat", ci, call.get("index", 0))).feed(fn["arguments"])
            if isinstance((delta.get("function_call") or {}).get("arguments"), str):
                delta["function_call"]["arguments"] = self.stream(("chat-fc", ci)).feed(delta["function_call"]["arguments"])
            if choice.get("finish_reason"):
                for key in [k for k in list(self.streams.keys()) if k[0] in {"chat", "chat-fc"} and k[1] == ci]:
                    stream_obj = self.streams.pop(key, None)
                    rest = stream_obj.flush() if stream_obj else ""
                    if not rest:
                        continue
                    flush = {k: v for k, v in value.items() if k not in {"choices", "usage"}}
                    if key[0] == "chat":
                        flush["choices"] = [{"index": ci, "delta": {"tool_calls": [{"index": key[2], "function": {"arguments": rest}}]}, "finish_reason": None}]
                    else:
                        flush["choices"] = [{"index": ci, "delta": {"function_call": {"arguments": rest}}, "finish_reason": None}]
                    before.append(self.encode(flush))

        return before
        return before

    # ---------- Anthropic Messages ----------
    def anthropic(self, value: dict[str, Any], event: str | None) -> list[bytes]:
        typ = value["type"]
        index = value.get("index", 0)
        if typ == "content_block_start":
            block = value.get("content_block") or {}
            self.anthropic_types[index] = block.get("type", "")
            if block.get("type") in AGENT_ANTHROPIC and "input" in block:
                block["input"] = restore_value(block["input"], self.table)
        elif typ == "content_block_delta":
            delta = value.get("delta") or {}
            if delta.get("type") == "input_json_delta" and self.anthropic_types.get(index) in AGENT_ANTHROPIC:
                delta["partial_json"] = self.stream(("anthropic", index)).feed(delta.get("partial_json", ""))
        elif typ == "content_block_stop":
            rest = self.flush(("anthropic", index))
            if rest:
                return [self.encode({"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": rest}},
                                    "content_block_delta")]
        return []
        return []

    # ---------- Responses ----------
    def responses(self, value: dict[str, Any], event: str | None) -> list[bytes]:
        typ = value["type"]
        item_id = value.get("item_id")
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
