"""SSE forwarding with argument buffering only; non-tool events stay verbatim."""
from __future__ import annotations

import copy
import json

from .adapter import restore_arguments, restore_tool_arguments

# The upstream is untrusted: one SSE frame, or one tool call's buffered arguments, may not grow without bound.
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_ARGUMENT_CHARS = 8 * 1024 * 1024


class StreamLimitError(RuntimeError):
    pass


class SSETransformer:
    def __init__(self, entities, observe=None):
        self.buffer = b""
        self.arguments = {}
        self.templates = {}
        self.entities = entities
        self.observe = observe

    def _append(self, key, text):
        value = self.arguments.get(key, "") + (text if isinstance(text, str) else "")
        if len(value) > MAX_ARGUMENT_CHARS:
            raise StreamLimitError(f"tool call arguments exceed {MAX_ARGUMENT_CHARS} characters")
        self.arguments[key] = value

    def feed(self, chunk: bytes) -> list[bytes]:
        self.buffer += chunk
        output = []
        while True:
            lf = self.buffer.find(b"\n\n")
            crlf = self.buffer.find(b"\r\n\r\n")
            if lf < 0 and crlf < 0:
                break
            index, size = (crlf, 4) if crlf >= 0 and (lf < 0 or crlf < lf) else (lf, 2)
            frame, self.buffer = self.buffer[:index + size], self.buffer[index + size:]
            output.extend(self.frame(frame))
        if len(self.buffer) > MAX_FRAME_BYTES:
            raise StreamLimitError(f"upstream SSE frame exceeds {MAX_FRAME_BYTES} bytes")
        return output

    def frame(self, frame):
        try:
            lines = frame.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            # Not valid UTF-8, so not a JSON event we could restore: forward it untouched.
            return [frame]
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
        prefix = []
        # OpenAI Chat: tool arguments can arrive in arbitrary partial JSON chunks.
        for choice in value.get("choices", []):
            ci = choice.get("index", 0)
            for call in choice.get("delta", {}).get("tool_calls", []):
                fn = call.get("function", {})
                if "arguments" in fn:
                    key = ("chat", ci, call.get("index", 0))
                    self._append(key, fn["arguments"])
                    template = copy.deepcopy(value)
                    template["choices"] = [{"index": ci, "delta": {"tool_calls": [{"index": call.get("index", 0), "function": {"arguments": ""}}]}, "finish_reason": None}]
                    self.templates[key] = template
                    fn["arguments"] = ""
            if choice.get("finish_reason"):
                for key in list(self.arguments):
                    if key[:2] == ("chat", ci):
                        template = self.templates.pop(key)
                        template["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] = restore_arguments(self.arguments.pop(key), self.entities)
                        prefix.append(self.encode(template))
        typ = value.get("type", "")
        if typ == "content_block_start" and value.get("content_block", {}).get("type") == "tool_use":
            block = value["content_block"]
            restored = restore_tool_arguments({"content": [block]}, self.entities, "anthropic")
            value["content_block"] = restored["content"][0]
        if typ == "content_block_delta" and value.get("delta", {}).get("type") == "input_json_delta":
            key = ("anthropic", value["index"])
            self._append(key, value["delta"].get("partial_json", ""))
            self.templates[key] = value
            return prefix  # emit the complete argument JSON immediately before block_stop
        if typ == "content_block_stop":
            key = ("anthropic", value["index"])
            if key in self.arguments:
                template = copy.deepcopy(self.templates.pop(key))
                template["delta"]["partial_json"] = restore_arguments(self.arguments.pop(key), self.entities)
                prefix.append(self.encode(template))
        if typ == "response.function_call_arguments.delta":
            key = ("responses", value.get("item_id"), value.get("output_index"))
            self._append(key, value.get("delta", ""))
            value["delta"] = ""
        if typ == "response.function_call_arguments.done":
            key = ("responses", value.get("item_id"), value.get("output_index"))
            raw = self.arguments.pop(key, value.get("arguments", ""))
            restored = restore_arguments(raw, self.entities)
            delta = copy.deepcopy(value)
            delta["type"] = "response.function_call_arguments.delta"
            delta.pop("arguments", None)
            delta["delta"] = restored
            prefix.append(self.encode(delta))
            value["arguments"] = restored
        if typ in {"response.output_item.done", "response.output_item.added"} and value.get("item", {}).get("type") == "function_call":
            item = value["item"]
            item["arguments"] = restore_arguments(item.get("arguments", ""), self.entities)
        if isinstance(value.get("response"), dict):
            value["response"] = restore_tool_arguments(value["response"], self.entities, "openai")
        return prefix + ([frame] if value == original else [self.encode(value, lines)])

    @staticmethod
    def encode(value, lines=()):
        prefix = "\n".join(line for line in lines if not line.startswith("data:") and line)
        if not prefix and value.get("type", "").startswith(("content_block", "response.")):
            prefix = "event: " + value["type"]
        return ((prefix + "\n" if prefix else "") + "data: " + json.dumps(value, ensure_ascii=False) + "\n\n").encode()

    def finish(self):
        if self.arguments:
            raise RuntimeError("Upstream ended with incomplete tool arguments")
        return self.buffer
