"""Incremental response observations, independent of the transport/UI."""
import copy
import json

from .model import ContextItem


class ResponseObserver:
    def __init__(self, session, publish):
        self.session = session
        self.publish = publish
        self.items = {}

    def put(self, key, kind, value, append=False):
        item = self.items.get(key)
        if item is None:
            item = ContextItem(f"response-{self.session.request_count}-{key}", kind, "assistant", "", "", False, kind == "reasoning")
            self.items[key] = item
            self.session.items.append(item)
        item.original = item.original + value if append else value
        item.sanitized = item.original
        item.revision += 1
        self.publish(self.session)

    def event(self, data):
        for choice in data.get("choices", []):
            idx = choice.get("index", 0)
            msg = choice.get("delta", choice.get("message", {}))
            for field, kind in (("content", "message"), ("reasoning_content", "reasoning"), ("reasoning", "reasoning")):
                if isinstance(msg.get(field), str):
                    self.put(f"chat-{idx}-{field}", kind, msg[field], "delta" in choice)
            if "reasoning_details" in msg:
                self.put(f"chat-{idx}-reasoning-details", "reasoning", json.dumps(msg["reasoning_details"], ensure_ascii=False))
            for call in msg.get("tool_calls", []):
                key = f"chat-{idx}-tool-{call.get('index', call.get('id', 0))}"
                if call.get("function", {}).get("arguments"):
                    self.put(key, "tool_arguments", call["function"]["arguments"], "delta" in choice)
        typ = data.get("type", "")
        if typ == "content_block_start":
            block = data.get("content_block", {})
            index = data.get("index", 0)
            self.block(block, f"anthropic-{index}")
        if typ == "content_block_delta":
            delta = data.get("delta", {})
            key = f"anthropic-{data.get('index', 0)}"
            if delta.get("type") == "text_delta":
                self.put(key, "message", delta.get("text", ""), True)
            elif delta.get("type") == "thinking_delta":
                self.put(key, "reasoning", delta.get("thinking", ""), True)
            elif delta.get("type") == "input_json_delta":
                self.put(key, "tool_arguments", delta.get("partial_json", ""), True)
            elif delta.get("type") == "signature_delta":
                self.put(key + "-signature", "reasoning", delta.get("signature", ""), True)
        if typ.startswith("response."):
            key = f"responses-{data.get('item_id', data.get('output_index', 0))}-{data.get('summary_index', data.get('content_index', 0))}"
            if typ in {"response.output_text.delta", "response.reasoning_summary_text.delta", "response.reasoning_text.delta", "response.function_call_arguments.delta"}:
                kind = "tool_arguments" if "arguments" in typ else "reasoning" if "reasoning" in typ else "message"
                self.put(key, kind, data.get("delta", ""), True)
            if typ == "response.output_item.done":
                self.block(data.get("item", {}), key + "-complete")
        for i, block in enumerate(data.get("content", [])):
            self.block(block, f"anthropic-{i}")
        for i, block in enumerate(data.get("output", [])):
            self.block(block, f"responses-{i}")

    def block(self, block, key):
        typ = block.get("type")
        if typ in {"thinking", "redacted_thinking", "reasoning"}:
            self.put(key, "reasoning", json.dumps(block, ensure_ascii=False))
        elif typ in {"tool_use", "function_call"}:
            self.put(key, "tool_arguments", block.get("arguments", json.dumps(block.get("input", {}), ensure_ascii=False)))
        elif typ == "text":
            self.put(key, "message", block.get("text", ""))
        elif typ == "message":
            for i, content in enumerate(block.get("content", [])):
                if isinstance(content, dict) and content.get("text"):
                    self.put(key + f"-{i}", "message", content["text"])
