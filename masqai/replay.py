"""Replay export: one session in the public site's replay format (a contract: don't rename fields).

At send time each request records its NEW items (raw text, sanitized text, and every decision as
source · verdict), the response's text and tool calls (arguments as sent by the untrusted model and as
restored for the agent), and whether it was blocked. RAM only. The export endpoint is available only
when the gateway was started with --playground, because it contains raw values; with synthetic=1 the
machine's real host identifiers are replaced with fixed fake ones.
"""
from __future__ import annotations

import json
import time
from typing import Any

from .detectors import host_values
from .model import ContextItem, Session
from .ops import address
from .restore import restore_arguments, restore_map, restore_text

FAKE_HOST = {"HOST": "DESKTOP-7Q2XK9M", "USERNAME": "alice"}


def item_decisions(session: Session, item: ContextItem) -> list[dict[str, Any]]:
    """Every op that touched this item, in replay-contract form."""
    if item.reasoning or item.opaque or not isinstance(item.original, str):
        return []
    text = item.original
    ops: list[dict[str, Any]] = []
    for span in item.spans:
        entity = session.entities.get(span["token"])
        if entity is None:
            continue
        if span["origin"] == "model":
            source = "model"
        elif entity.origin.startswith("detector") and item.id in entity.detected_in:
            source = "detector"
        else:
            source = "auto"
        reason = entity.reason if source != "auto" else "exact copy of a known value"
        ops.append(_op("mask", entity.cls, entity.entity_type, span["placeholder"], span["alias"], text[span["start"]:span["end"]],
                       source, "applied", reason))
    for skipped in item.unmasked:
        entity = session.entities.get(skipped["token"])
        if entity is None:
            continue
        vetoed = skipped["reason"].startswith("vetoed")
        reason = session.veto_reasons.get((item.id, skipped["start"], skipped["end"])) if vetoed else None
        ops.append(_op("mask", entity.cls, entity.entity_type, entity.token, False, text[skipped["start"]:skipped["end"]],
                       "auto", "vetoed" if vetoed else "left_as_is",
                       reason or ("the security model undid it" if vetoed else "inside a longer word")))
    for hide in item.hides:
        ops.append({**_op("hide", hide["class"], None, None, False, text[hide["start"]:hide["end"]], "model", "applied", hide["reason"]),
                    "summary": hide["summary"]})
    for rep in item.replaces:
        ops.append({**_op("replace", rep["class"], None, None, False, text[rep["start"]:rep["end"]], "model", "applied", rep["reason"]),
                    "with": rep["with"]})
    for rejected in session.rejected.get(item.id, []):
        raw = rejected["op"] if isinstance(rejected["op"], dict) else {}
        kind = raw.get("op") if raw.get("op") in {"mask", "hide", "replace", "relink", "unmask"} else "mask"
        value = raw.get("text") if isinstance(raw.get("text"), str) else raw.get("first") if isinstance(raw.get("first"), str) else None
        ops.append(_op(kind, raw.get("class") if raw.get("class") in {"secret", "intel"} else ("intel" if kind in {"hide", "replace"} else "secret"),
                       raw.get("type") if isinstance(raw.get("type"), str) else None, None, bool(raw.get("alias")), value,
                       "model", "rejected_invalid", rejected["error"]))
    return ops


def _op(op: str, cls: str, type_: str | None, placeholder: str | None, alias: bool, value: str | None,
        source: str, verdict: str, reason: str | None) -> dict[str, Any]:
    return {"op": op, "class": cls, "type": type_, "placeholder": placeholder, "alias": alias, "value": value,
            "with": None, "summary": None, "source": source, "verdict": verdict, "reason": reason}


# ---------- responses ----------

class ResponseRecorder:
    """Collects the untrusted model's text and tool calls from a body or from streamed events."""

    def __init__(self) -> None:
        self.text = ""
        self.calls: dict[Any, dict[str, str]] = {}
        self.order: list[Any] = []

    def _call(self, key: Any, name: str | None = None) -> dict[str, str]:
        if key not in self.calls:
            self.calls[key] = {"name": name or "tool", "args": ""}
            self.order.append(key)
        elif name:
            self.calls[key]["name"] = name
        return self.calls[key]

    def event(self, value: dict[str, Any]) -> None:
        for choice in value.get("choices") or []:
            delta = choice.get("delta") or choice.get("message") or {}
            if isinstance(delta.get("content"), str):
                self.text += delta["content"]
            for call in delta.get("tool_calls") or []:
                fn = call.get("function") or {}
                entry = self._call(("chat", choice.get("index", 0), call.get("index", call.get("id", 0))), fn.get("name"))
                entry["args"] += fn.get("arguments") or ""
        typ = value.get("type", "")
        if typ == "content_block_start":
            block = value.get("content_block") or {}
            if block.get("type") == "tool_use":
                self._call(("anthropic", value.get("index", 0)), block.get("name"))
        elif typ == "content_block_delta":
            delta = value.get("delta") or {}
            if delta.get("type") == "text_delta":
                self.text += delta.get("text", "")
            elif delta.get("type") == "input_json_delta" and ("anthropic", value.get("index", 0)) in self.calls:
                self.calls[("anthropic", value.get("index", 0))]["args"] += delta.get("partial_json", "")
        elif typ == "response.output_text.delta":
            self.text += value.get("delta", "")
        elif typ == "response.output_item.added":
            item = value.get("item") or {}
            if item.get("type") in {"function_call", "custom_tool_call"}:
                self._call(("responses", item.get("id")), item.get("name"))
        elif typ in {"response.function_call_arguments.delta", "response.custom_tool_call_input.delta"}:
            if ("responses", value.get("item_id")) in self.calls:
                self.calls[("responses", value.get("item_id"))]["args"] += value.get("delta", "")
        elif typ == "response.output_item.done":
            item = value.get("item") or {}
            if item.get("type") == "local_shell_call":
                self._call(("responses", item.get("id")), "local_shell")["args"] = json.dumps(item.get("action", {}), ensure_ascii=False)

    def body(self, data: dict[str, Any]) -> None:
        self.event(data)   # Chat: choices[].message
        for i, block in enumerate(data.get("content") or []):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                self.text += block.get("text", "")
            elif block.get("type") == "tool_use":
                self._call(("anthropic", i), block.get("name"))["args"] = json.dumps(block.get("input", {}), ensure_ascii=False)
        for item in data.get("output") or []:
            if not isinstance(item, dict):
                continue
            typ = item.get("type")
            if typ == "message":
                self.text += "".join(p.get("text", "") for p in item.get("content") or [] if isinstance(p, dict))
            elif typ == "function_call":
                self._call(("responses", item.get("id")), item.get("name"))["args"] = item.get("arguments", "")
            elif typ == "custom_tool_call":
                self._call(("responses", item.get("id")), item.get("name"))["args"] = item.get("input", "")
            elif typ == "local_shell_call":
                self._call(("responses", item.get("id")), "local_shell")["args"] = json.dumps(item.get("action", {}), ensure_ascii=False)

    def result(self, table: dict[str, str]) -> dict[str, Any]:
        calls = []
        for key in self.order:
            call = self.calls[key]
            calls.append({"name": call["name"], "argsSent": call["args"], "argsRestored": restore_arguments(call["args"], table)})
        return {"text": self.text, "calls": calls}


# ---------- recording ----------

def record_request(session: Session, items: list[ContextItem], seen_ids: set[str], blocked: dict[str, Any] | None) -> dict[str, Any]:
    """Store what this request added to the session, as the untrusted model received it."""
    new = []
    for item in items:
        if item.id in seen_ids or item.kind == "tool_definition" or item.reasoning:
            continue
        new.append({"id": item.id, "role": item.role, "kind": item.kind, "raw": item.original if isinstance(item.original, str) else "",
                    "sanitized": "" if blocked else (item.sanitized if isinstance(item.sanitized, str) else ""),
                    "ops": item_decisions(session, item)})
    record = {"index": session.request_count, "at": time.time(), "items": new, "blocked": blocked, "response": None,
              "relinks": [r for r in session.relinks if r["request"] == session.request_count]}
    session.requests.append(record)
    return record


# ---------- export ----------

def export(session: Session, synthetic: bool = True) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    table = restore_map(session.restore_table())
    forwarded = 0
    for record in session.requests:
        first_step = len(steps)
        for item in record["items"]:
            if item["role"] == "assistant":
                continue   # represented by the previous response step
            steps.append({
                "t": round(record["at"] - session.created, 1),
                "role": item["role"] if item["role"] in {"user", "tool", "system"} else ("system" if item["role"] == "developer" else "user"),
                "itemKind": item["kind"] if item["kind"] != "message" else f"{item['role']}_message",
                "raw": item["raw"], "sanitized": item["sanitized"], "ops": item["ops"],
                "relinks": [], "toolCall": None, "blocked": record["blocked"],
            })
        if not record["blocked"] and any(s["role"] in {"user", "tool"} for s in steps[first_step:]):
            forwarded += 1
        if record["relinks"] and len(steps) > first_step:
            steps[first_step]["relinks"] = [
                {"fromPlaceholder": r["from"], "toPlaceholder": r["to"],
                 "stepsRewritten": [i for i in range(first_step) if r["from"] in steps[i]["sanitized"]], "cacheBroken": True}
                for r in record["relinks"]]
            for r in record["relinks"]:
                steps[first_step]["ops"].append({**_op("relink", "secret", None, r["to"], True, session.entities[r["from"]].canonical
                                                       if r["from"] in session.entities else None, "model", "applied", r.get("reason")),
                                                 "placeholder": r["to"]})
        response = record.get("response")
        if response:
            calls = response["calls"] or [None]
            for n, call in enumerate(calls):
                text = response["text"] if n == 0 else ""
                steps.append({"t": round(response.get("at", record["at"]) - session.created, 1), "role": "assistant",
                              "itemKind": "assistant_tool_call" if call else "assistant_text",
                              "raw": text, "sanitized": text, "ops": [], "relinks": [], "toolCall": call, "blocked": None})
    data = {
        "id": session.id, "title": "", "summary": "",
        "relayRequestCount": forwarded,
        "headersStripped": sorted(session.headers_stripped),
        "pseudonymized": sorted(session.pseudonymized),
        "steps": steps,
    }
    return fake_host_identifiers(data) if synthetic else data


def fake_host_identifiers(data: Any) -> Any:
    """Replace this machine's real hostname, username and home paths with fixed fake ones."""
    pairs = []
    user = next((v for t, v in host_values() if t == "USERNAME"), None)
    for kind, value in host_values():
        if kind == "PATH":
            fake = value.replace(user, FAKE_HOST["USERNAME"]) if user else value
            pairs.append((value, fake))
        else:
            pairs.append((value, FAKE_HOST.get(kind, value)))
    pairs.sort(key=lambda p: -len(p[0]))

    def scrub(value: Any) -> Any:
        if isinstance(value, str):
            for real, fake in pairs:
                if real and real != fake:
                    value = value.replace(real, fake)
            return value
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items()}
        return value

    return scrub(data)


__all__ = ["ResponseRecorder", "export", "item_decisions", "record_request", "restore_text", "address"]
