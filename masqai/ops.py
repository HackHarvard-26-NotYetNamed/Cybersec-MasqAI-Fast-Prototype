"""Occurrence-bound masking and collapsing.

The security model never defines string replacers. Every operation it returns points at exactly one
occurrence: (item, line, text, nth) for a mask, (item, start line, end line) for a collapse. This module
resolves those addresses, validates each operation on its own, and renders an item's outbound text.

Exact copies of a known value's canonical text are masked automatically ("auto masks"), but only at
token boundaries: a match whose neighbouring character is a letter, digit or underscore is left as-is
(so the username `ANDY` never turns `HANDY` into `H<USERNAME_…>`). Texts the model marked as `$`
aliases are NOT copied automatically: each alias occurrence is one model operation.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .model import CollapseOp, ContextItem, Entity, MaskOp, Session

MIN_AUTO_LENGTH = 3        # shorter canonical values are masked only where an operation points
MAX_SUMMARY = 200
TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]*")
PLACEHOLDER_RE = re.compile(r"<\$?[A-Z][A-Z0-9_]*_[a-f0-9]{8}>")


def _word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def line_starts(text: str) -> list[int]:
    starts = [0]
    for index, ch in enumerate(text):
        if ch == "\n":
            starts.append(index + 1)
    return starts


def line_of(starts: list[int], offset: int) -> int:
    """1-based line number containing character `offset`."""
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def locate(text: str, line: Any, needle: Any, nth: Any = 1) -> tuple[int, int]:
    """Character range of the nth occurrence of `needle` that starts on `line`. Raises ValueError."""
    if type(line) is not int or line < 1:
        raise ValueError("line must be a positive integer")
    if not isinstance(needle, str) or not needle:
        raise ValueError("text must be a non-empty string copied exactly from the raw line")
    if nth is None:
        nth = 1
    if type(nth) is not int or nth < 1:
        raise ValueError("nth must be a positive integer")
    starts = line_starts(text)
    if line > len(starts):
        raise ValueError(f"line {line} does not exist (the item has {len(starts)} lines)")
    begin = starts[line - 1]
    stop = starts[line] if line < len(starts) else len(text) + 1
    found, position = [], text.find(needle, begin)
    while position != -1 and position < stop:
        found.append(position)
        position = text.find(needle, position + 1)
    if not found:
        raw_line = text[begin:stop].rstrip("\n")
        hint = " (it appears on another line)" if needle in text else ""
        raise ValueError(f"line {line} does not contain {needle!r}{hint}; the line is {raw_line[:300]!r}")
    if nth > len(found):
        raise ValueError(f"{needle!r} occurs {len(found)} time(s) starting on line {line}, not {nth}")
    return found[nth - 1], found[nth - 1] + len(needle)


def address(text: str, start: int, end: int) -> dict[str, Any]:
    """The (line, text, nth) address of a character range, as shown to the security model."""
    starts = line_starts(text)
    line = line_of(starts, start)
    needle = text[start:end]
    nth, position = 1, text.find(needle, starts[line - 1])
    while position != -1 and position < start:
        nth += 1
        position = text.find(needle, position + 1)
    return {"line": line, "text": needle, "nth": nth}


def numbered(text: str, first: int = 1, last: int | None = None) -> list[dict[str, Any]]:
    lines = text.split("\n")
    last = len(lines) if last is None else min(last, len(lines))
    return [{"n": n, "raw": lines[n - 1]} for n in range(max(1, first), last + 1)]


# ---------- planning: which spans are masked, which lines collapsed ----------

@dataclass
class Span:
    start: int
    end: int
    token: str          # entity token as recorded (may be merged into another)
    alias: bool
    origin: str         # "model" or "auto"

    @property
    def length(self) -> int:
        return self.end - self.start


def auto_spans(session: Session, item_id: str, text: str) -> tuple[list[Span], list[dict[str, Any]]]:
    """Exact copies of known canonical values at token boundaries. Also returns copies that were left
    as-is (inside a word, or vetoed), so the GUI and the security model can see them."""
    spans, skipped = [], []
    vetoed = session.vetoes.get(item_id, set())
    for entity in session.entities.values():
        value = entity.canonical
        if len(value) < MIN_AUTO_LENGTH:
            continue
        forms = {value}
        escaped = json.dumps(value, ensure_ascii=False)[1:-1]
        if escaped != value:
            forms.add(escaped)   # the same value inside JSON text (tool call arguments)
        for form in forms:
            position = text.find(form)
            while position != -1:
                end = position + len(form)
                inside = (_word(form[0]) and position > 0 and _word(text[position - 1])) or \
                         (_word(form[-1]) and end < len(text) and _word(text[end]))
                if inside:
                    skipped.append({"start": position, "end": end, "token": entity.token, "reason": "inside a word"})
                elif (position, end) in vetoed:
                    skipped.append({"start": position, "end": end, "token": entity.token, "reason": "vetoed by the security model"})
                else:
                    spans.append(Span(position, end, entity.token, False, "auto"))
                position = text.find(form, position + 1)
    return spans, skipped


def resolve(spans: list[Span]) -> list[Span]:
    """Pick non-overlapping spans: longer first, model before auto on ties. A span crossing another
    (neither contains the other) is merged into one alias-form span, so no fragment is left raw."""
    chosen: list[Span] = []
    for span in sorted(spans, key=lambda s: (-s.length, s.origin != "model", s.start)):
        hits = [c for c in chosen if c.start < span.end and span.start < c.end]
        if not hits:
            chosen.append(Span(span.start, span.end, span.token, span.alias, span.origin))
        elif any(c.start <= span.start and span.end <= c.end for c in hits):
            continue
        else:
            for c in hits:
                c.start, c.end, c.alias = min(c.start, span.start), max(c.end, span.end), True
    chosen.sort(key=lambda s: s.start)
    merged: list[Span] = []
    for span in chosen:
        if merged and span.start < merged[-1].end:
            merged[-1].end, merged[-1].alias = max(merged[-1].end, span.end), True
        else:
            merged.append(span)
    return merged


def placeholder(session: Session, token: str, alias: bool) -> str:
    entity = session.entities[token]
    root = session.root(token)
    return root.token.replace("<", "<$", 1) if alias or root is not entity else root.token


def render(session: Session, text: str, spans: list[Span], collapses: list[CollapseOp]) -> tuple[str, list[dict], list[dict]]:
    """Outbound text plus the masks/collapses actually applied (in original-text offsets)."""
    starts = line_starts(text)
    regions = []
    for op in sorted(collapses, key=lambda c: c.start_line):
        begin = starts[op.start_line - 1]
        end = (starts[op.end_line] - 1) if op.end_line < len(starts) else len(text)
        regions.append([begin, end, op])
    # A mask crossing a collapse boundary widens the collapse, so no part of the value stays raw.
    for region in regions:
        for span in spans:
            if span.start < region[1] and region[0] < span.end:
                region[0], region[1] = min(region[0], span.start), max(region[1], span.end)
    events = [(r[0], r[1], "collapse", r[2]) for r in regions]
    events += [(s.start, s.end, "mask", s) for s in spans if not any(r[0] <= s.start and s.end <= r[1] for r in regions)]
    events.sort(key=lambda e: e[0])
    out, applied_masks, applied_collapses, cursor = [], [], [], 0
    for start, end, kind, op in events:
        if start < cursor:
            continue
        out.append(text[cursor:start])
        if kind == "collapse":
            out.append(f"…[MASQ_BLOCK: {op.summary}]…")
            applied_collapses.append({"start": start, "end": end, "start_line": op.start_line, "end_line": op.end_line, "summary": op.summary})
        else:
            ph = placeholder(session, op.token, op.alias)
            out.append(ph)
            applied_masks.append({"start": start, "end": end, "token": op.token, "placeholder": ph, "alias": ph.startswith("<$"), "origin": op.origin})
        cursor = end
    out.append(text[cursor:])
    return "".join(out), applied_masks, applied_collapses


def model_spans(session: Session, item_id: str) -> list[Span]:
    return [Span(op.start, op.end, op.token, op.alias, "model") for op in session.ops.get(item_id, [])
            if isinstance(op, MaskOp) and op.token in session.entities]


def collapses_of(session: Session, item_id: str) -> list[CollapseOp]:
    return [op for op in session.ops.get(item_id, []) if isinstance(op, CollapseOp)]


def plan_item(session: Session, item: ContextItem) -> None:
    """Compute item.sanitized from the session's operations and known values."""
    if item.reasoning or not isinstance(item.original, str):
        item.sanitized, item.spans, item.unmasked, item.collapses = item.original, [], [], []
        item.changed = False
        return
    text = item.original
    autos, skipped = auto_spans(session, item.id, text)
    spans = resolve(model_spans(session, item.id) + autos)
    sanitized, masks, collapses = render(session, text, spans, collapses_of(session, item.id))
    if item.json_value and not _parses(sanitized):
        # An automatic copy straddled JSON syntax (a known value that contains quotes or braces).
        # Keep only the model's masks, which were checked against the JSON when they were added.
        spans = resolve(model_spans(session, item.id))
        sanitized, masks, collapses = render(session, text, spans, collapses_of(session, item.id))
        if not _parses(sanitized):
            raise ValueError(f"masking would break the JSON of tool arguments in item {item.id}")
    covered = [(m["start"], m["end"]) for m in masks] + [(c["start"], c["end"]) for c in collapses]
    item.unmasked = [s for s in skipped if not any(a <= s["start"] and s["end"] <= b for a, b in covered)]
    item.sanitized, item.spans, item.collapses = sanitized, masks, collapses
    item.changed = sanitized != item.original


def plan_all(session: Session, items: list[ContextItem]) -> None:
    for item in items:
        plan_item(session, item)


# ---------- validating and applying the security model's operations ----------

class OpError(ValueError):
    pass


def _token(session: Session, labels: dict[str, str], value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise OpError("token must be an existing placeholder such as <PATH_1a2b3c4d>, or a label defined in this answer")
    token = labels.get(value, value)
    if token.startswith("<$"):
        token = token.replace("<$", "<", 1)
    if token not in session.entities:
        raise OpError(f"unknown token {value!r}")
    return token


def _parses(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except ValueError:
        return False


class Applier:
    """Validates operations one by one and applies the valid ones to the session."""

    def __init__(self, session: Session, items: list[ContextItem], allow_veto: bool, request: int) -> None:
        self.session = session
        self.items = items
        self.refs = {f"#{i + 1}": item for i, item in enumerate(items)}
        self.allow_veto = allow_veto
        self.request = request
        self.labels: dict[str, str] = {}
        self.new_entities: list[str] = []

    def item(self, ref: Any, *, tool_result: bool = False) -> ContextItem:
        item = self.refs.get(ref) if isinstance(ref, str) else None
        if item is None:
            raise OpError(f"unknown item {ref!r}; use a ref such as \"#3\" from the input")
        if item.reasoning or not item.eligible or not isinstance(item.original, str):
            raise OpError(f"item {ref} cannot be edited (system prompt, tool description or reasoning)")
        if tool_result and item.kind != "tool_result":
            raise OpError(f"item {ref} is a {item.kind}; only tool results can be collapsed")
        return item

    def apply(self, operations: Any) -> list[dict[str, Any]]:
        if not isinstance(operations, list):
            raise OpError("operations must be a list")
        results: list[dict[str, Any] | None] = [None] * len(operations)
        # New entities first, so labels they define can be referenced in any order.
        order = sorted(range(len(operations)), key=lambda i: 0 if self._defines(operations[i]) else 1)
        for index in order:
            op = operations[index]
            try:
                effect = self.one(op)
                results[index] = {"index": index, "op": op, "ok": True, "effect": effect}
            except OpError as exc:
                results[index] = {"index": index, "op": op, "ok": False, "error": str(exc)}
        return [r for r in results if r is not None]

    @staticmethod
    def _defines(op: Any) -> bool:
        return isinstance(op, dict) and op.get("op") == "mask" and not op.get("token")

    def one(self, op: Any) -> str:
        if not isinstance(op, dict):
            raise OpError("each operation must be an object")
        kind = op.get("op")
        if kind == "mask":
            return self.mask(op)
        if kind == "collapse":
            return self.collapse(op)
        if kind == "relink":
            return self.relink(op)
        if kind == "unmask":
            return self.unmask(op)
        raise OpError(f"unknown op {kind!r}; expected mask, collapse, relink" + (" or unmask" if self.allow_veto else ""))

    # --- mask ---
    def mask(self, op: dict[str, Any]) -> str:
        item = self.item(op.get("item"))
        try:
            start, end = locate(item.original, op.get("line"), op.get("text"), op.get("nth", 1))
        except ValueError as exc:
            raise OpError(str(exc)) from None
        text = item.original[start:end]
        alias = op.get("alias", False)
        if not isinstance(alias, bool):
            raise OpError("alias must be true or false")
        session = self.session
        if op.get("token"):
            token = _token(session, self.labels, op["token"])
            entity = session.entities[token]
            if not alias and text not in (entity.canonical, session.root(token).canonical):
                raise OpError(f"{text!r} differs from the value of {token}; set alias:true if it is a partial or changed form")
            existing = entity
        else:
            if alias:
                raise OpError("alias:true needs token: the placeholder (or label) this text is a form of")
            entity_type = op.get("type", "SECRET")
            if not isinstance(entity_type, str) or not TYPE_RE.fullmatch(entity_type):
                raise OpError("type must be uppercase letters, digits and underscores, starting with a letter")
            existing = session.entity_for(text)
        # Overlap rules against what is already masked in this item (before any new entity exists).
        current = resolve(model_spans(session, item.id) + auto_spans(session, item.id, item.original)[0])
        for span in current:
            if span.start == start and span.end == end:
                if existing and session.root(span.token).token == session.root(existing.token).token:
                    self._label(op, existing.token)
                    return "already masked here"
                if span.origin == "model":
                    raise OpError(f"this occurrence is already masked as {span.token}; use relink to join the two entities")
                # An automatic mask of another entity at the same place: the model's choice wins.
            elif span.start < end and start < span.end:
                if span.start <= start and end <= span.end:
                    # Nothing leaks here; still record a new value so its other exact copies are masked.
                    token = existing.token if existing else session.new_entity(text, op.get("type", "SECRET")).token
                    if not existing:
                        self.new_entities.append(token)
                    self._label(op, token)
                    return f"already inside the masked text {placeholder(session, span.token, span.alias)}" + ("" if existing else " (new entity recorded)")
                if not (start <= span.start and span.end <= end):
                    raise OpError(f"crosses the masked text {item.original[span.start:span.end]!r}; mask a range that contains it or does not touch it")
        created = existing is None
        token = existing.token if existing else session.new_entity(text, op.get("type", "SECRET")).token
        new = MaskOp(item.id, start, end, token, alias, text, "model", self.request)
        session.ops.setdefault(item.id, []).append(new)
        if _parses(item.original):
            probe = ContextItem(item.id, item.kind, item.role, item.original, item.original, json_value=item.json_value)
            try:
                plan_item(session, probe)
                broken = not _parses(probe.sanitized)
            except ValueError:
                broken = True
            if broken:
                session.ops[item.id].remove(new)
                if created:
                    del session.entities[token]
                raise OpError("this mask would break the JSON structure; mask only text inside a string value")
        if created:
            self.new_entities.append(token)
        self._label(op, token)
        ph = placeholder(session, token, alias)
        return f"masked as {ph}" + (" (new entity; its other exact copies are masked automatically)" if created else "")

    def _label(self, op: dict[str, Any], token: str) -> None:
        label = op.get("label")
        if isinstance(label, str) and label:
            self.labels[label] = token

    # --- collapse ---
    def collapse(self, op: dict[str, Any]) -> str:
        item = self.item(op.get("item"), tool_result=True)
        lines = item.original.split("\n")
        start, end = op.get("start"), op.get("end")
        if type(start) is not int or type(end) is not int or not (1 <= start <= end <= len(lines)):
            raise OpError(f"start/end must be line numbers with 1 <= start <= end <= {len(lines)}")
        if lines[start - 1] != op.get("first"):
            raise OpError(f"first must equal raw line {start} exactly: {lines[start - 1][:300]!r}")
        if lines[end - 1] != op.get("last"):
            raise OpError(f"last must equal raw line {end} exactly: {lines[end - 1][:300]!r}")
        summary = op.get("summary")
        if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_SUMMARY or "\n" in summary or "\r" in summary:
            raise OpError(f"summary must be one non-empty line of at most {MAX_SUMMARY} characters")
        summary = summary.strip()
        for value, ph in self.session.known_values():
            if len(value) >= MIN_AUTO_LENGTH and value in summary:
                raise OpError(f"summary contains the sensitive value masked as {ph}")
        if PLACEHOLDER_RE.search(summary):
            raise OpError("summary must not contain placeholders")
        for other in collapses_of(self.session, item.id):
            if other.start_line <= end and start <= other.end_line:
                if (other.start_line, other.end_line) == (start, end):
                    other.summary = summary
                    return "summary updated"
                raise OpError(f"overlaps the collapsed lines {other.start_line}-{other.end_line}")
        self.session.ops.setdefault(item.id, []).append(CollapseOp(item.id, start, end, summary, lines[start - 1], lines[end - 1], self.request))
        return f"lines {start}-{end} collapsed"

    # --- relink ---
    def relink(self, op: dict[str, Any]) -> str:
        old = _token(self.session, self.labels, op.get("token"))
        new = _token(self.session, self.labels, op.get("to"))
        if self.session.root(old).token == self.session.root(new).token:
            return "already linked"
        if self.session.entities[old].merged_into:
            raise OpError(f"{old} is already linked to {self.session.entities[old].merged_into}")
        self.session.entities[old].merged_into = new
        return f"{old} is now sent as {placeholder(self.session, old, True)}"

    # --- unmask (veto an automatic mask) ---
    def unmask(self, op: dict[str, Any]) -> str:
        if not self.allow_veto:
            raise OpError("unmask is disabled in this configuration")
        item = self.item(op.get("item"))
        try:
            start, end = locate(item.original, op.get("line"), op.get("text"), op.get("nth", 1))
        except ValueError as exc:
            raise OpError(str(exc)) from None
        autos, _ = auto_spans(self.session, item.id, item.original)
        if not any(s.start == start and s.end == end for s in autos):
            raise OpError("unmask only applies to an automatic copy of a known value at exactly this position")
        self.session.vetoes.setdefault(item.id, set()).add((start, end))
        return "automatic mask removed at this occurrence"
