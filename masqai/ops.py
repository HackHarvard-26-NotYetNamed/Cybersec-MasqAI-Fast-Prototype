"""Occurrence-bound operations: mask (reversible), hide and replace (lossy rephrasing), relink, unmask.

The security model never defines string replacers. Every operation it returns points at exactly one
occurrence: (item, line, text, nth) for a mask or a replace, (item, start line, end line) for a hide.
This module resolves those addresses, validates each operation on its own, and renders an item's
outbound text.

Exact copies of a known value's canonical text are masked automatically ("auto masks"), but only at
token boundaries: a match whose neighbouring character is a letter, digit or underscore is left as-is
(so the username `ANDY` never turns `HANDY` into `H<USERNAME_…>`). Texts the model marked as `$`
aliases are NOT copied automatically: each alias occurrence is one model operation.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any

from .model import ContextItem, Entity, HideOp, MaskOp, ReplaceOp, Session

MIN_AUTO_LENGTH = 3        # shorter canonical values are masked only where an operation points
MAX_SUMMARY = 200          # hide summaries and replace substitutes
MAX_REASON = 300
CLASSES = ("secret", "intel")
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


# ---------- planning: which spans are masked, which lines hidden, which texts replaced ----------

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
    """Exact copies of known canonical values and their transit variants (JSON escaped, URL encoded,
    slash-normalized) at token boundaries. Also returns copies that were left as-is (inside a word, or vetoed),
    so the GUI and the security model can see them."""
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
        
        # URL / percent-encoded variants (both fully quoted and safe="/")
        for safe_chars in ("", "/"):
            enc = urllib.parse.quote(value, safe=safe_chars)
            if enc != value:
                forms.add(enc)

        # Ambient identifiers (username, host) should also treat hyphens and dots as word constituents
        # when flanked by other alphanumerics, avoiding auto-masking inside structured tokens like sk-alice-token.
        is_ambient = entity.entity_type in ("USERNAME", "HOST", "USER")
        for form in forms:
            position = text.find(form)
            while position != -1:
                end = position + len(form)
                prev_ch = text[position - 1] if position > 0 else ""
                next_ch = text[end] if end < len(text) else ""
                
                # For ambient identifiers, a dot only counts as a word continuation if it is
                # part of a compound identifier (flanked by alphanumerics), not trailing punctuation.
                inside_left = _word(prev_ch) or (is_ambient and prev_ch == "." and position > 1 and _word(text[position - 2]))
                inside_right = _word(next_ch) or (is_ambient and next_ch == "." and end + 1 < len(text) and _word(text[end + 1]))
                inside = (_word(form[0]) and inside_left) or (_word(form[-1]) and inside_right)
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


def hidden_marker(summary: str) -> str:
    return f"…[hidden: {summary}]…"


def render(session: Session, text: str, spans: list[Span], hides: list[HideOp],
           replaces: list[ReplaceOp] | None = None) -> tuple[str, list[dict], list[dict], list[dict]]:
    """Outbound text plus the masks, hides and replaces actually applied (in original-text offsets)."""
    starts = line_starts(text)
    regions = []
    for op in sorted(hides, key=lambda c: c.start_line):
        begin = starts[op.start_line - 1]
        end = (starts[op.end_line] - 1) if op.end_line < len(starts) else len(text)
        regions.append([begin, end, op])
    # A mask crossing a hidden range widens the range, so no part of the value stays raw.
    for region in regions:
        for span in spans:
            if span.start < region[1] and region[0] < span.end:
                region[0], region[1] = min(region[0], span.start), max(region[1], span.end)
    inside = lambda a, b: any(r[0] <= a and b <= r[1] for r in regions)
    events = [(r[0], r[1], "hide", r[2]) for r in regions]
    events += [(s.start, s.end, "mask", s) for s in spans if not inside(s.start, s.end)]
    # A replace never overlaps a mask (validated); one inside a hidden range is simply hidden.
    events += [(r.start, r.end, "replace", r) for r in (replaces or []) if not inside(r.start, r.end)]
    events.sort(key=lambda e: e[0])
    out, applied_masks, applied_hides, applied_replaces, cursor = [], [], [], [], 0
    for start, end, kind, op in events:
        if start < cursor:
            continue
        out.append(text[cursor:start])
        if kind == "hide":
            out.append(hidden_marker(op.summary))
            applied_hides.append({"start": start, "end": end, "start_line": op.start_line, "end_line": op.end_line,
                                  "summary": op.summary, "class": op.cls, "reason": op.reason})
        elif kind == "replace":
            out.append(op.replacement)
            applied_replaces.append({"start": start, "end": end, "with": op.replacement, "class": op.cls, "reason": op.reason})
        else:
            ph = placeholder(session, op.token, op.alias)
            out.append(ph)
            applied_masks.append({"start": start, "end": end, "token": op.token, "placeholder": ph, "alias": ph.startswith("<$"), "origin": op.origin})
        cursor = end
    out.append(text[cursor:])
    return "".join(out), applied_masks, applied_hides, applied_replaces


def model_spans(session: Session, item_id: str) -> list[Span]:
    return [Span(op.start, op.end, op.token, op.alias, "model") for op in session.ops.get(item_id, [])
            if isinstance(op, MaskOp) and op.token in session.entities]


def hides_of(session: Session, item_id: str) -> list[HideOp]:
    return [op for op in session.ops.get(item_id, []) if isinstance(op, HideOp)]


def replaces_of(session: Session, item_id: str) -> list[ReplaceOp]:
    return [op for op in session.ops.get(item_id, []) if isinstance(op, ReplaceOp)]


def plan_item(session: Session, item: ContextItem) -> None:
    """Compute item.sanitized from the session's operations and known values."""
    if item.reasoning or item.opaque or not isinstance(item.original, str):
        item.sanitized, item.spans, item.unmasked, item.hides, item.replaces = item.original, [], [], [], []
        item.changed = False
        return
    text = item.original
    autos, skipped = auto_spans(session, item.id, text)
    spans = resolve(model_spans(session, item.id) + autos)
    hides, replaces = hides_of(session, item.id), replaces_of(session, item.id)
    sanitized, masks, applied_hides, applied_replaces = render(session, text, spans, hides, replaces)
    if item.json_value and not _parses(sanitized):
        # An automatic copy straddled JSON syntax (a known value that contains quotes or braces).
        # Keep only the model's masks, which were checked against the JSON when they were added.
        spans = resolve(model_spans(session, item.id))
        sanitized, masks, applied_hides, applied_replaces = render(session, text, spans, hides, replaces)
        if not _parses(sanitized):
            raise ValueError(f"masking would break the JSON of tool arguments in item {item.id}")
    covered = [(m["start"], m["end"]) for m in masks] + [(c["start"], c["end"]) for c in applied_hides + applied_replaces]
    item.unmasked = [s for s in skipped if not any(a <= s["start"] and s["end"] <= b for a, b in covered)]
    item.sanitized, item.spans, item.hides, item.replaces = sanitized, masks, applied_hides, applied_replaces
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


def _cls(op: dict[str, Any], default: str) -> str:
    value = op.get("class", default)
    if value not in CLASSES:
        raise OpError('class must be "secret" or "intel"')
    return value


def _reason(op: dict[str, Any]) -> str | None:
    value = op.get("reason")
    if value is None:
        return None
    if not isinstance(value, str):
        raise OpError("reason must be a string")
    return value.strip()[:MAX_REASON] or None


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

    def item(self, ref: Any, *, tool_result: bool = False, what: str = "") -> ContextItem:
        item = self.refs.get(ref) if isinstance(ref, str) else None
        if item is None:
            raise OpError(f"unknown item {ref!r}; use a ref such as \"#3\" from the input")
        if item.reasoning or item.opaque or not item.eligible or not isinstance(item.original, str):
            raise OpError(f"item {ref} cannot be edited (reasoning or opaque content)")
        if tool_result and item.kind != "tool_result":
            raise OpError(f"item {ref} is a {item.kind}; {what} only applies to tool results")
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
        if kind == "hide":
            return self.hide(op)
        if kind == "replace":
            return self.replace(op)
        if kind == "relink":
            return self.relink(op)
        if kind == "unmask":
            return self.unmask(op)
        raise OpError(f"unknown op {kind!r}; expected mask, hide, replace, relink" + (" or unmask" if self.allow_veto else ""))

    def _locate(self, item: ContextItem, op: dict[str, Any]) -> tuple[int, int]:
        try:
            return locate(item.original, op.get("line"), op.get("text"), op.get("nth", 1))
        except ValueError as exc:
            raise OpError(str(exc)) from None

    # --- mask ---
    def mask(self, op: dict[str, Any]) -> str:
        item = self.item(op.get("item"))
        start, end = self._locate(item, op)
        text = item.original[start:end]
        alias = op.get("alias", False)
        if not isinstance(alias, bool):
            raise OpError("alias must be true or false")
        cls, reason = _cls(op, "secret"), _reason(op)
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
        if any(r.start < end and start < r.end for r in replaces_of(session, item.id)):
            raise OpError("this text overlaps a replaced occurrence; it is already rephrased")
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
                    token = existing.token if existing else session.new_entity(text, op.get("type", "SECRET"), "model", cls, reason).token
                    if not existing:
                        self.new_entities.append(token)
                    self._label(op, token)
                    return f"already inside the masked text {placeholder(session, span.token, span.alias)}" + ("" if existing else " (new entity recorded)")
                if not (start <= span.start and span.end <= end):
                    raise OpError(f"crosses the masked text {item.original[span.start:span.end]!r}; mask a range that contains it or does not touch it")
        created = existing is None
        token = existing.token if existing else session.new_entity(text, op.get("type", "SECRET"), "model", cls, reason).token
        new = MaskOp(item.id, start, end, token, alias, text, "model", self.request, reason)
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

    def _check_rephrase(self, value: Any, what: str) -> str:
        """A hide summary or replace substitute: one short line, no sensitive value, no placeholder."""
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_SUMMARY or "\n" in value or "\r" in value:
            raise OpError(f"{what} must be one non-empty line of at most {MAX_SUMMARY} characters")
        value = value.strip()
        for known, ph in self.session.known_values():
            if len(known) >= MIN_AUTO_LENGTH and known in value:
                raise OpError(f"{what} contains the sensitive value masked as {ph}")
        if PLACEHOLDER_RE.search(value):
            raise OpError(f"{what} must not contain placeholders")
        return value

    # --- hide (rephrase: a whole-line range of a tool result) ---
    def hide(self, op: dict[str, Any]) -> str:
        item = self.item(op.get("item"), tool_result=True, what="hide")
        lines = item.original.split("\n")
        start, end = op.get("start"), op.get("end")
        if type(start) is not int or type(end) is not int or not (1 <= start <= end <= len(lines)):
            raise OpError(f"start/end must be line numbers with 1 <= start <= end <= {len(lines)}")
        if lines[start - 1] != op.get("first"):
            raise OpError(f"first must equal raw line {start} exactly: {lines[start - 1][:300]!r}")
        if lines[end - 1] != op.get("last"):
            raise OpError(f"last must equal raw line {end} exactly: {lines[end - 1][:300]!r}")
        summary = self._check_rephrase(op.get("summary"), "summary")
        cls, reason = _cls(op, "intel"), _reason(op)
        for other in hides_of(self.session, item.id):
            if other.start_line <= end and start <= other.end_line:
                if (other.start_line, other.end_line) == (start, end):
                    other.summary, other.reason = summary, reason or other.reason
                    return "summary updated"
                raise OpError(f"overlaps the hidden lines {other.start_line}-{other.end_line}")
        self.session.ops.setdefault(item.id, []).append(
            HideOp(item.id, start, end, summary, lines[start - 1], lines[end - 1], self.request, cls, reason))
        return f"lines {start}-{end} hidden"

    # --- replace (rephrase: one occurrence of a tool result) ---
    def replace(self, op: dict[str, Any]) -> str:
        item = self.item(op.get("item"), tool_result=True, what="replace")
        start, end = self._locate(item, op)
        replacement = self._check_rephrase(op.get("with"), "with")
        cls, reason = _cls(op, "intel"), _reason(op)
        session = self.session
        current = resolve(model_spans(session, item.id) + auto_spans(session, item.id, item.original)[0])
        if any(s.start < end and start < s.end for s in current):
            raise OpError("this text overlaps a masked value; masks and replaces must not overlap")
        for other in replaces_of(session, item.id):
            if other.start < end and start < other.end:
                if (other.start, other.end) == (start, end):
                    other.replacement, other.reason = replacement, reason or other.reason
                    return "substitute updated"
                raise OpError(f"overlaps the replaced text {other.text!r}")
        session.ops.setdefault(item.id, []).append(
            ReplaceOp(item.id, start, end, item.original[start:end], replacement, self.request, cls, reason))
        return f"replaced with {replacement!r}"

    # --- relink ---
    def relink(self, op: dict[str, Any]) -> str:
        old = _token(self.session, self.labels, op.get("token"))
        new = _token(self.session, self.labels, op.get("to"))
        if self.session.root(old).token == self.session.root(new).token:
            return "already linked"
        if self.session.entities[old].merged_into:
            raise OpError(f"{old} is already linked to {self.session.entities[old].merged_into}")
        self.session.entities[old].merged_into = new
        self.session.relinks.append({"from": old, "to": placeholder(self.session, old, True), "request": self.request,
                                     "reason": _reason(op)})
        return f"{old} is now sent as {placeholder(self.session, old, True)}"

    # --- unmask (veto an automatic mask) ---
    def unmask(self, op: dict[str, Any]) -> str:
        if not self.allow_veto:
            raise OpError("unmask is disabled in this configuration")
        item = self.item(op.get("item"))
        start, end = self._locate(item, op)
        autos, _ = auto_spans(self.session, item.id, item.original)
        matched_auto = next((s for s in autos if s.start == start and s.end == end), None)
        if matched_auto is None:
            raise OpError("unmask only applies to an automatic copy of a known value at exactly this position")
        
        is_global = op.get("global", False)
        if not isinstance(is_global, bool):
            raise OpError("global must be a boolean (true or false)")
            
        if is_global:
            # Revoke the entity globally from session.entities and remove any auto-spans of it
            token = matched_auto.token
            if token in self.session.entities:
                del self.session.entities[token]
            # Clear any other entities that merged into this token
            for ent in self.session.entities.values():
                if ent.merged_into == token:
                    ent.merged_into = None
            return f"entity {token} globally revoked and automatic masks removed"

        self.session.vetoes.setdefault(item.id, set()).add((start, end))
        self.session.veto_reasons[(item.id, start, end)] = _reason(op)
        return "automatic mask removed at this occurrence"
