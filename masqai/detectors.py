"""Deterministic detectors: rule tables in masqai/rules/*.toml, host identifiers, user-listed values.

Detectors only ever MASK. They are fast and can't be prompt-injected; their three known flaws (no
pattern for unknown formats, false alarms inside longer words, no alias linking) are what the security
model fixes. Every hit seeds the session mapping; exact copies elsewhere are then auto-masked by ops.py.
"""
from __future__ import annotations

import os
import re
import socket
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator

from .config import DetectorConfig
from .model import ContextItem, Entity, Session

PACKAGE_RULES = Path(__file__).parent / "rules"
MIN_VALUE_LENGTH = 3
PLACEHOLDER_RE = re.compile(r"<\$?[A-Z][A-Z0-9_]*_[a-f0-9]{8}>")
TEMPLATE_STARTS = ("{{", "<")


def templated(value: str) -> bool:
    """A reference, template or elided example rather than a literal (`${DB_PASSWORD}`, `$TOKEN`,
    `<PATH_…>`, `{{x}}`, `__TOKEN__`, `sk-...`, `<your key here>`)."""
    return (bool(PLACEHOLDER_RE.search(value)) or bool(re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^{}]+\}|%[A-Za-z_][A-Za-z0-9_]*%|\*+", value)) or value.startswith(TEMPLATE_STARTS)
            or (value.startswith("__") and value.endswith("__")) or "..." in value or "…" in value
            or ("<" in value and ">" in value) or value.lower().startswith(("your", "my-", "my_", "example")))


@dataclass(frozen=True)
class Rule:
    """One detector. `group` is the part of the match that is the secret. A rule with a group (a context
    rule: only the value is masked) skips templated values and values that fully match an `ignore` regex."""
    name: str
    type: str
    pattern: re.Pattern[str]
    group: int | str = 0
    ignore: tuple[re.Pattern[str], ...] = field(default=(), compare=False)

    def hits(self, text: str) -> Iterator[tuple[int, int]]:
        for match in self.pattern.finditer(text):
            start, end = match.span(self.group)
            if end <= start:
                continue
            value = match.group(self.group)
            if self.group != 0 and (templated(value) or any(p.fullmatch(value) for p in self.ignore)):
                continue
            yield start, end


@dataclass(frozen=True)
class Finding:
    rule: str
    type: str
    value: str


def rules_path(rules_dir: str | None) -> Path:
    if not rules_dir:
        return PACKAGE_RULES
    path = Path(rules_dir)
    if path.is_dir():
        return path
    # A relative default such as "masqai/rules" also works when started from another directory.
    candidate = Path(__file__).parent.parent / rules_dir
    return candidate if candidate.is_dir() else PACKAGE_RULES


@lru_cache(maxsize=8)
def load_rules(rules_dir: str | None = None) -> tuple[Rule, ...]:
    """Pattern rules from patterns.toml plus the generic key=value rule built from keyvalue.toml.
    Order is specificity: scan() keeps the first rule's hit when two overlap."""
    base = rules_path(rules_dir)
    rules: list[Rule] = []
    for file in sorted(base.glob("*.toml")):
        data = tomllib.loads(file.read_text(encoding="utf-8"))
        for entry in data.get("rule", []):
            ignore = tuple(re.compile(p, re.IGNORECASE) for p in entry.get("ignore", []))
            rules.append(Rule(entry["name"], entry["type"].upper(), re.compile(entry["regex"]), entry.get("group", 0), ignore))
        if "names" in data:
            rules.append(keyvalue_rule(data["names"], int(data.get("min_length", 8)), int(data.get("min_length_mixed", 6)),
                                       tuple(data.get("ignore_values", []))))
    # Generic and broad rules go last so a specific rule names an overlapping hit.
    late = {"email": 1, "generic_key_value": 2}
    return tuple(sorted(rules, key=lambda r: late.get(r.name, 0)))


def keyvalue_rule(names: list[str], min_length: int, min_mixed: int, ignore_values: tuple[str, ...]) -> Rule:
    """`<key>[quote] (=|:) [quote]<value>` where the key ends in a secret-like name; only the value is
    the secret. Names of 5+ characters may be glued to a prefix (`dbpassword`, `csrftoken`); shorter
    ones (`pwd`, `auth`, `pass`) only as a whole segment (`DB_PWD`), so `bypass` or `oauth` don't count.
    Filters keep code and templates out: calls, attribute paths, constant names, prose, placeholders."""
    long_names = tuple(sorted({n.lower() for n in names if len(n) >= 5}, key=len, reverse=True))
    short_names = tuple(sorted({n.lower() for n in names if len(n) < 5}, key=len, reverse=True))
    # The key is matched as one token and its name checked in Python: a regex alternation of names
    # behind a `[…]*` prefix would be retried at every position of every word.
    pattern = re.compile(
        r"(?<![A-Za-z0-9_.-])(?P<key>[A-Za-z0-9_.-]+)\\?[\"']?[ \t]*(?:=|:(?!:))(?![=~])[ \t]*"
        r"(?:(?P<q>\\?[\"'])(?P<value>[^\"'\\\r\n]+)(?P=q)|(?P<bare>[^\s\"'`,;{}()\[\]<>|\\]+))")
    ignore = {v.lower() for v in ignore_values} | {n.lower() for n in names}
    identifier = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    attribute = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
    line_start = re.compile(r"[ \t]*(?:export[ \t]+|-[ \t]+)?")

    def secret_key(key: str) -> bool:
        key = key.lower()
        if key.endswith(long_names):
            return True
        return any(key == n or (key.endswith(n) and key[-len(n) - 1] in "_.-") for n in short_names)

    def literal(match: re.Match[str]) -> tuple[str, int] | None:
        if match.group("value") is not None:
            return match.group("value"), match.start("value")
        bare = match.group("bare").rstrip(".,")
        return (bare, match.start("bare")) if bare else None

    def assignment_line(match: re.Match[str]) -> bool:
        """The key starts its line, as in .env, YAML, TOML, INI or shell (`export KEY=…`, `- key: …`)."""
        text, key = match.string, match.start("key")
        return bool(line_start.fullmatch(text, text.rfind("\n", 0, key) + 1, key))

    def in_call(match: re.Match[str]) -> bool:
        """The key is an argument or parameter: an unclosed `(` before it on the same line."""
        text, key = match.string, match.start("key")
        before = text[text.rfind("\n", 0, key) + 1:key]
        return before.count("(") > before.count(")")

    def accept(match: re.Match[str]) -> bool:
        if not secret_key(match.group("key")):
            return False
        found = literal(match)
        if not found:
            return False
        value, start = found
        if value.lower() in ignore or len(set(value)) == 1 or templated(value):
            return False
        letters, digits = any(c.isalpha() for c in value), any(c.isdigit() for c in value)
        if len(value) < (min_mixed if letters and digits else min_length):
            return False
        if match.group("value") is not None:
            return not (" " in value and not digits)          # prose such as "The token to use"
        # Unquoted: tell a literal from code.
        end = start + len(value)
        if end < len(match.string) and match.string[end] in "([":
            return False                                      # a call or subscript: password=getpass()
        if value.startswith(".") or attribute.fullmatch(value):
            return False                                      # os.environ, self.secret, .asyncio.server
        if identifier.fullmatch(value):
            # A bare word is a variable or type name in code (`auth: AuthTypes`, `login(password=password1)`),
            # but a real value on an assignment line (`DB_PASSWORD=hunter22`, `password: s3cretpw`) or,
            # with letters and digits, anywhere outside a call (`deploy with password=hunter22x`).
            if not (assignment_line(match) or (letters and digits and not in_call(match))):
                return False
            if not digits and ("_" in value or value[0].isupper()):
                return False                                  # MY_SECRET_NAME, SecretStr
        return True

    class KeyValueRule(Rule):
        def hits(self, text: str) -> Iterator[tuple[int, int]]:
            position = 0
            while (match := self.pattern.search(text, position)) is not None:
                if accept(match):
                    value, start = literal(match)
                    yield start, start + len(value)
                    position = start + len(value)
                else:
                    # Resume at the rejected value: it may itself hold a `key=value` (`key: password=…`).
                    position = match.start("q") if match.group("q") else match.start("bare")

    return KeyValueRule("generic_key_value", "SECRET", pattern, 0)


def import_gitleaks(path: str | Path) -> list[Rule]:
    """Hook for importing gitleaks rules. Not wired yet: decide from measured false positives."""
    raise NotImplementedError("gitleaks import is not enabled; see DECISIONS.md")


def scan(text: str, rules: Iterable[Rule]) -> list[Finding]:
    """Every rule hit in `text`, most specific rule first. A hit overlapping an earlier hit is dropped, so
    `postgres://bob:pw@db.example.com` gives the credentials, not also an e-mail `pw@db.example.com`."""
    taken: list[tuple[int, int]] = []
    found: list[Finding] = []
    for rule in rules:
        for start, end in rule.hits(text):
            value = text[start:end]
            if len(value) < MIN_VALUE_LENGTH or value.startswith("<"):
                continue
            if any(a < end and start < b for a, b in taken):
                continue
            taken.append((start, end))
            found.append(Finding(rule.name, rule.type, value))
    return found


def host_values() -> list[tuple[str, str]]:
    """Identifiers of the machine running the gateway, masked when detect_host_identifiers is on."""
    values = [("HOST", socket.gethostname()), ("USERNAME", os.getenv("USERNAME") or os.getenv("USER") or "")]
    for name in ("USERPROFILE", "HOME"):
        if os.getenv(name):
            values.append(("PATH", os.getenv(name, "")))
    return [(t, v) for t, v in values if v and len(v) >= MIN_VALUE_LENGTH]


def seed_entities(session: Session, items: Iterable[ContextItem], config: DetectorConfig) -> list[Entity]:
    """Add every detector hit to the session mapping. Exact copies are then masked automatically (at
    word boundaries) by ops.plan_item. Returns the entities created by this call."""
    rules = load_rules(config.rules_dir)
    found: list[Entity] = []

    def add(value: str, entity_type: str, origin: str, item_id: str | None) -> None:
        entity = session.entity_for(value)
        if entity is None:
            entity = session.new_entity(value, entity_type, origin, reason=f"matched detector {origin.removeprefix('detector:')}")
            found.append(entity)
        if item_id:
            entity.detected_in.add(item_id)

    fixed: list[tuple[str, str, str]] = []
    if config.detect_host_identifiers:
        fixed += [(v, t, "detector:host") for t, v in host_values()]
    fixed += [(c.value, c.type.upper(), "detector:custom") for c in config.custom_values]
    for item in items:
        if item.reasoning or item.opaque or not isinstance(item.original, str):
            continue
        text = item.original
        findings = scan(text, rules)
        for finding in findings:
            add(finding.value, finding.type, f"detector:{finding.rule}", item.id)
        # Structured tokens found by rules dominate ambient fixed identifiers (host/user/path).
        # Do not seed a fixed identifier if it appears wholly inside a detected structured secret in this item.
        rule_spans = []
        for finding in findings:
            pos = text.find(finding.value)
            while pos != -1:
                rule_spans.append((pos, pos + len(finding.value)))
                pos = text.find(finding.value, pos + 1)

        for value, entity_type, origin in fixed:
            pos = text.find(value)
            while pos != -1:
                end = pos + len(value)
                inside_rule = any(rsp[0] <= pos and end <= rsp[1] for rsp in rule_spans)
                if not inside_rule:
                    add(value, entity_type, origin, item.id)
                pos = text.find(value, pos + 1)
    for value, entity_type, origin in fixed:
        if session.entity_for(value) is None:
            add(value, entity_type, origin, None)
    return found


def rule_names(rules_dir: str | None = None) -> list[str]:
    return [rule.name for rule in load_rules(rules_dir)]
