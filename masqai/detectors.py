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
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from .config import DetectorConfig
from .model import ContextItem, Entity, Session

PACKAGE_RULES = Path(__file__).parent / "rules"
MIN_VALUE_LENGTH = 3


@dataclass(frozen=True)
class Rule:
    name: str
    type: str
    pattern: re.Pattern[str]
    group: int | str = 0


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
    """Pattern rules from patterns.toml plus the generic key=value rule built from keyvalue.toml."""
    base = rules_path(rules_dir)
    rules: list[Rule] = []
    for file in sorted(base.glob("*.toml")):
        data = tomllib.loads(file.read_text(encoding="utf-8"))
        for entry in data.get("rule", []):
            rules.append(Rule(entry["name"], entry["type"].upper(), re.compile(entry["regex"]), entry.get("group", 0)))
        if "names" in data:
            rules.append(keyvalue_rule(data["names"], int(data.get("min_length", 6)), tuple(data.get("ignore_values", []))))
    return tuple(rules)


def keyvalue_rule(names: list[str], min_length: int, ignore: tuple[str, ...]) -> Rule:
    alternatives = "|".join(sorted((re.escape(n) for n in names), key=len, reverse=True))
    # The key may be prefixed (DB_PASSWORD, client.secret) but must END with one of the names.
    # Values: no quotes, spaces, separators or a placeholder's angle brackets.
    pattern = re.compile(
        r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9_.-]*[_.-])?(?:" + alternatives + r")[\"']?\s*[:=]\s*[\"']?"
        r"(?!" + "|".join(re.escape(v) + r"\b" for v in ignore) + r")"
        r"([^\s\"',;<>{}()\[\]]{" + str(min_length) + r",})"
    )
    return Rule("generic_key_value", "SECRET", pattern, 1)


def import_gitleaks(path: str | Path) -> list[Rule]:
    """Hook for importing gitleaks rules. Not wired yet: decide from measured false positives."""
    raise NotImplementedError("gitleaks import is not enabled; see DECISIONS.md")


def scan(text: str, rules: Iterable[Rule]) -> list[Finding]:
    found: list[Finding] = []
    for rule in rules:
        for match in rule.pattern.finditer(text):
            value = match.group(rule.group)
            if value and len(value) >= MIN_VALUE_LENGTH and not value.startswith("<"):
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
        for finding in scan(text, rules):
            add(finding.value, finding.type, f"detector:{finding.rule}", item.id)
        for value, entity_type, origin in fixed:
            if value in text:
                add(value, entity_type, origin, item.id)
    for value, entity_type, origin in fixed:
        if session.entity_for(value) is None:
            add(value, entity_type, origin, None)
    return found


def rule_names(rules_dir: str | None = None) -> list[str]:
    return [rule.name for rule in load_rules(rules_dir)]
