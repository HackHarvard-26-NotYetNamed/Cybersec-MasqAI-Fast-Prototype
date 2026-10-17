"""What to protect: the user's own selection of categories (config `protect`), no presets.

Each category is switched on or off by the user. It is enforced in three places:
- detectors: a rule or host identifier of a switched-off category is not looked for (detectors.seed_entities);
- the security model: its input lists the categories to protect and the ones to leave alone (sanitize._input);
- the gateway: a mask, hide or replace the model proposes for a switched-off category is accepted as a no-op
  (ops.Applier), so a model that ignores the policy changes nothing and can't push a request into a failed
  correction round.
A type that maps to no category stays protected (the safe default). Custom values (detectors.custom_values) are
always masked: the user listed them explicitly. The policy applies to values found from now on; masks that a
session already has stay until the session is forgotten.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Category:
    id: str
    label: str
    kind: str            # "secret" (masked, reversible) or "intel" (hidden or replaced, lossy)
    description: str     # shown in the GUI and given to the security model
    types: frozenset[str] = frozenset()


CATEGORIES: tuple[Category, ...] = (
    Category("credentials", "Credentials", "secret",
             "API keys, tokens, passwords, private keys, connection strings and webhooks",
             frozenset({"PRIVATE_KEY", "JWT", "OR_KEY", "ANTHROPIC_KEY", "OPENAI_KEY", "AWS_KEY", "AWS_SECRET", "STRIPE_KEY",
                        "GOOGLE_KEY", "SLACK_TOKEN", "SLACK_WEBHOOK", "GITHUB_TOKEN", "GITLAB_TOKEN", "NPM_TOKEN", "HF_TOKEN",
                        "PYPI_TOKEN", "DO_TOKEN", "SHOPIFY_TOKEN", "SENDGRID_KEY", "CREDENTIAL", "CREDENTIALS", "BEARER_TOKEN",
                        "SECRET", "PASSWORD", "PASSPHRASE", "TOKEN", "KEY", "API_KEY", "CERTIFICATE", "FINGERPRINT"})),
    Category("file_paths", "File paths", "secret",
             "paths that point at private data, such as a home directory, a database file or an app's data folder",
             frozenset({"PATH", "FILE", "FILE_PATH", "DIRECTORY", "DIR", "FOLDER", "DB_PATH", "HOME"})),
    Category("machine_identity", "Machine identity", "secret",
             "the computer's username, host name, device name, IP and MAC addresses",
             frozenset({"USERNAME", "HOST", "HOSTNAME", "DEVICE", "DEVICE_NAME", "MACHINE", "IP", "IP_ADDRESS", "MAC",
                        "MAC_ADDRESS", "ACCOUNT"})),
    Category("emails", "Email addresses", "secret", "personal and work email addresses", frozenset({"EMAIL", "EMAIL_ADDRESS"})),
    Category("people", "People", "secret",
             "people's names, chat handles, phone numbers and private chat ids",
             frozenset({"USER", "NAME", "PERSON", "FULL_NAME", "AUTHOR", "TEAMMATE", "HANDLE", "CHAT_HANDLE", "PHONE",
                        "PHONE_NUMBER", "CHAT_ID", "CONTACT"})),
    Category("locations", "Locations", "intel",
             "street addresses and where someone lives, works or is",
             frozenset({"ADDRESS", "STREET_ADDRESS", "LOCATION", "CITY", "GPS", "COORDINATES"})),
    Category("infrastructure", "Infrastructure", "intel",
             "what the endpoint could learn about the machine and its setup: environment dumps, installed software, "
             "internal hostnames and network layout"),
    Category("documents", "Private documents", "intel",
             "the contents of unreleased plans, designs, contracts and other internal documents"),
    Category("messages", "Private messages", "intel",
             "the text of private messages, notifications, emails and calendar entries"),
)
BY_ID = {c.id: c for c in CATEGORIES}
_BY_TYPE = {t: c.id for c in CATEGORIES for t in c.types}
# Free-form types the security model invents, by their ending: OR_STAGING_KEY, DB_PASSWORD, APP_DATA_PATH, ...
_SUFFIXES = ((re.compile(r"(_|^)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIALS?)$"), "credentials"),
             (re.compile(r"(_|^)(PATH|DIR|DIRECTORY|FILE)$"), "file_paths"),
             (re.compile(r"(_|^)(HOST|HOSTNAME|IP)$"), "machine_identity"),
             (re.compile(r"(_|^)EMAIL$"), "emails"),
             (re.compile(r"(_|^)(NAME|PHONE|HANDLE)$"), "people"),
             (re.compile(r"(_|^)(ADDRESS|LOCATION)$"), "locations"))


def category_of(entity_type: object) -> str | None:
    """The category of a type name, or None when it can't be told (then it stays protected)."""
    if not isinstance(entity_type, str) or not entity_type:
        return None
    name = entity_type.upper()
    if name in _BY_TYPE:
        return _BY_TYPE[name]
    return next((category for pattern, category in _SUFFIXES if pattern.search(name)), None)


def protected(selection: dict[str, bool], entity_type: object = None, category: object = None) -> bool:
    """Whether a value of this type (or an intel op of this category) must be protected under `selection`.
    Both come from the security model's JSON, so anything that isn't a known name counts as protected."""
    category = category if isinstance(category, str) and category in BY_ID else category_of(entity_type)
    return category is None or selection.get(category, True)


def model_policy(selection: dict[str, bool]) -> dict[str, list[dict[str, str]]]:
    """The policy as given to the security model."""
    def entry(c: Category) -> dict[str, str]:
        return {"category": c.id, "kind": c.kind, "what": c.description}
    return {"protect": [entry(c) for c in CATEGORIES if selection.get(c.id, True)],
            "do_not_protect": [entry(c) for c in CATEGORIES if not selection.get(c.id, True)]}
