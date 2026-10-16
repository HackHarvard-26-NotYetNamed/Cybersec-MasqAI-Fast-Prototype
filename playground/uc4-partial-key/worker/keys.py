from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def deployment() -> dict:
    return json.loads((ROOT / "deploy" / "worker.json").read_text(encoding="utf-8"))


def api_key(key_ref: str) -> str:
    with open(ROOT / "config" / "llm-keys.toml", "rb") as handle:
        return tomllib.load(handle)[key_ref]["key"]


def fingerprint(key: str) -> str:
    """What the worker logs instead of the key: prefix + first 3 and last 3 characters of the secret part."""
    prefix = "sk-or-v1-"
    secret = key[len(prefix):]
    return f"{prefix}{secret[:3]}...{secret[-3:]}"
