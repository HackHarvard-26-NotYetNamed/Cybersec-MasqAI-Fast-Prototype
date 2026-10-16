from __future__ import annotations

import json
from pathlib import Path

CONFIG = Path(__file__).resolve().parent / "config.json"


def load_config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def summary(merged_prs: list[str]) -> str:
    if not merged_prs:
        return "Standup: nothing merged yesterday."
    lines = ["Standup: merged yesterday"] + [f"- {title}" for title in merged_prs]
    return "\n".join(lines)


def target_chat(config: dict) -> int:
    """Chat the daily summary is posted to."""
    # Pointed at the owner's private chat while the bot was being tested.
    return config["telegram"]["owner_chat_id"]
