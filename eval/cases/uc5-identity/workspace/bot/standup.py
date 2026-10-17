import json
from pathlib import Path


def target_chat() -> int:
    cfg = json.loads((Path(__file__).parent / "config.json").read_text())
    return cfg["telegram"]["team_chat_id"]
