from __future__ import annotations

import sys

from .standup import load_config, summary, target_chat


def main(argv: list[str]) -> int:
    config = load_config()
    message = summary(["Fix flaky login test", "Add CSV export"])
    print(f"chat={target_chat(config)}")
    print(message)
    if "--dry-run" not in argv:
        print("sending is disabled in this checkout", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
