from __future__ import annotations

import sys

from .client import build_request


def main(argv: list[str]) -> int:
    cities = argv or ["Boston"]
    request = build_request(cities)
    print("POST", request.full_url)
    print(request.data.decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
