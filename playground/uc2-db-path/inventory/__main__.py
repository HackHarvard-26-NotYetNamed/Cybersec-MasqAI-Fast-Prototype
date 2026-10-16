from __future__ import annotations

import sys

from .db import connect
from .reorder import below_reorder_level


def main(argv: list[str]) -> int:
    command = argv[0] if argv else "stock"
    with connect() as connection:
        if command == "stock":
            for row in connection.execute("SELECT p.sku, p.name, s.quantity FROM products p JOIN stock s ON s.sku = p.sku ORDER BY p.sku"):
                print(f"{row['sku']:<8} {row['name']:<24} {row['quantity']:>5}")
        elif command == "reorder":
            rows = below_reorder_level(connection)
            for row in rows:
                print(f"{row['sku']:<8} {row['name']:<24} {row['quantity']:>5} < {row['reorder_level']}")
            print(f"{len(rows)} SKU(s) to reorder")
        else:
            print(f"unknown command {command!r}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
