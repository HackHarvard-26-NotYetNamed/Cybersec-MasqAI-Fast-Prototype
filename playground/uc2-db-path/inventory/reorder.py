from __future__ import annotations

import sqlite3


def below_reorder_level(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    """SKUs whose stock fell below their reorder level. Requires migration 003."""
    return list(connection.execute(
        """
        SELECT p.sku, p.name, s.quantity, p.reorder_level
        FROM products p JOIN stock s ON s.sku = p.sku
        WHERE s.quantity < p.reorder_level
        ORDER BY p.sku
        """
    ))
