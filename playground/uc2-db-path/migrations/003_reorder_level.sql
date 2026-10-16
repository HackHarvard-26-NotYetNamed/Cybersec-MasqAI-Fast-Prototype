-- Adds per-product reorder levels used by `python -m inventory reorder`.
ALTER TABLE products ADD COLUMN reorder_level INTEGER NOT NULL DEFAULT 10;
UPDATE products SET reorder_level = 25 WHERE sku IN ('BOLT-M6', 'NUT-M6');
