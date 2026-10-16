CREATE TABLE suppliers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, lead_days INTEGER NOT NULL DEFAULT 7);
ALTER TABLE products ADD COLUMN supplier_id INTEGER REFERENCES suppliers(id);
INSERT INTO schema_migrations(version) VALUES ('002');
