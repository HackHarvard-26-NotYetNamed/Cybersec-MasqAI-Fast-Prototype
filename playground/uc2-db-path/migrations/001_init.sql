CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE products (sku TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE stock (sku TEXT PRIMARY KEY REFERENCES products(sku), quantity INTEGER NOT NULL);
INSERT INTO schema_migrations(version) VALUES ('001');
