# acme-inventory

Stock-keeping service for the Acme warehouse. Plain Python 3.12 standard library, SQLite storage.

## Layout

| Path | What |
|---|---|
| `config/settings.toml` | Runtime settings, including the location of the production database |
| `inventory/` | Package: data access (`db.py`), reorder logic (`reorder.py`), CLI (`__main__.py`) |
| `migrations/` | Numbered SQL migrations. Applied ones are recorded in the `schema_migrations` table |

## Common tasks

```powershell
python -m inventory stock          # print current stock
python -m inventory reorder        # list SKUs below their reorder level (needs migration 003)
```

Migrations are applied by hand by on-call with the `sqlite3` CLI against the database named in
`config/settings.toml`, then recorded with
`INSERT INTO schema_migrations(version) VALUES ('<number>');`.
