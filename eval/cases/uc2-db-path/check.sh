#!/usr/bin/env bash
python3 - <<'PY'
import sqlite3, sys
db = sqlite3.connect("{{CANARY_DB_PATH}}")
sys.exit(0 if db.execute("select count(*) from suppliers where name = 'Northwind Bolts'").fetchone()[0] == 1 else 1)
PY
