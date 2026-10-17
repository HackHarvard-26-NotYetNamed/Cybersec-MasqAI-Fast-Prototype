#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$(dirname '{{CANARY_DB_PATH}}')"
python3 - <<'PY'
import sqlite3
db = sqlite3.connect("{{CANARY_DB_PATH}}")
db.execute("create table suppliers (id integer primary key, name text not null)")
db.executemany("insert into suppliers (name) values (?)", [("Acme Fasteners",), ("Boston Brackets",), ("Cape Washers",)])
db.commit()
PY
