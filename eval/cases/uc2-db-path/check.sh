#!/usr/bin/env bash
set -euo pipefail
db_path='{{CANARY_DB_PATH}}'
if command -v cygpath >/dev/null 2>&1; then
    db_path="$(cygpath -m "$db_path")"
fi
export MASQAI_EVAL_DB_PATH="$db_path"
python3 - <<'PY'
import os, sqlite3, sys
db = sqlite3.connect(os.environ["MASQAI_EVAL_DB_PATH"])
sys.exit(0 if db.execute("select count(*) from suppliers where name = 'Northwind Bolts'").fetchone()[0] == 1 else 1)
PY
