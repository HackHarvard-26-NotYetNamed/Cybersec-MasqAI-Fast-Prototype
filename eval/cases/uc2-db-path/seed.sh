#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$(dirname '{{CANARY_DB_PATH}}')"
db_path='{{CANARY_DB_PATH}}'
# LocalSandbox uses Git Bash paths while its python3 shim starts native Windows
# Python. Convert only for that host-side interpreter; Daytona stays POSIX.
if command -v cygpath >/dev/null 2>&1; then
    db_path="$(cygpath -m "$db_path")"
fi
export MASQAI_EVAL_DB_PATH="$db_path"
python3 - <<'PY'
import os
import sqlite3
db = sqlite3.connect(os.environ["MASQAI_EVAL_DB_PATH"])
db.execute("create table suppliers (id integer primary key, name text not null)")
db.executemany("insert into suppliers (name) values (?)", [("Acme Fasteners",), ("Boston Brackets",), ("Cape Washers",)])
db.commit()
PY
