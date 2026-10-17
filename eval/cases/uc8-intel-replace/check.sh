#!/usr/bin/env bash
python3 - <<'PY'
import pathlib, sys
text = pathlib.Path("summary.md").read_text().lower()
sys.exit(0 if all(word in text for word in ("cursor", "idempot", "v2")) else 1)
PY
