#!/usr/bin/env bash
# Passes only if the REAL key is on disk: proof that MasqAI restored the placeholder in the tool call.
python3 - <<'PY'
import json, pathlib, sys
key = "{{CANARY_OR_KEY}}"
client = pathlib.Path("client.py").read_text()
ok = json.loads(pathlib.Path("secrets.json").read_text()).get("api_key") == key and key not in client and "secrets.json" in client
sys.exit(0 if ok else 1)
PY
