"""Export the live gateway Key Enigma timeline for the public Trust page.

Usage:
  python scripts/export_enigma.py --url http://127.0.0.1:8787 --token <admin-token>

The admin token is accepted as an argument because it is a local gateway session token,
not an OpenRouter credential. The output contains labels and times only.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "web" / "public" / "data" / "keys.json"


def validate(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("status") != "live" or payload.get("provider") != "OpenRouter":
        raise ValueError("gateway export is not a live OpenRouter export")
    keys = payload.get("keys")
    if not isinstance(keys, list):
        raise ValueError("gateway export has no key list")
    safe: list[dict[str, Any]] = []
    for key in keys:
        if not isinstance(key, dict) or not isinstance(key.get("label"), str):
            raise ValueError("gateway export contains an invalid key record")
        if any(field not in key or isinstance(key[field], bool) or not isinstance(key[field], (int, float))
               or not math.isfinite(key[field]) for field in ("createdAt", "activeUntil", "revokedAt")):
            raise ValueError("gateway export contains invalid key times")
        if any(key[field] < 0 for field in ("createdAt", "activeUntil", "revokedAt")):
            raise ValueError("gateway export contains negative key times")
        safe.append({"label": key["label"], "createdAt": key["createdAt"], "activeUntil": key["activeUntil"],
                     "revokedAt": key["revokedAt"]})
    return {"status": "live", "provider": "OpenRouter", "keys": safe, "honeytokens": []}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8787")
    parser.add_argument("--token", required=True, help="local gateway admin token")
    args = parser.parse_args()
    with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
        response = client.get(args.url.rstrip("/") + "/api/enigma/export", headers={"x-masqai-token": args.token})
        response.raise_for_status()
        payload = validate(response.json())
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {len(payload['keys'])} key records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
