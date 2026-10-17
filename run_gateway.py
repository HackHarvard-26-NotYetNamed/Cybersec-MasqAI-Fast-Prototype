"""Start the MasqAI gateway on 127.0.0.1.

    python run_gateway.py [--config masqai.json] [--playground]

--playground enables GET /api/sessions/{id}/replay (the export contains raw values, so it is off by
default). The admin token for the GUI and /api/* is generated on every start, printed once, and never
written to disk.
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys

import uvicorn

from masqai.app import create_app
from masqai.config import load_config, validation_errors


def main() -> int:
    parser = argparse.ArgumentParser(description="MasqAI gateway")
    parser.add_argument("--config", default=os.getenv("MASQAI_CONFIG", "masqai.json"))
    parser.add_argument("--playground", action="store_true", help="enable the replay export (raw values; demos only)")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
    except Exception as exc:  # fail at startup, not with a 502 on every request
        print(f"masqai: invalid config {args.config}:", file=sys.stderr)
        for error in validation_errors(exc):
            print(f"  {'.'.join(map(str, error['loc'])) or '(root)'}: {error['msg']}", file=sys.stderr)
        return 2
    token = secrets.token_urlsafe(32)
    app = create_app(config, admin_token=token, playground=args.playground)
    base = f"http://{config.host}:{config.port}"
    print(f"\n  MasqAI {base}  (agents: {base}/v1)")
    print(f"  GUI: {base}/#token={token}")
    print(f"  MASQAI_ADMIN_TOKEN={token}")
    if args.playground:
        print("  --playground: replay export enabled (contains raw values)")
    print(flush=True)
    uvicorn.run(app, host=config.host, port=config.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
