"""Start the MasqAI gateway on 127.0.0.1.

    python run_gateway.py [--config masqai.json] [--playground]

--playground enables GET /api/sessions/{id}/replay (the export contains raw values, so it is off by
default). The admin token for the GUI and /api/* is generated on every start, printed once, and never
written to disk.

Key Enigma: for every provider with key_enigma enabled, the custody backend is opened here, before uvicorn starts.
In passphrase mode that means typing the vault passphrase on this terminal; without a terminal the gateway refuses
to start. Rotation runs in this one process, so there is exactly one uvicorn worker.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys
from typing import Any, Callable

import uvicorn

from masqai.app import create_app
from masqai.config import GatewayConfig, load_config, validation_errors
from masqai.custody import CustodyError, ManagementBackend, load_backend


def open_backends(config: GatewayConfig, *, prompt: Callable[[str], str] | None = None,
                  transport: Any = None) -> dict[str, ManagementBackend]:
    """Open the custody backend of each rotating provider. On any failure, close the ones already opened."""
    backends: dict[str, ManagementBackend] = {}
    try:
        for provider in config.providers:
            if not provider.rotates:
                continue
            enigma = provider.key_enigma
            print(f"  Key Enigma ({provider.name}): {enigma.custody.mode} custody", flush=True)
            backends[provider.name] = load_backend(enigma.custody, workspace_id=enigma.workspace_id,
                                                   instance_id=enigma.instance_id, prompt=prompt, transport=transport)
    except BaseException:
        close_backends(backends)
        raise
    return backends


def close_backends(backends: dict[str, ManagementBackend]) -> None:
    async def close() -> None:
        for backend in backends.values():
            await backend.aclose()
    if backends:
        asyncio.run(close())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MasqAI gateway")
    parser.add_argument("--config", default=os.getenv("MASQAI_CONFIG", "masqai.json"))
    parser.add_argument("--playground", action="store_true", help="enable the replay export (raw values; demos only)")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except Exception as exc:  # fail at startup, not with a 502 on every request
        print(f"masqai: invalid config {args.config}:", file=sys.stderr)
        for error in validation_errors(exc):
            print(f"  {'.'.join(map(str, error['loc'])) or '(root)'}: {error['msg']}", file=sys.stderr)
        return 2
    keyring = None
    if any(p.rotates for p in config.providers):
        from masqai.enigma import build_keyring
        try:
            backends = open_backends(config)
        except CustodyError as exc:
            print(f"masqai: Key Enigma cannot start: {exc}", file=sys.stderr)
            return 2
        except (KeyboardInterrupt, EOFError):
            print("\nmasqai: cancelled", file=sys.stderr)
            return 130
        # From here the key sources own the backends: the app's lifespan closes them (and wipes the key).
        try:
            keyring = build_keyring(config, backends)
        except BaseException:
            close_backends(backends)
            raise
    token = secrets.token_urlsafe(32)
    app = create_app(config, admin_token=token, playground=args.playground, keyring=keyring)
    base = f"http://{config.host}:{config.port}"
    print(f"\n  MasqAI {base}  (agents: {base}/v1)")
    print(f"  GUI: {base}/#token={token}")
    print(f"  MASQAI_ADMIN_TOKEN={token}")
    if args.playground:
        print("  --playground: replay export enabled (contains raw values)")
    print(flush=True)
    # workers=1, always: Key Enigma rotation state lives in this process (a second worker would rotate on its own).
    uvicorn.run(app, host=config.host, port=config.port, log_level="warning", workers=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
