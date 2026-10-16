from __future__ import annotations

import sys

from .keys import api_key, deployment, fingerprint


def main(argv: list[str]) -> int:
    deploy = deployment()
    key = api_key(deploy["key_ref"])
    print(f"environment={deploy['environment']} key_ref={deploy['key_ref']} key={fingerprint(key)}")
    if "--dry-run" in argv:
        return 0
    print("worker loop not available in this checkout", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
