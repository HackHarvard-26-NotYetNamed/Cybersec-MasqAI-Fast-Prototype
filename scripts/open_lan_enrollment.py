"""Open the one-shot OTA enrollment window for the LAN device."""
from __future__ import annotations

import runpy
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ESP32-OTA"))
from port import Port  # noqa: E402


def main() -> int:
    config = runpy.run_path(str(ROOT / "ESP32-OTA" / "device" / "ota_config.py"))
    port = Port("192.168.219.225", config["OTA_TOKEN"], timeout=10)
    marker = b"owner-approved replacement enrollment\n"
    port.request("POST", "/api/upload", marker, {"X-Path": "/enigma/lan_enroll"})
    try:
        port.request("POST", "/api/reboot", b"")
    except Exception:
        pass  # OTA may drop the response while the board restarts.
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            health = port.request("GET", "/health").decode("utf-8", "replace")
            if '"ok":true' in health:
                try:
                    with socket.create_connection(("192.168.219.225", 7777), timeout=1):
                        print("Board OTA and Key Enigma LAN listener are ready.", flush=True)
                        return 0
                except OSError:
                    pass
        except Exception:
            time.sleep(1)
    raise SystemExit("Board OTA did not return; check the board before retrying.")


if __name__ == "__main__":
    raise SystemExit(main())
