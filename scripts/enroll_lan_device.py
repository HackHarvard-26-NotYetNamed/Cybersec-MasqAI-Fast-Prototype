"""One-shot, owner-confirmed enrollment for a LAN-connected Key Enigma device.

Keeps the X25519 session alive while the owner compares the displayed code. The
management key is read from ormanagement.env only after the local confirmation.
"""
from __future__ import annotations

import argparse
import json
import secrets
import time
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from masqai.custody import CustodyError
from masqai.custody import device as D
from masqai.custody.vault import check_management_key


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKSPACE = "0f08ec6b-562f-4a09-b4fe-cfbc881d0ee6"


def read_management_key(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip() == "OPENROUTER_MANAGEMENT_KEY":
            key = value.strip().strip("\"'")
            if key:
                return key
    raise CustodyError("OPENROUTER_MANAGEMENT_KEY is missing from ormanagement.env")


class Enrollment:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.client = D.DeviceClient(D.open_transport(f"tcp://{args.board}:7777"), timeout=90)
        self.info, self.code = self.client.enroll_begin()
        self.deadline = time.monotonic() + 105
        self.confirmation = secrets.token_urlsafe(24)
        self.instance = secrets.token_hex(4)
        self.done = threading.Event()
        self.result: str | None = None
        self.httpd = HTTPServer(("127.0.0.1", args.control_port), self.handler())

    def handler(self):
        enrollment = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/challenge":
                    self.send_error(404)
                    return
                raw = json.dumps({"code": enrollment.code, "confirmation": enrollment.confirmation,
                                  "device_id": enrollment.args.device_id,
                                  "seconds_remaining": max(0, int(enrollment.deadline - time.monotonic()))}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                if self.path != "/confirm":
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    body = json.loads(self.rfile.read(min(length, 1024)))
                except ValueError:
                    self.send_error(400)
                    return
                if time.monotonic() >= enrollment.deadline:
                    self.send_error(410, "pairing window expired; restart Terminal 1")
                    enrollment.done.set()
                    return
                if not secrets.compare_digest(str(body.get("confirmation", "")), enrollment.confirmation):
                    self.send_error(403, "confirmation does not belong to the active broker session")
                    return
                if body.get("code") != enrollment.code:
                    self.send_error(403, "pairing code does not match")
                    return
                try:
                    enrollment.enroll()
                except Exception as exc:
                    enrollment.result = f"ERROR: {type(exc).__name__}: {exc}"
                    status, response = 500, {"error": enrollment.result}
                else:
                    status = 200
                    response = {"ok": True, "device_id": enrollment.pairing.device_id,
                                "instance_id": enrollment.instance, "pairing_file": str(enrollment.pairing_path)}
                raw = json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                enrollment.done.set()

            def log_message(self, *_: object) -> None:
                return

        return Handler

    def enroll(self) -> None:
        key = read_management_key(ROOT / "ormanagement.env")
        check_management_key(key)
        result = self.client.call("ENROLL_SET", {
            "mk": D.seal_field(self.client.enc, key),
            "ws": self.args.workspace,
            "inst": self.instance,
            "exp": None,
            "pol": {},
        })
        key = ""
        k_mac = D.open_field(self.client.enc, result.get("kmac"))
        unlock = D.open_field(self.client.enc, result.get("us"))
        device_id = result.get("id")
        if len(k_mac) != 32 or len(unlock) != 32 or not isinstance(device_id, str) or not D.DEVICE_ID_RE.fullmatch(device_id):
            raise CustodyError("board returned malformed enrollment data")
        self.pairing = D.Pairing(device_id, bytearray(k_mac), bytearray(unlock), self.args.workspace,
                                 self.instance, D.check_policy(result.get("pol")), D.parse_time(result.get("exp")),
                                 f"tcp://{self.args.board}:7777", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        requested_path = Path(self.args.pairing_file).expanduser()
        default_path = Path.home() / f".masqai/device-{self.args.device_id}.pair"
        self.pairing_path = Path.home() / f".masqai/device-{device_id}.pair" if requested_path == default_path else requested_path
        D.write_pairing(self.pairing_path, self.pairing)
        self.pairing.wipe()

    def run(self) -> None:
        print(f"PAIRING_CODE={self.code}", flush=True)
        print(f"DEVICE_ID={self.args.device_id}", flush=True)
        print(f"CONFIRM_URL=http://127.0.0.1:{self.args.control_port}/confirm", flush=True)
        print(f"CHALLENGE_URL=http://127.0.0.1:{self.args.control_port}/challenge", flush=True)
        print("Compare the board display with this terminal. No credential is read until Terminal 2 confirms.", flush=True)
        self.httpd.timeout = 0.5
        try:
            while not self.done.is_set() and time.monotonic() < self.deadline:
                self.httpd.handle_request()
            if not self.done.is_set():
                raise CustodyError("the pairing session expired; restart Terminal 1 to open a fresh session")
            if self.result:
                raise CustodyError(self.result)
            print(f"ENROLLED pairing_file={self.pairing_path} instance_id={self.instance}", flush=True)
        finally:
            self.httpd.server_close()
            self.client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Owner-confirmed LAN enrollment")
    parser.add_argument("--board", default="192.168.219.225")
    parser.add_argument("--workspace", default=DEFAULT_WORKSPACE)
    parser.add_argument("--device-id", default="esp32-f2324aa7")
    parser.add_argument("--control-port", type=int, default=18777)
    parser.add_argument("--pairing-file", default=str(Path.home() / ".masqai" / "device-esp32-f2324aa7.pair"))
    args = parser.parse_args()
    enrollment = Enrollment(args)
    enrollment.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
