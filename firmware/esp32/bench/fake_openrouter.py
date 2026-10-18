"""BENCH ONLY: a fake OpenRouter management API over real TLS on the LAN, for the device bench test (design §13.6,
build step 8). It reuses tests.helpers.FakeOpenRouter, so the board talks to the same fake the CPython tests use.

A throwaway CA signs a certificate for `openrouter.ai`. The board's bench app trusts only that CA and dials this
host's IP instead of resolving openrouter.ai, while TLS still checks the name `openrouter.ai`. Nothing here is real:
the management key is FAKE-marked and the CA key is deleted after signing.

    python firmware/esp32/bench/fake_openrouter.py [--port 8443] [--out DIR]

Control endpoint for the bench driver (plain HTTP on --control, loopback only):
    GET /state -> JSON {keys: [...public records...], calls: [...]}
    POST /script {"management_key": ..., "budgets": n, "fail": [[method, prefix, [codes]]]}
"""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
import httpx  # noqa: E402

from tests.helpers import FakeOpenRouter  # noqa: E402

OPENSSL = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"


def make_identity(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)

    def run(*args: str) -> None:
        subprocess.run([OPENSSL, *args], cwd=out, check=True, capture_output=True)
    (out / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                  "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:openrouter.ai\n", encoding="ascii")
    run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key")
    run("req", "-new", "-x509", "-key", "ca.key", "-sha256", "-days", "7", "-subj", "/CN=MasqAI bench CA (throwaway)",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign", "-out", "ca.pem")
    run("x509", "-in", "ca.pem", "-outform", "DER", "-out", "bench_ca.der")
    run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "leaf.key")
    run("req", "-new", "-key", "leaf.key", "-subj", "/CN=openrouter.ai", "-out", "leaf.csr")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "7",
        "-sha256", "-extfile", "leaf.ext", "-out", "leaf.pem")
    for junk in ("ca.key", "leaf.csr", "leaf.ext", "ca.srl"):
        (out / junk).unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--control", type=int, default=8444)
    parser.add_argument("--out", default=str(Path.home() / ".masqai-bench"))
    args = parser.parse_args()
    out = Path(args.out)
    if not (out / "bench_ca.der").exists():
        make_identity(out)
    fake = FakeOpenRouter()
    lock = threading.Lock()
    log: list[str] = []

    class Api(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _serve(self):
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items() if k.lower() in ("authorization", "content-type")}
            request = httpx.Request(self.command, "https://openrouter.ai" + self.path, headers=headers, content=body)
            with lock:
                response = fake.handler(request)
                log.append(f"{self.command} {self.path.split('?')[0]} -> {response.status_code}")
            data = response.content
            self.send_response(response.status_code)
            self.send_header("Date", formatdate(usegmt=True))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True
        do_GET = do_POST = do_PATCH = do_DELETE = _serve

    class Control(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj):
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            with lock:
                self._json({"keys": [{k: v for k, v in r.items() if not k.startswith("_")} for r in fake.keys.values()],
                            "calls": list(log)})

        def do_POST(self):
            script = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
            with lock:
                if "management_key" in script:
                    fake.management_key = script["management_key"]
                if "budgets" in script:
                    fake.budgets = [{"id": "b0"}] * int(script["budgets"])
                for method, prefix, codes in script.get("fail", []):
                    fake.fail[(method, prefix)] = list(codes)
                if script.get("add_key"):
                    fake.add_key(script["add_key"])
            self._json({"ok": True})

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # TLS 1.2 only: what the board negotiated with the real openrouter.ai (bench test 2). Offering 1.3 makes the
    # board's handshake stall on this MicroPython build.
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(out / "leaf.pem", out / "leaf.key")

    class TlsServer(ThreadingHTTPServer):
        """The TLS handshake runs in the per-connection thread (with a timeout), so one stalled client can't block
        the accept loop."""

        def finish_request(self, request, client_address):
            request.settimeout(20)
            try:
                tls = ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                with lock:
                    log.append(f"TLS handshake from {client_address[0]} failed: {type(exc).__name__}")
                return
            self.RequestHandlerClass(tls, client_address, self)

    api = TlsServer(("0.0.0.0", args.port), Api)
    control = ThreadingHTTPServer(("127.0.0.1", args.control), Control)
    threading.Thread(target=control.serve_forever, daemon=True).start()
    print(f"fake OpenRouter (TLS, cert for openrouter.ai) on 0.0.0.0:{args.port}; control on 127.0.0.1:{args.control}", flush=True)
    print(f"board CA file: {out / 'bench_ca.der'}", flush=True)
    api.serve_forever()


if __name__ == "__main__":
    main()
