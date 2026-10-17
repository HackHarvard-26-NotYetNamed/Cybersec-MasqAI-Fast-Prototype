#!/usr/bin/env python3
"""Host-side port for the ESP32-OTA MicroPython driver."""

import argparse
import json
import sys
import urllib.parse
import urllib.request
import urllib.error


class Port:
    def __init__(self, host, token, timeout=10):
        self.base = "http://" + host.strip().rstrip("/")
        self.token = token
        self.timeout = timeout

    def request(self, method, path, body=None, headers=None):
        request_headers = {"X-OTA-Token": self.token}
        request_headers.update(headers or {})
        request = urllib.request.Request(self.base + path, data=body, headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError("device returned HTTP %s: %s" % (exc.code, detail)) from exc

    def list(self, path):
        query = urllib.parse.urlencode({"path": path})
        return json.loads(self.request("GET", "/api/list?" + query))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Transfer files and use the shell on an ESP32-OTA device")
    parser.add_argument("--host", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--timeout", type=float, default=10)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health")
    sub.add_parser("reboot")
    ls = sub.add_parser("ls"); ls.add_argument("path", nargs="?", default="/")
    put = sub.add_parser("put"); put.add_argument("local"); put.add_argument("remote")
    get = sub.add_parser("get"); get.add_argument("remote"); get.add_argument("local")
    rm = sub.add_parser("rm"); rm.add_argument("remote")
    mkdir = sub.add_parser("mkdir"); mkdir.add_argument("remote")
    shell = sub.add_parser("shell")
    shell.add_argument("shell_command", nargs="*")
    args = parser.parse_args(argv)
    port = Port(args.host, args.token, args.timeout)
    if args.command == "health":
        print(port.request("GET", "/health").decode())
    elif args.command == "reboot":
        print(port.request("POST", "/api/reboot", b"").decode())
    elif args.command == "ls":
        print(json.dumps(port.list(args.path), indent=2))
    elif args.command == "put":
        with open(args.local, "rb") as source:
            port.request("POST", "/api/upload", source.read(), {"X-Path": args.remote})
        print("uploaded", args.remote)
    elif args.command == "get":
        data = port.request("GET", "/api/download?" + urllib.parse.urlencode({"path": args.remote}))
        with open(args.local, "wb") as target:
            target.write(data)
        print("downloaded", args.remote)
    elif args.command == "rm":
        port.request("POST", "/api/delete", b"", {"X-Path": args.remote}); print("deleted", args.remote)
    elif args.command == "mkdir":
        port.request("POST", "/api/mkdir", b"", {"X-Path": args.remote}); print("created", args.remote)
    elif args.command == "shell":
        if args.shell_command:
            print(port.request("POST", "/api/shell", " ".join(args.shell_command).encode()).decode())
        else:
            while True:
                try: line = input("esp32> ")
                except (EOFError, KeyboardInterrupt): break
                if line in ("exit", "quit"): break
                print(port.request("POST", "/api/shell", line.encode()).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
