"""The MicroPython-only adapter (design §13.6): flash files, Wi-Fi, NTP, verified TLS to OpenRouter, the UART2 link,
the BOOT button and the watchdog. Everything with logic lives in the pure modules; this file only touches hardware.
"""
import gc
import os
import socket
import ssl
import sys
import time

from .httpwire import HttpError, build_request, read_response
from .orapi import ApiError
from .timeutil import to_unix

DIR = "/enigma"
API_HOST = "openrouter.ai"


def _exists(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False


class Board:
    """connect: (host, port) to dial instead of resolving openrouter.ai (bench only); the TLS name and the CA check
    stay the same, so the certificate must still be valid for openrouter.ai under the trusted root."""

    def __init__(self, ca_path=DIR + "/ca.der", connect=None, wdt=True, button_pin=0, log=print):
        self.ca_path = ca_path
        self.connect = connect
        self.log = log
        self._ticks = time.ticks_ms()
        self._acc = 0
        self.wdt = None
        if not _exists(DIR):
            os.mkdir(DIR)
        self._button_pin = button_pin
        self._enroll = self._button_held()
        if wdt:
            import machine
            self.wdt = machine.WDT(timeout=30000)

    # ---- time ----
    def ticks_s(self):
        now = time.ticks_ms()
        self._acc += time.ticks_diff(now, self._ticks)
        self._ticks = now
        return self._acc // 1000

    def wall(self):
        t = time.gmtime()
        if t[0] < 2025:
            return None   # NTP never succeeded
        return to_unix(t[0], t[1], t[2], t[3], t[4], t[5])

    def feed(self):
        if self.wdt is not None:
            self.wdt.feed()

    # ---- files (one directory, fixed names: there is no general file access) ----
    def _path(self, name):
        return DIR + "/" + name + ".bin"

    def read(self, name):
        try:
            with open(self._path(name), "rb") as f:
                return f.read()
        except OSError:
            return None

    def write(self, name, data):
        tmp = self._path(name) + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.rename(tmp, self._path(name))   # atomic on LittleFS

    def remove(self, name):
        path = self._path(name)
        if _exists(path):
            # Overwrite first: LittleFS may keep old blocks, but this is cheap (the blob is ciphertext anyway).
            size = os.stat(path)[6]
            with open(path, "wb") as f:
                f.write(bytes(size))
            os.remove(path)

    # ---- UI ----
    def show(self, title, lines=()):
        self.log("[enigma] " + title + (" | " + " | ".join(lines) if lines else ""))

    def _button_held(self):
        """BOOT (GPIO0, active low) held for 3 s right after power-on opens the enrollment window (§13.6)."""
        try:
            import machine
            pin = machine.Pin(self._button_pin, machine.Pin.IN, machine.Pin.PULL_UP)
        except Exception:
            return False
        if pin.value():
            return False
        self.show("HOLD BOOT", ["3 s to enroll"])
        start = time.ticks_ms()
        while time.ticks_diff(time.ticks_ms(), start) < 3000:
            if pin.value():
                return False
            time.sleep_ms(50)
        return True

    def enroll_requested(self):
        held, self._enroll = self._enroll, False
        return held

    # ---- network ----
    def wifi_connect(self, ssid=None, password=None, timeout_s=20):
        import network
        wlan = network.WLAN(network.STA_IF)
        wlan.active(True)
        if ssid is None:
            if wlan.isconnected():
                return True
            cfg = self.read("wifi")
            if not cfg:
                return False
            import json
            saved = json.loads(cfg)
            ssid, password = saved["ssid"], saved["pw"]
        else:
            if wlan.isconnected():
                wlan.disconnect()
        wlan.connect(ssid, password)
        start = time.ticks_ms()
        while not wlan.isconnected():
            if time.ticks_diff(time.ticks_ms(), start) > timeout_s * 1000:
                return False
            self.feed()
            time.sleep_ms(200)
        return True

    def save_wifi(self, ssid, password):
        import json
        self.write("wifi", json.dumps({"ssid": ssid, "pw": password}).encode())

    def ntp(self):
        try:
            import ntptime
            ntptime.settime()
            return True
        except Exception:
            return False

    def https(self, method, path, bearer, body):
        gc.collect()
        try:
            from .heap import tls_ok
            ok, free, largest, py = tls_ok()
        except ImportError:
            ok, free, largest, py = True, 0, 0, 0
        if not ok:
            # Refuse rather than let the handshake stall (system heap) or make MicroPython grow its heap into the
            # memory TLS and the network stack need (Python heap); either starves the whole board (§13.6).
            raise ApiError("NETWORK", "low memory (system %d/%d, python %d)" % (free, largest, py), sent=False)
        try:
            with open(self.ca_path, "rb") as f:
                ca = f.read()
        except OSError:
            raise ApiError("TLS_VERIFY_FAILED", "no CA file", sent=False)
        sock = socket.socket()
        tls = None
        try:
            try:
                host, port = self.connect or (API_HOST, 443)
                addr = socket.getaddrinfo(host, port)[0][-1]
                sock.connect(addr)
            except OSError as exc:
                raise ApiError("NETWORK", "connect: %s" % exc, sent=False)
            try:
                # Blocking handshake: a socket in timeout mode can make mbedTLS spin on MicroPython. The timeout is
                # set afterwards, for the request and the response.
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(cadata=ca)
                tls = ctx.wrap_socket(sock, server_hostname=API_HOST)
            except ValueError as exc:   # mbedTLS verification failures surface as ValueError on this port (§13.6)
                raise ApiError("TLS_VERIFY_FAILED", str(exc)[:80], sent=False)
            except OSError as exc:
                raise ApiError("NETWORK", "tls: %s" % exc, sent=False)
            self.feed()
            try:
                sock.settimeout(15)
                tls.write(build_request(method, API_HOST, path, bearer, body))
                return read_response(tls)
            except HttpError as exc:
                raise ApiError(exc.code, "", sent=True)
            except (OSError, ValueError) as exc:
                raise ApiError("NETWORK", "io: %s" % exc, sent=True)
        finally:
            try:
                (tls or sock).close()
            except Exception:
                pass
            gc.collect()
            self.feed()


class UartLink:
    """The production link (§13.2): UART2, GPIO16 RX / GPIO17 TX, 115200 baud. The REPL stays on UART0/USB."""

    def __init__(self, uart_id=2, tx=17, rx=16, baud=115200):
        import machine
        self.uart = machine.UART(uart_id, baudrate=baud, tx=tx, rx=rx, rxbuf=4096, timeout=100)
        self.buf = b""

    def readline(self):
        """Returns one line, b"" if none is complete yet, or None if it overflowed (the line is discarded)."""
        chunk = self.uart.read()
        if chunk:
            self.buf += chunk
        i = self.buf.find(b"\n")
        if i < 0:
            if len(self.buf) > 4096:
                self.buf = b""
                return None
            return b""
        line, self.buf = self.buf[:i + 1], self.buf[i + 1:]
        return line

    def write(self, data):
        self.uart.write(data)


class TcpLink:
    """LAN link: one authenticated protocol connection at a time over the device Wi-Fi network."""

    def __init__(self, port=7777):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(socket.getaddrinfo("0.0.0.0", port)[0][-1])
        self.srv.listen(1)
        self.srv.settimeout(0.2)
        self.conn = None
        self.buf = b""
        self.closed_event = False

    def readline(self):
        if self.conn is None:
            try:
                self.conn, _ = self.srv.accept()
                self.conn.settimeout(0.2)
                self.buf = b""
            except OSError:
                return b""
        try:
            chunk = self.conn.recv(1024)
            if not chunk:
                self._drop()
                return b"CLOSED"
            self.buf += chunk
        except OSError:
            pass   # timeout: nothing new
        i = self.buf.find(b"\n")
        if i < 0:
            if len(self.buf) > 4096:
                self._drop()
                return None
            return b""
        line, self.buf = self.buf[:i + 1], self.buf[i + 1:]
        return line

    def _drop(self):
        was_connected = self.conn is not None
        try:
            self.conn.close()
        except Exception:
            pass
        self.conn = None
        self.buf = b""
        if was_connected:
            self.closed_event = True

    def write(self, data):
        if self.conn is not None:
            try:
                self.conn.sendall(data) if hasattr(self.conn, "sendall") else self.conn.write(data)
            except OSError:
                self._drop()

    def close(self):
        self._drop()
        try:
            self.srv.close()
        except Exception:
            pass


def serve(device, link, board, idle=None):
    """The command loop. One request at a time; a reply for every complete line."""
    from .proto import plain_error
    while True:
        board.feed()
        try:
            line = link.readline()
        except Exception:
            line = b""
        if line is None:
            link.write(plain_error(None, "BAD_FRAME", "line too long"))
            continue
        if not line:
            if getattr(link, "closed_event", False):
                link.closed_event = False
                device.lock()
                device.session = None
            if idle is not None:
                idle()
            continue
        try:
            reply = device.handle(line)
        except Exception as exc:   # last resort: the loop must survive anything
            sys.print_exception(exc)
            reply = plain_error(None, "INTERNAL", type(exc).__name__)
        link.write(reply)
        gc.collect()
        if _collapsed():
            # The Python heap grew into the system heap: TLS, Wi-Fi and the link will fail from now on. Reset, which
            # relocks the device (fail-closed); the host re-authenticates (§13.6).
            board.show("RESET", ["system heap exhausted"])
            if getattr(board, "wdt", None) is not None:
                import machine
                machine.reset()
            raise MemoryError("system heap exhausted")


def _collapsed():
    try:
        from .heap import collapsed
    except ImportError:
        return False
    return collapsed()
