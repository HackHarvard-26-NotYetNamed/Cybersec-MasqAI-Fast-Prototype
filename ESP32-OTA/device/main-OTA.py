"""Authenticated MicroPython HTTP file port and shell."""

import os
import socket
import sys
import time

try:
    import _thread
except ImportError:
    _thread = None

import ota_config


_display = None
_display_addr = 0
_display_error = ""
_wlan = None
_ip_address = ""


class _StatusDisplay:
    def __init__(self):
        from machine import I2C, Pin
        from ssd1306 import SSD1306_I2C

        self.i2c = I2C(
            ota_config.DISPLAY_I2C_ID,
            scl=Pin(ota_config.DISPLAY_SCL_PIN),
            sda=Pin(ota_config.DISPLAY_SDA_PIN),
            freq=ota_config.DISPLAY_I2C_FREQ,
        )
        found = self.i2c.scan()
        preferred = ota_config.DISPLAY_ADDR
        address = preferred if preferred in found else None
        if address is None:
            for candidate in (0x3C, 0x3D):
                if candidate in found:
                    address = candidate
                    break
        if address is None:
            raise OSError("SSD1306 not found on I2C: %s" % found)
        self.address = address
        self.oled = SSD1306_I2C(
            ota_config.DISPLAY_WIDTH,
            ota_config.DISPLAY_HEIGHT,
            self.i2c,
            addr=address,
        )

    def show(self, title, lines):
        self.oled.fill(0)
        self.oled.text(str(title)[:21], 0, 0)
        y = 16
        for line in lines:
            if y >= ota_config.DISPLAY_HEIGHT:
                break
            self.oled.text(str(line)[:21], 0, y)
            y += 8
        self.oled.show()


def _display_show(title, lines=()):
    if _display is None:
        return
    try:
        _display.show(title, lines)
    except Exception as exc:
        global _display_error
        _display_error = str(exc)


def _init_display():
    global _display, _display_addr, _display_error
    if not getattr(ota_config, "DISPLAY_ENABLED", True):
        return
    try:
        _display = _StatusDisplay()
        _display_addr = _display.address
        _display_show("ESP32 OTA", ("BOOTING", "SCL %d SDA %d" % (ota_config.DISPLAY_SCL_PIN, ota_config.DISPLAY_SDA_PIN)))
    except Exception as exc:
        _display = None
        _display_addr = 0
        _display_error = str(exc)


def _display_wifi_connecting():
    _display_show("ESP32 OTA", ("WIFI CONNECTING", ota_config.WIFI_SSID))


def _display_online(ip_address):
    _display_show("ESP32 OTA", ("ONLINE", "IP " + ip_address, "HOST " + ota_config.HOSTNAME))


def _display_wifi_failed():
    _display_show("ESP32 OTA", ("WIFI FAILED", "RETRYING"))


def _reply(conn, status, body=b"", content_type="text/plain"):
    if isinstance(body, str):
        body = body.encode()
    header = "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (status, content_type, len(body))
    conn.send(header.encode())
    if body:
        conn.send(body)


def _safe(path):
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    parts = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError("path escapes filesystem")
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def _read_request(conn):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 8192:
        chunk = conn.recv(512)
        if not chunk:
            break
        data += chunk
    marker = data.find(b"\r\n\r\n")
    if marker < 0:
        raise ValueError("bad HTTP request")
    head, body = data[:marker].decode(), data[marker + 4:]
    lines = head.split("\r\n")
    method, target, _ = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower().strip()] = value.strip()
    length = int(headers.get("content-length", "0"))
    while len(body) < length:
        body += conn.recv(min(1024, length - len(body)))
    return method, target, headers, body[:length]


def _json(value):
    # The responses are deliberately simple and avoid requiring ujson/json.
    if isinstance(value, list):
        return "[" + ",".join(_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join('"%s":%s' % (key, _json(val)) for key, val in value.items()) + "}"
    if isinstance(value, str):
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _list(path):
    result = []
    for name in os.listdir(path):
        child = (path.rstrip("/") + "/" + name) if path != "/" else "/" + name
        try:
            is_dir = (os.stat(child)[0] & 0x4000) != 0
            size = 0 if is_dir else os.stat(child)[6]
        except OSError:
            is_dir, size = False, 0
        result.append({"name": name, "path": child, "directory": is_dir, "size": size})
    return result


def _shell(command):
    words = command.strip().split()
    if not words:
        return ""
    op = words[0]
    if op in ("pwd",):
        return "/"
    if op in ("ls", "dir"):
        return "\n".join(item["name"] + ("/" if item["directory"] else "") for item in _list(_safe(words[1] if len(words) > 1 else "/")))
    if op == "cat" and len(words) == 2:
        with open(_safe(words[1]), "r") as handle:
            return handle.read()
    if op == "mkdir" and len(words) == 2:
        os.mkdir(_safe(words[1]))
        return "ok"
    if op in ("rm", "delete") and len(words) == 2:
        os.remove(_safe(words[1]))
        return "ok"
    if op == "help":
        return "pwd | ls [path] | cat path | mkdir path | rm path | help"
    return "error: supported commands are pwd, ls, cat, mkdir, rm, help"


def _handle(conn):
    method, target, headers, body = _read_request(conn)
    if headers.get("x-ota-token") != ota_config.OTA_TOKEN:
        return _reply(conn, "401 Unauthorized", "unauthorized")
    path, _, query = target.partition("?")
    params = {}
    for pair in query.split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            params[key] = value.replace("%2F", "/").replace("%20", " ")
    if path == "/health" and method == "GET":
        return _reply(conn, "200 OK", _json({
            "ok": True,
            "hostname": ota_config.HOSTNAME,
            "ip": _ip_address,
            "uptime_ms": time.ticks_ms(),
            "display": _display is not None,
            "display_addr": _display_addr,
            "display_error": _display_error,
        }), "application/json")
    if path == "/api/list" and method == "GET":
        return _reply(conn, "200 OK", _json(_list(_safe(params.get("path", "/")))), "application/json")
    if path == "/api/download" and method == "GET":
        with open(_safe(params.get("path", "/")), "rb") as handle:
            data = handle.read()
        return _reply(conn, "200 OK", data, "application/octet-stream")
    if path == "/api/upload" and method == "POST":
        with open(_safe(headers.get("x-path", "/upload.bin")), "wb") as handle:
            handle.write(body)
        return _reply(conn, "200 OK", "ok")
    if path == "/api/delete" and method == "POST":
        os.remove(_safe(headers["x-path"]))
        return _reply(conn, "200 OK", "ok")
    if path == "/api/mkdir" and method == "POST":
        os.mkdir(_safe(headers["x-path"]))
        return _reply(conn, "200 OK", "ok")
    if path == "/api/shell" and method == "POST":
        return _reply(conn, "200 OK", _shell(body.decode()))
    if path == "/api/reboot" and method == "POST":
        _reply(conn, "200 OK", "rebooting")
        time.sleep_ms(250)
        __import__("machine").reset()
        return
    return _reply(conn, "404 Not Found", "not found")


def serve():
    addr = socket.getaddrinfo("0.0.0.0", ota_config.PORT)[0][-1]
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(addr)
    server.listen(2)
    while True:
        conn, _ = server.accept()
        try:
            _handle(conn)
        except Exception as exc:
            try:
                _reply(conn, "400 Bad Request", "error: " + str(exc))
            except Exception:
                pass
        finally:
            conn.close()


def _connect_wifi():
    global _wlan, _ip_address
    network = __import__("network")
    wlan = network.WLAN(network.STA_IF)
    _wlan = wlan
    wlan.active(True)
    _display_wifi_connecting()
    if not wlan.isconnected():
        wlan.connect(ota_config.WIFI_SSID, ota_config.WIFI_PASSWORD)
    deadline = time.ticks_add(time.ticks_ms(), ota_config.WIFI_TIMEOUT_MS)
    while not wlan.isconnected() and time.ticks_diff(deadline, time.ticks_ms()) > 0:
        time.sleep_ms(100)
    if not wlan.isconnected():
        _ip_address = ""
        _display_wifi_failed()
        return False
    _ip_address = wlan.ifconfig()[0]
    _display_online(_ip_address)
    return True


def _runner():
    while True:
        if _connect_wifi():
            try:
                serve()
            except Exception as exc:
                sys.print_exception(exc)
        time.sleep(5)


def start():
    _init_display()
    if _thread is None:
        _display_show("ESP32 OTA", ("NO THREAD SUPPORT",))
        return False
    _thread.start_new_thread(_runner, ())
    return True
