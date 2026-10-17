import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("ota_port", ROOT / "port.py")
ota_port = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ota_port)


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self):
        return self.body


def test_port_adds_authentication_and_lists(monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout):
        seen["request"] = request
        seen["timeout"] = timeout
        return FakeResponse(b'[{"name":"app.py"}]')

    monkeypatch.setattr(ota_port.urllib.request, "urlopen", fake_urlopen)
    port = ota_port.Port("esp32.local", "secret", timeout=3)
    assert port.list("/") == [{"name": "app.py"}]
    assert seen["request"].get_header("X-ota-token") == "secret"
    assert seen["timeout"] == 3


def test_port_upload_request_contains_path_and_bytes(monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout):
        seen["request"] = request
        return FakeResponse(b"ok")

    monkeypatch.setattr(ota_port.urllib.request, "urlopen", fake_urlopen)
    port = ota_port.Port("192.168.1.4", "secret")
    port.request("POST", "/api/upload", b"hello", {"X-Path": "/hello.txt"})
    assert seen["request"].data == b"hello"
    assert seen["request"].get_header("X-path") == "/hello.txt"


def test_reboot_command_posts_to_reboot_endpoint(monkeypatch, capsys):
    seen = {}

    def fake_request(self, method, path, body=None, headers=None):
        seen.update(method=method, path=path, body=body)
        return b"rebooting"

    monkeypatch.setattr(ota_port.Port, "request", fake_request)
    assert ota_port.main(["--host=esp32.local", "--token=secret", "reboot"]) == 0
    assert seen == {"method": "POST", "path": "/api/reboot", "body": b""}
    assert capsys.readouterr().out.strip() == "rebooting"


def test_device_sources_compile_as_python():
    # This catches syntax regressions without importing hardware-only modules.
    for filename in ("main.py", "main-OTA.py", "ota_config.example.py", "app.py"):
        source = (ROOT / "device" / filename).read_text(encoding="ascii")
        compile(source, filename, "exec")
    compile((ROOT / "ssd1306.py").read_text(encoding="ascii"), "ssd1306.py", "exec")


def test_display_pin_configuration_is_explicit():
    config = (ROOT / "device" / "ota_config.example.py").read_text(encoding="ascii")
    assert "DISPLAY_SCL_PIN = 18" in config
    assert "DISPLAY_SDA_PIN = 23" in config
