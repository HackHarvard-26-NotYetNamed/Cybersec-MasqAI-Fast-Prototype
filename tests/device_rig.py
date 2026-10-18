"""Test rig for device custody: the real firmware logic (firmware/esp32/enigma_dev) on a fake board, wired to the
host's DeviceBackend through an in-process transport. OpenRouter is the in-memory FakeOpenRouter (tests/helpers.py).
"""
from __future__ import annotations

import sys
import time
from email.utils import formatdate
from pathlib import Path
from typing import Any

import httpx

FIRMWARE = Path(__file__).resolve().parent.parent / "firmware" / "esp32"
if str(FIRMWARE) not in sys.path:
    sys.path.insert(0, str(FIRMWARE))

from enigma_dev.core import Device  # noqa: E402
from enigma_dev.orapi import ApiError  # noqa: E402

from masqai.custody import BackendUnavailable  # noqa: E402
from masqai.custody.device import DeviceClient, Pairing, check_policy  # noqa: E402

from tests.helpers import FAKE_INSTANCE, FAKE_MGMT_KEY, FAKE_WORKSPACE, FakeOpenRouter  # noqa: E402


class FakeBoard:
    """In-memory flash, a settable clock, and HTTPS answered by a FakeOpenRouter. `net_down` makes every call fail
    before it is sent; `drop_after_send` makes the next call fail after it was sent (the key may exist)."""

    def __init__(self, fake: FakeOpenRouter | None = None, *, enroll: bool = False, now: int | None = None,
                 clock: Any = None) -> None:
        self.fake = fake or FakeOpenRouter()
        self.files: dict[str, bytes] = {}
        self.clock = clock      # a tests.test_rotation.FakeClock: board time follows it (OpenRouter's clock = utcnow)
        self._t = int(now if now is not None else time.time())
        self.t0 = self.t
        self.wall_offset: int | None = 0
        self.enroll = enroll
        self.net_down = False
        self.drop_after_send = 0
        self.date_header = True
        self.shown: list[tuple[str, list[str]]] = []
        self.requests: list[tuple[str, str]] = []
        self.wifi: tuple[str, str] | None = None
        self.wifi_ok = True
        self.writes = 0

    # time
    @property
    def t(self) -> int:
        if self.clock is not None:
            return int(self.clock.utcnow().timestamp())
        return self._t

    def ticks_s(self) -> int:
        return self.t - self.t0

    def wall(self):
        return None if self.wall_offset is None else self.t + self.wall_offset

    def advance(self, seconds: int) -> None:
        if self.clock is not None:
            raise AssertionError("advance the FakeClock instead")
        self._t += int(seconds)

    def feed(self) -> None:
        pass

    # files
    def read(self, name):
        return self.files.get(name)

    def write(self, name, data):
        self.writes += 1
        self.files[name] = bytes(data)

    def remove(self, name):
        self.files.pop(name, None)

    # ui
    def show(self, title, lines=()):
        self.shown.append((title, list(lines)))

    def enroll_requested(self):
        held, self.enroll = self.enroll, False
        return held

    def wifi_connect(self, ssid=None, password=None, timeout_s=20):
        self.wifi = (ssid, password)
        return self.wifi_ok

    def save_wifi(self, ssid, password):
        self.write("wifi", ("%s\n%s" % (ssid, password)).encode())

    def ntp(self):
        return True

    # network
    def https(self, method, path, bearer, body):
        if self.net_down:
            raise ApiError("NETWORK", "down", sent=False)
        self.requests.append((method, path))
        headers = {"authorization": f"Bearer {bearer}"} if bearer else {}
        request = httpx.Request(method, "https://openrouter.ai" + path, headers=headers, content=body or b"")
        response = self.fake.handler(request)
        if self.drop_after_send:
            self.drop_after_send -= 1
            raise ApiError("NETWORK", "io: reset", sent=True)
        out = {k.lower(): v for k, v in response.headers.items()}
        if self.date_header:
            out["date"] = formatdate(self.t, usegmt=True)
        return response.status_code, out, response.content


class LoopTransport:
    """Host <-> firmware in one process: every written line is handled by the Device at once."""

    def __init__(self, device: Device) -> None:
        self.device = device
        self.replies: list[bytes] = []
        self.sent: list[bytes] = []
        self.unplugged = False
        self.closed = False
        self.tamper = None      # callable(bytes) -> bytes, applied to replies

    def write(self, data: bytes) -> None:
        if self.unplugged:
            raise BackendUnavailable("unplugged")
        self.sent.append(data)
        reply = self.device.handle(data)
        if self.tamper is not None:
            reply = self.tamper(reply)
        self.replies.append(reply)

    def readline(self, timeout: float) -> bytes:
        if self.unplugged or not self.replies:
            raise BackendUnavailable("the device did not answer in time")
        return self.replies.pop(0).rstrip(b"\n")

    def reset(self) -> None:
        self.replies.clear()

    def close(self) -> None:
        self.closed = True


def enroll(board: FakeBoard, *, policy: dict | None = None, workspace: str = FAKE_WORKSPACE,
           instance: str = FAKE_INSTANCE, key: str = FAKE_MGMT_KEY) -> tuple[Device, Pairing]:
    """Enroll a device the way the CLI does, and return it with the pairing the host would store."""
    from masqai.custody.device import open_field, seal_field
    board.enroll = True
    device = Device(board)
    client = DeviceClient(LoopTransport(device))
    info, code = client.enroll_begin()
    assert code == device.sas, "both ends must derive the same pairing code"
    result = client.call("ENROLL_SET", {"mk": seal_field(client.enc, key), "ws": workspace, "inst": instance,
                                        "exp": None, "pol": policy or {}})
    pairing = Pairing(result["id"], bytearray(open_field(client.enc, result["kmac"])),
                      bytearray(open_field(client.enc, result["us"])), workspace, instance,
                      check_policy(result["pol"]), None, "loop", "2026-10-18T00:00:00Z")
    return device, pairing
