"""Device custody, host side (design §13, build step 8): DeviceBackend, the pairing file, the CLI and gateway startup,
run against the real firmware logic on a fake board (tests/device_rig.py) and the in-memory FakeOpenRouter.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import socket
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import run_gateway
from masqai.config import load_config
from masqai.custody import (BackendUnavailable, CustodyError, ManagementAuthError, ManagementBackend, RateLimited,
                            load_backend)
from masqai.custody import device as D
from masqai.enigma import EnigmaKeySource, build_keyring
from tests.device_rig import FakeBoard, LoopTransport, enroll
from tests.helpers import FAKE_INSTANCE, FAKE_MGMT_KEY, FAKE_WORKSPACE, FakeOpenRouter
from tests.test_rotation import POLICY, FakeClock, Fixed
from tests.test_vault import or_provider


def soon(seconds: int = 1900) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


class Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.fake = FakeOpenRouter()
        self.board = FakeBoard(self.fake)
        self.device, self.pairing = enroll(self.board)
        self.link = LoopTransport(self.device)
        self.backend = D.DeviceBackend(self.pairing, self.link, workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE)
        self.backend._connect()

    async def asyncTearDown(self) -> None:
        await self.backend.aclose()


class Backend(Base):
    def test_it_is_a_management_backend_without_the_management_key(self):
        self.assertIsInstance(self.backend, ManagementBackend)
        self.assertEqual(self.backend.mode, "device")
        self.assertEqual(self.backend.known_secrets(), [])
        self.assertNotIn(FAKE_MGMT_KEY.encode(), b"".join(self.link.sent) + b"".join(self.link.replies))

    async def test_mint_revoke_usage(self):
        minted = await self.backend.mint(suffix="ab12-1", expires_at=soon(), limit_usd=2.0)
        self.assertEqual(minted.name, f"masqai-enigma-{FAKE_INSTANCE}-ab12-1")
        self.assertEqual(minted.limit_usd, 2.0)
        self.assertEqual(minted.key, self.fake.keys[minted.hash]["_key"])
        self.assertLessEqual(minted.expires_at, soon(1901))
        self.assertNotIn(minted.key.encode(), b"".join(self.link.replies))   # encrypted on the wire
        self.assertEqual(await self.backend.usage(minted.hash), 0.0)
        self.assertEqual(await self.backend.revoke(minted.hash), "deleted")
        self.assertEqual(await self.backend.revoke(minted.hash), "already_gone")

    async def test_the_device_refuses_what_its_policy_forbids(self):
        with self.assertRaisesRegex(CustodyError, "POLICY_LIMIT"):
            await self.backend.mint(suffix="r-1", expires_at=soon(), limit_usd=2.01)
        with self.assertRaisesRegex(CustodyError, "POLICY_TTL"):
            await self.backend.mint(suffix="r-1", expires_at=soon(4000), limit_usd=2.0)
        for i in range(4):
            await self.backend.mint(suffix=f"r-{i}", expires_at=soon(), limit_usd=1.0)
        with self.assertRaises(RateLimited):
            await self.backend.mint(suffix="r-9", expires_at=soon(), limit_usd=1.0)

    async def test_foreign_keys_are_out_of_reach(self):
        foreign = self.fake.add_key("someone else's key")
        with self.assertRaisesRegex(CustodyError, "NOT_IN_JOURNAL"):
            await self.backend.revoke(foreign)
        self.assertIn(foreign, self.fake.keys)

    async def test_status_cleanup_and_policy_check(self):
        status = await self.backend.status()
        self.assertTrue(status.healthy, status.detail)
        self.assertEqual((status.max_limit_usd, status.max_ttl_seconds), (2.0, 1900))
        self.fake.budgets = []
        self.assertFalse((await self.backend.status()).healthy)
        self.fake.budgets = [{"id": "b"}]
        await self.backend.mint(suffix="r-1", expires_at=soon(), limit_usd=1.0)
        self.assertEqual(await self.backend.cleanup(), 1)
        self.assertEqual(self.fake.keys, {})
        self.backend.check_rotation(ttl_seconds=POLICY.ttl_seconds, per_key_limit_usd=2.0)
        with self.assertRaisesRegex(CustodyError, "caps them at 1900"):
            self.backend.check_rotation(ttl_seconds=1901, per_key_limit_usd=2.0)
        with self.assertRaisesRegex(CustodyError, "device cap"):
            self.backend.check_rotation(ttl_seconds=1900, per_key_limit_usd=2.5)

    async def test_a_device_reboot_is_survived_by_authenticating_again(self):
        await self.backend.mint(suffix="r-1", expires_at=soon(), limit_usd=1.0)
        from enigma_dev.core import Device
        self.link.device = Device(self.board)       # power cycle: back to LOCKED, no session
        self.board.advance(300)
        minted = await self.backend.mint(suffix="r-2", expires_at=soon(), limit_usd=1.0)
        self.assertIn(minted.hash, self.fake.keys)

    async def test_an_unplugged_device_is_unavailable_not_fatal(self):
        self.link.unplugged = True
        with self.assertRaises(BackendUnavailable):
            await self.backend.mint(suffix="r-1", expires_at=soon(), limit_usd=1.0)
        self.assertFalse((await self.backend.status()).healthy)
        self.link.unplugged = False
        await self.backend.mint(suffix="r-1", expires_at=soon(), limit_usd=1.0)

    async def test_a_tampered_reply_is_refused(self):
        def flip(reply: bytes) -> bytes:
            mac, payload = reply.split(b" ", 1)
            return mac + b" " + payload.replace(b'"n": ', b'"n":  ', 1)   # one changed byte, same meaning
        self.link.tamper = flip
        with self.assertRaisesRegex(CustodyError, "does not authenticate"):
            await self.backend.usage("a" * 64)

    def forge(self, change):
        """A reply re-MACed with the session key (what a buggy or compromised device firmware could send)."""
        def tamper(reply: bytes) -> bytes:
            mac, payload = reply.split(b" ", 1)
            if mac == b"-":
                return reply
            body = change(json.loads(payload))
            return D.frame(self.backend.client._mac, D.TAG_REP, body).rstrip(b"\n")
        return tamper

    async def test_a_reply_for_another_request_is_refused(self):
        self.link.tamper = self.forge(lambda body: {**body, "n": body["n"] + 1})
        with self.assertRaisesRegex(CustodyError, "another request"):
            await self.backend.usage("a" * 64)

    async def test_a_key_under_an_unexpected_name_or_limit_is_refused(self):
        def rename(body):
            if body.get("ok") and "name" in body.get("r", {}):
                body["r"]["name"] = "someone-else"
            return body
        self.link.tamper = self.forge(rename)
        with self.assertRaisesRegex(CustodyError, "unexpected name"):
            await self.backend.mint(suffix="r-1", expires_at=soon(), limit_usd=1.0)
        self.board.advance(300)

        def overlimit(body):
            if body.get("ok") and "lim" in body.get("r", {}):
                body["r"]["lim"] = 101
            return body
        self.link.tamper = self.forge(overlimit)
        with self.assertRaisesRegex(CustodyError, "valid expiry or limit"):
            await self.backend.mint(suffix="r-2", expires_at=soon(), limit_usd=1.0)

    def test_another_enrolled_device_on_the_port_is_refused(self):
        # Same pairing secret but a different id (a cloned pairing file pointing at another board) is refused.
        twin = D.Pairing("esp32-00000000", bytearray(self.pairing.k_mac), bytearray(self.pairing.unlock_secret),
                         self.pairing.workspace_id, self.pairing.instance_id, self.pairing.policy, None, "loop",
                         "2026-10-18T00:00:00Z")
        with self.assertRaisesRegex(CustodyError, "not esp32-00000000"):
            D.DeviceBackend(twin, self.link, workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE)._connect()

    async def test_a_refused_management_key_is_an_auth_error(self):
        self.fake.management_key = "sk-or-v1-FAKEFAKEFAKErevoked"
        with self.assertRaises(ManagementAuthError):
            await self.backend.mint(suffix="r-1", expires_at=soon(), limit_usd=1.0)

    async def test_close_locks_the_device_and_wipes_the_pairing(self):
        await self.backend.aclose()
        self.assertIsNone(self.device.mk)
        self.assertEqual(bytes(self.pairing.k_mac), b"")
        self.assertTrue(self.link.closed)
        with self.assertRaises(ManagementAuthError):
            await self.backend.mint(suffix="r-1", expires_at=soon(), limit_usd=1.0)

    def test_wrong_pairing_or_device_is_refused(self):
        other_board = FakeBoard(self.fake)
        other_device, other_pairing = enroll(other_board)
        link = LoopTransport(other_device)
        with self.assertRaisesRegex(CustodyError, "does not authenticate"):
            D.DeviceBackend(self.pairing, link, workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE)._connect()
        with self.assertRaisesRegex(CustodyError, "different workspace"):
            D.DeviceBackend(self.pairing, link, workspace_id="11111111-2222-3333-4444-555555555555", instance_id=FAKE_INSTANCE)
        with self.assertRaisesRegex(CustodyError, "different instance"):
            D.DeviceBackend(self.pairing, link, workspace_id=FAKE_WORKSPACE, instance_id="00000000")


class Rotation(unittest.IsolatedAsyncioTestCase):
    """The rotation state machine on DeviceBackend, end to end."""

    async def test_rotation_through_the_device(self):
        fake = FakeOpenRouter()
        clock = FakeClock()
        board = FakeBoard(fake, clock=clock)
        device, pairing = enroll(board)
        fake.add_key(f"masqai-enigma-{FAKE_INSTANCE}-leftover")   # not in the journal: never touched
        backend = D.DeviceBackend(pairing, LoopTransport(device), workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE,
                                  utcnow=clock.utcnow)

        async def inline(op, args=None):    # the fake clock can't wait for worker threads: run device calls inline
            return backend._call_sync(op, args)
        backend._call = inline

        async def probe(key: str) -> bool:
            return any(r["_key"] == key for r in fake.keys.values())
        source = EnigmaKeySource("openrouter", backend, POLICY, clock=clock, probe=probe, rng=Fixed(), owns_backend=True)
        await asyncio.wait_for(source.start(), 5)
        first = source.lease()
        first.release()
        await clock.advance(900)
        with source.lease() as second:
            self.assertNotEqual(first.key, second)
        await clock.advance(700)
        self.assertNotIn(first.key, [r["_key"] for r in fake.keys.values()])
        snap = source.snapshot()
        self.assertEqual(snap["custody"], "device")
        await source.stop()
        self.assertEqual(len(fake.keys), 1)                                   # only the foreign leftover
        self.assertIsNone(device.mk)                                          # locked at shutdown


class Pairing(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))

    def test_round_trip_and_strict_parsing(self):
        _, pairing = enroll(FakeBoard())
        path = self.dir / "p.pair"
        D.write_pairing(path, pairing)
        again = D.read_pairing(path)
        self.assertEqual((bytes(again.k_mac), bytes(again.unlock_secret), again.device_id),
                         (bytes(pairing.k_mac), bytes(pairing.unlock_secret), pairing.device_id))
        self.assertNotIn("kmac", repr(again))
        raw = json.loads(path.read_text())
        for change in ({"extra": 1}, {"v": 2}, {"id": "../etc"}, {"kmac": "AAAA"}, {"ws": "x"}, {"pol": {}}):
            with self.subTest(change=change):
                with self.assertRaises(CustodyError):
                    D.parse_pairing(json.dumps({**raw, **change}).encode())
        with self.assertRaisesRegex(CustodyError, "enroll"):
            D.read_pairing(self.dir / "missing.pair")

    def test_load_backend_opens_device_mode(self):
        fake = FakeOpenRouter()
        device, pairing = enroll(FakeBoard(fake))
        path = self.dir / "p.pair"
        D.write_pairing(path, pairing)
        custody = {"mode": "device", "serial_port": "COM9", "device_id": pairing.device_id, "pairing_file": str(path)}
        backend = load_backend(custody, workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE, transport=LoopTransport(device))
        self.assertEqual(backend.mode, "device")
        self.assertEqual(device.state, "UNLOCKED")
        asyncio.run(backend.aclose())
        with self.assertRaisesRegex(CustodyError, "pairs"):
            load_backend({**custody, "device_id": "esp32-00000000"}, workspace_id=FAKE_WORKSPACE, instance_id=FAKE_INSTANCE,
                         transport=LoopTransport(device))


class Scripted:
    def __init__(self, secrets: list[str], answers: list[str]) -> None:
        self.secrets, self.answers, self.said = list(secrets), list(answers), []

    def console(self) -> D.Console:
        return D.Console(secret=lambda p: self.secrets.pop(0), ask=lambda p: self.answers.pop(0), say=self.said.append)


class Cli(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
        self.fake = FakeOpenRouter()
        self.board = FakeBoard(self.fake, enroll=True)
        from enigma_dev.core import Device
        self.device = Device(self.board)

    def run_cli(self, argv, script):
        return D.main(argv, script.console(), transport=LoopTransport(self.device))

    def test_enroll_writes_the_pairing_and_prints_the_checklist(self):
        out = self.dir / "dev.pair"
        script = Scripted([FAKE_MGMT_KEY, "wifi-password-FAKE"],
                          ["yes", FAKE_WORKSPACE, FAKE_INSTANCE, "", "bench-ssid", "max_limit_c=150"])
        self.assertEqual(self.run_cli(["enroll", "--port", "COM9", "--pairing-file", str(out)], script), 0, script.said)
        pairing = D.read_pairing(out)
        self.assertEqual(pairing.policy["max_limit_c"], 150)
        self.assertEqual(self.board.wifi, ("bench-ssid", "wifi-password-FAKE"))
        said = "\n".join(script.said)
        self.assertIn("DTR and RTS are NOT connected", said)
        self.assertIn(pairing.device_id, said)
        for secret in (FAKE_MGMT_KEY, "wifi-password-FAKE"):
            self.assertNotIn(secret, said)
            self.assertNotIn(secret, out.read_text())

    def test_enroll_stops_when_the_codes_differ(self):
        script = Scripted([FAKE_MGMT_KEY], ["no"])
        self.assertEqual(self.run_cli(["enroll", "--port", "COM9", "--pairing-file", str(self.dir / "p")], script), 1)
        self.assertIn("codes differ", script.said[-1])
        self.assertEqual(script.secrets, [FAKE_MGMT_KEY])          # the key was never asked for
        self.assertNotIn("mk", self.board.files)

    def test_enroll_refuses_a_non_management_key(self):
        script = Scripted(["sk-or-v1-FAKEFAKEFAKEinference"], ["yes", FAKE_WORKSPACE, FAKE_INSTANCE, "", "", ""])
        self.assertEqual(self.run_cli(["enroll", "--port", "COM9", "--pairing-file", str(self.dir / "p")], script), 1)
        self.assertIn("MGMT_AUTH", script.said[-1])
        self.assertFalse((self.dir / "p").exists())

    def test_status_and_unpair(self):
        out = self.dir / "dev.pair"
        self.run_cli(["enroll", "--port", "COM9", "--pairing-file", str(out)],
                     Scripted([FAKE_MGMT_KEY], ["yes", FAKE_WORKSPACE, FAKE_INSTANCE, "", "", ""]))
        script = Scripted([], [])
        self.assertEqual(self.run_cli(["status", "--port", "COM9", "--pairing-file", str(out)], script), 0, script.said)
        self.assertIn("LOCKED", script.said[0])
        # unpair needs a new button window
        script = Scripted([], ["yes", "erase"])
        self.assertEqual(self.run_cli(["unpair", "--port", "COM9", "--pairing-file", str(out)], script), 1)
        self.assertIn("no enrollment window", script.said[-1])
        self.board.enroll = True
        from enigma_dev.core import Device
        self.device = Device(self.board)
        script = Scripted([], ["yes", "erase"])
        self.assertEqual(self.run_cli(["unpair", "--port", "COM9", "--pairing-file", str(out)], script), 0, script.said)
        self.assertEqual(self.board.files, {})
        self.assertFalse(out.exists())

    def test_lan_transport_warns_about_the_network_boundary(self):
        script = Scripted([], [])
        with patch.object(D, "open_transport", lambda spec: LoopTransport(self.device)):
            D.main(["status", "--port", "tcp://127.0.0.1:7777"], script.console())
        self.assertIn("LAN transport", script.said[0])
        self.assertIn("trusted", script.said[0])


class Transports(unittest.TestCase):
    def test_tcp_transport_round_trip_and_timeouts(self):
        server = socket.create_server(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def serve():
            conn, _ = server.accept()
            with conn:
                data = conn.recv(100)
                conn.sendall(data.upper())
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        link = D.open_transport(f"tcp://127.0.0.1:{port}")
        link.write(b"hello\n")
        self.assertEqual(link.readline(5), b"HELLO")
        with self.assertRaises(BackendUnavailable):
            link.readline(0.3)
        link.close()
        server.close()
        with self.assertRaises(CustodyError):
            D.open_transport("tcp://nohost")

    def test_serial_transport_never_asserts_dtr_or_rts(self):
        import serial
        opened = {}

        class FakeSerial:
            def __init__(self):
                self.dtr = self.rts = True
                self.in_waiting = 0

            def open(self):
                opened.update(dtr=self.dtr, rts=self.rts)
        with patch.object(serial, "Serial", FakeSerial):
            D.SerialTransport("COM9")
        self.assertEqual(opened, {"dtr": False, "rts": False})


class Startup(unittest.TestCase):
    def test_run_gateway_opens_the_device_and_rejects_a_config_beyond_its_policy(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        fake = FakeOpenRouter()
        device, pairing = enroll(FakeBoard(fake))
        path = tmp / "p.pair"
        D.write_pairing(path, pairing)
        custody = {"mode": "device", "serial_port": "COM9", "device_id": pairing.device_id, "pairing_file": str(path)}
        for limit, code in ((2.0, 0), (5.0, 2)):
            with self.subTest(limit=limit):
                config_path = tmp / "masqai.json"
                config_path.write_text(json.dumps({"providers": [or_provider(custody=custody, per_key_limit_usd=limit)],
                                                   "default_route": {"provider": "openrouter"}}))
                started = []
                real = run_gateway.load_backend
                with patch.object(run_gateway, "load_backend",
                                  lambda *a, **kw: real(*a, **{**kw, "transport": LoopTransport(device)})), \
                        patch.object(run_gateway.uvicorn, "run", lambda app, **kw: started.append(kw)), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(run_gateway.main(["--config", str(config_path)]), code)
                if code:
                    self.assertIn("device cap", err.getvalue())
                    self.assertEqual(started, [])
                    self.assertIsNone(device.mk)          # the backend was closed: the device relocked
                else:
                    self.assertEqual(started[0]["workers"], 1)

    def test_config_requires_a_device_id_shape(self):
        from masqai.config import CustodyConfig
        with self.assertRaisesRegex(Exception, "esp32-"):
            CustodyConfig.model_validate({"mode": "device", "serial_port": "COM5", "device_id": "board-1"})


if __name__ == "__main__":
    unittest.main()
