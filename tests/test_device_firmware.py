"""Device firmware logic under CPython (design §13, build step 7): crypto, time, HTTP parsing, policy, journal and the
command state machine. The same modules run on the ESP32; the hardware adapter (hw.py) is bench-tested on the board.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import unittest

import tests.device_rig  # noqa: F401  (puts firmware/esp32 on sys.path)
from tests.device_rig import FakeBoard, LoopTransport, enroll
from enigma_dev import crypto, httpwire, policy as pol, proto, timeutil
from enigma_dev.core import ENROLL, LOCKED, UNLOCKED, UNPROVISIONED, Device
from enigma_dev.journal import Journal
from tests.helpers import FAKE_INSTANCE, FAKE_MGMT_KEY, FAKE_WORKSPACE, FakeOpenRouter

from masqai.custody.device import DeviceClient, seal_field


class Crypto(unittest.TestCase):
    def test_hmac_and_hkdf_match_the_standard_library(self):
        for size in (0, 1, 32, 64, 65, 200):
            key, data = os.urandom(size), os.urandom(size * 3)
            self.assertEqual(crypto.hmac_sha256(key, data), hmac.new(key, data, hashlib.sha256).digest())
        # RFC 5869 test case 1
        okm = crypto.hkdf(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                          bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_aes_ctr_matches_cryptography(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = os.urandom(32)
        for iv in (os.urandom(16), b"\xff" * 16):   # including counter wrap-around
            for size in (0, 1, 16, 17, 100):
                data = os.urandom(size)
                enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
                self.assertEqual(crypto.aes_ctr(key, iv, data), enc.update(data) + enc.finalize())

    def test_x25519_rfc7748_vectors_and_interop(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from enigma_dev import x25519
        scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(x25519.x25519(scalar, u).hex(), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        host = X25519PrivateKey.generate()
        host_pub = host.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        private, public = x25519.keypair()
        self.assertEqual(x25519.shared(private, host_pub), host.exchange(X25519PublicKey.from_public_bytes(public)))
        with self.assertRaises(crypto.CryptoError):
            x25519.shared(private, bytes(32))   # low-order point -> all-zero secret: refused

    def test_sealed_blobs_authenticate_and_bind_their_label(self):
        secret = os.urandom(32)
        blob = crypto.seal(secret, b"management key", b"mk")
        self.assertNotIn(b"management key", blob)
        self.assertEqual(crypto.open_sealed(secret, blob, b"mk"), b"management key")
        for bad in (os.urandom(32), None):
            with self.assertRaises(crypto.CryptoError):
                crypto.open_sealed(bad or secret, blob if bad else blob[:-1] + bytes([blob[-1] ^ 1]), b"mk")
        with self.assertRaises(crypto.CryptoError):
            crypto.open_sealed(secret, blob, b"other")
        flipped = bytearray(blob)
        flipped[10] ^= 1
        with self.assertRaises(crypto.CryptoError):
            crypto.open_sealed(secret, bytes(flipped), b"mk")

    def test_ct_equal(self):
        self.assertTrue(crypto.ct_equal(b"abc", b"abc"))
        self.assertFalse(crypto.ct_equal(b"abc", b"abd"))
        self.assertFalse(crypto.ct_equal(b"abc", b"ab"))


class Time(unittest.TestCase):
    def test_round_trip_against_the_standard_library(self):
        from datetime import datetime, timezone
        for when in (0, 951782400, 1709251199, 1792324800, 4102444800 - 1):
            dt = datetime.fromtimestamp(when, timezone.utc)
            self.assertEqual(timeutil.iso(when), dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
            self.assertEqual(timeutil.parse_iso(timeutil.iso(when)), when)
            from email.utils import formatdate
            self.assertEqual(timeutil.parse_http_date(formatdate(when, usegmt=True)), when)

    def test_malformed_times_are_refused(self):
        for bad in ("", "2026-02-30T00:00:00Z", "2026-10-18T25:00:00Z", "2026-10-18T12:00:00", "2026-10-18T12:00:00+02:00",
                    "2026-10-18 12:00:00Z", "2026-10-18T12:00:00.Z", None, 5):
            self.assertIsNone(timeutil.parse_iso(bad), bad)
        for bad in ("Sun, 18 Oct 2026 12:00:00 UTC", "18 Oct 2026 12:00:00 GMT", "Sun, 31 Feb 2026 12:00:00 GMT", ""):
            self.assertIsNone(timeutil.parse_http_date(bad), bad)
        self.assertEqual(timeutil.parse_iso("2026-10-18T12:00:00.123456Z"), timeutil.parse_iso("2026-10-18T12:00:00Z"))


class Stream:
    def __init__(self, data: bytes, step: int = 7) -> None:
        self.data, self.step = data, step

    def read(self, n):
        n = min(n, self.step)
        out, self.data = self.data[:n], self.data[n:]
        return out


class Http(unittest.TestCase):
    def test_content_length_chunked_and_close_bodies(self):
        cases = [b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nDate: x\r\n\r\nhelloEXTRA",
                 b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2;x=y\r\nlo\r\n0\r\n\r\n",
                 b"HTTP/1.0 200 OK\r\nServer: s\r\n\r\nhello"]
        for raw in cases:
            status, headers, body = httpwire.read_response(Stream(raw))
            self.assertIn(status, (200, 201))
            self.assertEqual(body, b"hello")
        self.assertEqual(httpwire.read_response(Stream(cases[0]))[1]["date"], "x")

    def test_oversized_responses_are_refused_not_buffered(self):
        big = b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\n" + b"x" * 9000
        with self.assertRaises(httpwire.HttpError) as caught:
            httpwire.read_response(Stream(big, 512), cap=8192)
        self.assertEqual(caught.exception.code, "RESP_TOO_LARGE")
        endless = b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 20000
        with self.assertRaises(httpwire.HttpError):
            httpwire.read_response(Stream(endless, 512), cap=8192)
        chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"1000\r\n" + b"x" * 4096 + b"\r\n" + b"1000\r\n" + b"x" * 4096 + b"\r\n" + b"10\r\n"
        with self.assertRaises(httpwire.HttpError):
            httpwire.read_response(Stream(chunked, 512), cap=8192)
        with self.assertRaises(httpwire.HttpError):
            httpwire.read_response(Stream(b"HTTP/1.1 200 OK\r\nX: " + b"a" * 9000 + b"\r\n\r\n", 512))

    def test_garbage_is_refused(self):
        for raw in (b"", b"SSH-2.0\r\n\r\n", b"HTTP/1.1 abc\r\n\r\n", b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"):
            with self.assertRaises(httpwire.HttpError):
                httpwire.read_response(Stream(raw))

    def test_request_shape(self):
        raw = httpwire.build_request("POST", "openrouter.ai", "/api/v1/keys", "sk-or-v1-FAKE", b"{}")
        self.assertTrue(raw.startswith(b"POST /api/v1/keys HTTP/1.1\r\nHost: openrouter.ai\r\n"))
        self.assertIn(b"Connection: close\r\n", raw)
        self.assertIn(b"Content-Length: 2\r\n\r\n{}", raw)


class LanDeployment(unittest.TestCase):
    def test_persistent_lan_entrypoint_uses_owner_marker_real_tls_and_watchdog(self):
        from pathlib import Path
        source = (Path(__file__).parents[1] / "firmware" / "esp32" / "lan_app.py").read_text()
        self.assertIn('"/enigma/lan_enroll"', source)
        self.assertIn('"/enigma/lan_enroll.bin"', source)
        self.assertIn('display.text(str(line)[:21]', source)
        self.assertIn('Board(wdt=True', source)
        self.assertIn('TcpLink(7777)', source)
        self.assertIn('serve(device, link, board, idle=_idle)', source)
        self.assertNotIn('bench_target.json', source)
        self.assertNotIn('20 * 60', source)


NOW = 1_800_000_000


def entry(created, expires=None, state="live", burst=0):
    return {"h": "a" * 64, "s": "x", "c": created, "x": expires if expires is not None else created + 1900, "st": state, "b": burst}


class Policy(unittest.TestCase):
    P = pol.build()

    def test_defaults_match_the_design(self):
        self.assertEqual(self.P, {"max_limit_c": 200, "max_ttl_s": 1900, "min_mint_gap_s": 240, "burst_max": 3,
                                  "burst_window_s": 600, "max_mints_per_day": 120, "max_live_keys": 4})

    def test_overrides_are_checked(self):
        self.assertEqual(pol.build({"max_limit_c": 300})["max_limit_c"], 300)
        for bad in ({"max_limit_c": 0}, {"max_limit_c": "200"}, {"max_ttl_s": True}, {"nope": 1}, {"max_live_keys": 1}):
            with self.assertRaises(pol.PolicyError):
                pol.build(bad)
        with self.assertRaises(pol.PolicyError):
            pol.check({**self.P, "extra": 1})
        with self.assertRaises(pol.PolicyError):
            pol.check({k: v for k, v in self.P.items() if k != "max_live_keys"})

    def test_caps_on_ttl_and_limit_are_refusals_not_clamps(self):
        self.assertEqual(pol.admit(self.P, [], NOW, 1900, 200), (1900, 0))
        for ttl, limit, code in ((1901, 200, "POLICY_TTL"), (1900, 201, "POLICY_LIMIT"), (59, 200, "BAD_ARGS"),
                                 (1900.0, 200, "BAD_ARGS"), (1900, 0, "BAD_ARGS"), (1900, True, "BAD_ARGS")):
            with self.assertRaises(pol.PolicyError) as caught:
                pol.admit(self.P, [], NOW, ttl, limit)
            self.assertEqual(caught.exception.code, code)

    def test_live_key_cap_counts_pending_and_failed_until_expiry(self):
        entries = [entry(NOW - 100 * i, expires=NOW + 100) for i in range(1, 4)] + [entry(NOW - 900, expires=NOW + 100, state="pending")]
        with self.assertRaises(pol.PolicyError) as caught:
            pol.admit(self.P, entries, NOW, 1900, 200)
        self.assertEqual(caught.exception.code, "LIVE_KEYS")
        entries[-1]["st"] = "revoked"
        pol.admit(self.P, entries, NOW, 1900, 200)
        entries[-1]["st"] = "failed"
        with self.assertRaises(pol.PolicyError):
            pol.admit(self.P, entries, NOW, 1900, 200)
        entries[-1]["x"] = NOW   # expired: no longer live
        pol.admit(self.P, entries, NOW, 1900, 200)

    def test_gap_and_burst(self):
        entries = [entry(NOW - 300, state="revoked")]
        self.assertEqual(pol.admit(self.P, entries, NOW, 1900, 200)[1], 0)      # normal rotation
        entries = [entry(NOW - 10, state="revoked")]
        self.assertEqual(pol.admit(self.P, entries, NOW, 1900, 200)[1], 1)      # early: uses the burst allowance
        entries = [entry(NOW - 100 + i, state="revoked", burst=1) for i in range(3)]   # 3 bursts, the last 98 s ago
        with self.assertRaises(pol.PolicyError) as caught:
            pol.admit(self.P, entries, NOW, 1900, 200)
        self.assertEqual(caught.exception.code, "RATE_GAP")
        entries = [entry(NOW - 601 + i, state="revoked", burst=1) for i in range(3)] + [entry(NOW - 250, state="revoked")]
        self.assertEqual(pol.admit(self.P, entries, NOW, 1900, 200)[1], 0)      # window passed

    def test_daily_cap(self):
        entries = [entry(NOW - 86000 + i * 700, state="revoked") for i in range(120)]
        with self.assertRaises(pol.PolicyError) as caught:
            pol.admit(self.P, entries, NOW, 1900, 200)
        self.assertEqual(caught.exception.code, "RATE_DAY")
        entries[0]["c"] = NOW - 86400   # older than a day: does not count
        pol.admit(self.P, entries, NOW, 1900, 200)


class JournalTests(unittest.TestCase):
    def test_persists_and_skips_torn_lines(self):
        board = FakeBoard()
        journal = Journal(board)
        e = journal.add("r-1", NOW, NOW + 1900, 0)
        journal.set(e, h="b" * 64, st="live")
        board.files["journal"] += b'["torn", "x", 1\n'
        again = Journal(board)
        self.assertEqual(len(again.entries), 1)
        self.assertEqual(again.entries[0]["h"], "b" * 64)
        self.assertNotIn(b"sk-", board.files["journal"])

    def test_prune_keeps_a_day_and_live_keys(self):
        board = FakeBoard()
        journal = Journal(board)
        journal.entries = [entry(NOW - 90000, state="revoked"), entry(NOW - 90000, expires=NOW + 10),
                           entry(NOW - 100, state="revoked")]
        journal.prune(NOW)
        self.assertEqual(len(journal.entries), 2)


# ---------------------------------------------------------------------------------------------------------------
# The command state machine
# ---------------------------------------------------------------------------------------------------------------

class Machine(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeOpenRouter()
        self.board = FakeBoard(self.fake)

    def session(self, device, pairing):
        client = DeviceClient(LoopTransport(device))
        client.hello(bytes(pairing.k_mac))
        return client

    def unlocked(self, **kw):
        device, pairing = enroll(self.board, **kw)
        client = self.session(device, pairing)
        client.call("UNLOCK", {"us": seal_field(client.enc, bytes(pairing.unlock_secret))})
        return device, pairing, client

    def test_unprovisioned_device_refuses_everything_but_hello(self):
        device = Device(self.board)
        self.assertEqual(device.state, UNPROVISIONED)
        client = DeviceClient(LoopTransport(device))
        info = client.hello(None)
        self.assertEqual(info["state"], UNPROVISIONED)
        self.assertNotIn("dn", info)
        reply = json.loads(device.handle(b'- {"n": 1, "op": "MINT", "a": {}}').split(b" ", 1)[1])
        self.assertEqual(reply["e"]["code"], "AUTH")

    def test_enrollment_needs_the_window(self):
        device = Device(self.board)    # no button
        client = DeviceClient(LoopTransport(device))
        with self.assertRaisesRegex(Exception, "no enrollment window"):
            client.enroll_begin()

    def test_enrollment_window_closes_after_120_s_and_after_one_enrollment(self):
        self.board.enroll = True
        device = Device(self.board)
        self.assertEqual(device.state, ENROLL)
        self.board.advance(121)
        self.assertEqual(device.state, UNPROVISIONED)
        device, pairing = enroll(self.board)
        self.assertEqual(device.state, LOCKED)
        with self.assertRaisesRegex(Exception, "no enrollment window"):
            DeviceClient(LoopTransport(device)).enroll_begin()

    def test_run_mode_does_not_keep_the_enrollment_code_loaded(self):
        import sys
        device, pairing = enroll(self.board)
        self.assertEqual(device.state, LOCKED)   # reading the state closes the window and unloads enroll/x25519
        self.assertNotIn("enigma_dev.enroll", sys.modules)
        self.assertNotIn("enigma_dev.x25519", sys.modules)
        import enigma_dev.crypto
        self.assertFalse(hasattr(enigma_dev.crypto, "x25519"))

    def test_enrollment_stores_only_ciphertext_and_needs_a_budgeted_workspace(self):
        device, pairing = enroll(self.board)
        flash = b"".join(self.board.files.values())
        self.assertNotIn(FAKE_MGMT_KEY.encode(), flash)
        self.assertNotIn(bytes(pairing.unlock_secret), flash)
        self.assertEqual(device.ident["kmac"], bytes(pairing.k_mac))
        for fake, code in ((FakeOpenRouter(budgets=0), "NO_BUDGET"),):
            with self.assertRaisesRegex(Exception, code):
                enroll(FakeBoard(fake))
        other = FakeOpenRouter()
        other.workspaces = set()
        with self.assertRaisesRegex(Exception, "NO_WORKSPACE"):
            enroll(FakeBoard(other))
        with self.assertRaisesRegex(Exception, "MGMT_AUTH"):
            enroll(FakeBoard(FakeOpenRouter()), key="sk-or-v1-FAKEFAKEFAKEnotmanagement")

    def test_enrollment_secrets_never_travel_in_plaintext(self):
        self.board.enroll = True
        device = Device(self.board)
        link = LoopTransport(device)
        client = DeviceClient(link)
        client.enroll_begin()
        result = client.call("ENROLL_SET", {"mk": seal_field(client.enc, FAKE_MGMT_KEY), "ws": FAKE_WORKSPACE,
                                            "inst": FAKE_INSTANCE, "exp": None, "pol": {}})
        wire = b"".join(link.sent) + b"".join(link.replies)
        self.assertNotIn(FAKE_MGMT_KEY.encode(), wire)
        stored = json.loads(self.board.files["dev"])
        self.assertNotIn(stored["kmac"].encode(), wire)             # k_mac and the unlock secret travel encrypted
        self.assertEqual(len(crypto.b64d(result["us"])), 16 + 32)

    def test_unlock_needs_the_right_secret_and_relocks_on_every_hello(self):
        device, pairing = enroll(self.board)
        client = self.session(device, pairing)
        with self.assertRaisesRegex(Exception, "UNLOCK_FAILED"):
            client.call("UNLOCK", {"us": seal_field(client.enc, os.urandom(32))})
        self.assertEqual(device.state, LOCKED)
        with self.assertRaisesRegex(Exception, "STATE"):
            client.call("MINT", {"s": "r-1", "ttl": 1900, "lim": 200})
        client.call("UNLOCK", {"us": seal_field(client.enc, bytes(pairing.unlock_secret))})
        self.assertEqual(device.state, UNLOCKED)
        self.assertIsNotNone(device.mk)
        client.hello(bytes(pairing.k_mac))   # a new session (e.g. another process on the port) relocks
        self.assertEqual(device.state, LOCKED)
        self.assertIsNone(device.mk)

    def test_frames_need_the_mac_and_a_rising_counter(self):
        device, pairing, client = self.unlocked()
        good = proto.frame(client._mac, proto.TAG_REQ, {"n": 100, "op": "STATUS", "a": {}})
        self.assertTrue(json.loads(device.handle(good).split(b" ", 1)[1])["ok"])
        replay = json.loads(device.handle(good).split(b" ", 1)[1])
        self.assertEqual(replay["e"]["code"], "REPLAY")
        forged = proto.frame(os.urandom(32), proto.TAG_REQ, {"n": 200, "op": "STATUS", "a": {}})
        self.assertEqual(json.loads(device.handle(forged).split(b" ", 1)[1])["e"]["code"], "AUTH")
        # a reply can't be reflected back as a request (different direction tag)
        reflected = proto.frame(client._mac, proto.TAG_REP, {"n": 300, "op": "STATUS", "a": {}})
        self.assertEqual(json.loads(device.handle(reflected).split(b" ", 1)[1])["e"]["code"], "AUTH")
        for junk in (b"", b"x" * 3000, b"nospace", b"- [1]", b"- {bad json"):
            self.assertIn(b'"ok": false', device.handle(junk))

    def test_mint_builds_the_name_and_expiry_on_the_device(self):
        device, pairing, client = self.unlocked()
        result = client.call("MINT", {"s": "ab12-1", "ttl": 1900, "lim": 200})
        record = self.fake.keys[result["h"]]
        self.assertEqual(record["name"], f"masqai-enigma-{FAKE_INSTANCE}-ab12-1")
        self.assertEqual(record["workspace_id"], FAKE_WORKSPACE)
        self.assertEqual(record["limit"], 2.0)
        self.assertEqual(timeutil.parse_iso(record["expires_at"]), self.board.t + 1900)   # OpenRouter's clock + ttl
        self.assertNotIn(record["_key"], json.dumps(result))     # the key travels encrypted
        for suffix in ("../x", "A", "", "x" * 33, "-x", None, 5):
            with self.assertRaisesRegex(Exception, "BAD_ARGS"):
                client.call("MINT", {"s": suffix, "ttl": 1900, "lim": 200})

    def test_the_host_clock_and_ntp_cannot_stretch_a_key(self):
        device, pairing, client = self.unlocked()
        self.board.wall_offset = 3600       # the RTC (NTP) is an hour off OpenRouter: refuse
        with self.assertRaisesRegex(Exception, "CLOCK_SKEW"):
            client.call("MINT", {"s": "r-1", "ttl": 1900, "lim": 200})
        self.board.wall_offset = None       # no NTP at all: OpenRouter's Date header is enough
        client.call("MINT", {"s": "r-2", "ttl": 1900, "lim": 200})
        self.board.date_header = False
        self.board.advance(4000)            # server clock stale and no Date header: no mint
        with self.assertRaisesRegex(Exception, "NO_SERVER_TIME|CLOCK"):
            device.api.server_time = None
            client.call("MINT", {"s": "r-3", "ttl": 1900, "lim": 200})

    def test_policy_is_enforced_by_the_device(self):
        device, pairing, client = self.unlocked()
        with self.assertRaisesRegex(Exception, "POLICY_LIMIT"):
            client.call("MINT", {"s": "r-1", "ttl": 1900, "lim": 201})
        with self.assertRaisesRegex(Exception, "POLICY_TTL"):
            client.call("MINT", {"s": "r-1", "ttl": 1901, "lim": 200})
        for i in range(4):                   # 1 normal + 3 burst
            client.call("MINT", {"s": f"r-{i}", "ttl": 1900, "lim": 200})
            self.board.advance(1)
        with self.assertRaisesRegex(Exception, "LIVE_KEYS|RATE_GAP"):
            client.call("MINT", {"s": "r-9", "ttl": 1900, "lim": 200})
        self.assertEqual(len(self.fake.keys), 4)

    def test_rate_limits_survive_a_reboot(self):
        device, pairing, client = self.unlocked()
        for i in range(4):
            client.call("MINT", {"s": f"r-{i}", "ttl": 1900, "lim": 200})
            h = [k for k in self.fake.keys][-1]
            client.call("REVOKE", {"h": h})
        rebooted = Device(self.board)   # power cycle: RAM gone, flash kept
        client = self.session(rebooted, pairing)
        client.call("UNLOCK", {"us": seal_field(client.enc, bytes(pairing.unlock_secret))})
        with self.assertRaisesRegex(Exception, "RATE_GAP"):
            client.call("MINT", {"s": "r-9", "ttl": 1900, "lim": 200})

    def test_revoke_scope_is_the_journal(self):
        device, pairing, client = self.unlocked()
        foreign = self.fake.add_key("user's own key")
        with self.assertRaisesRegex(Exception, "NOT_IN_JOURNAL"):
            client.call("REVOKE", {"h": foreign})
        with self.assertRaisesRegex(Exception, "NOT_IN_JOURNAL"):
            client.call("USAGE", {"h": foreign})
        self.assertIn(foreign, self.fake.keys)
        minted = client.call("MINT", {"s": "r-1", "ttl": 1900, "lim": 200})
        self.assertEqual(client.call("USAGE", {"h": minted["h"]})["u"], 0.0)
        self.assertEqual(client.call("REVOKE", {"h": minted["h"]})["outcome"], "deleted")
        self.assertEqual(client.call("REVOKE", {"h": minted["h"]})["outcome"], "already_gone")

    def test_revoke_falls_back_to_disable_then_marks_failed(self):
        device, pairing, client = self.unlocked()
        minted = client.call("MINT", {"s": "r-1", "ttl": 1900, "lim": 200})
        self.fake.fail[("DELETE", "/keys/")] = [500]
        self.assertEqual(client.call("REVOKE", {"h": minted["h"]})["outcome"], "disabled")
        self.board.advance(300)
        minted = client.call("MINT", {"s": "r-2", "ttl": 1900, "lim": 200})
        self.fake.fail[("DELETE", "/keys/")] = [500]
        self.fake.fail[("PATCH", "/keys/")] = [500]
        with self.assertRaisesRegex(Exception, "REVOKE_FAILED"):
            client.call("REVOKE", {"h": minted["h"]})
        self.assertEqual(device.journal.find(minted["h"])["st"], "failed")
        self.assertEqual(client.call("CLEANUP")["revoked"], 1)   # retried by cleanup

    def test_cleanup_revokes_every_open_journal_entry(self):
        device, pairing, client = self.unlocked()
        hashes = []
        for i in range(3):
            hashes.append(client.call("MINT", {"s": f"r-{i}", "ttl": 1900, "lim": 200})["h"])
            self.board.advance(300)
        foreign = self.fake.add_key(f"masqai-enigma-{FAKE_INSTANCE}-not-ours")
        self.assertEqual(client.call("CLEANUP"), {"revoked": 3, "failed": 0})
        self.assertEqual(set(self.fake.keys), {foreign})   # the device never lists or deletes other keys

    def test_a_mint_lost_in_flight_still_counts_as_live(self):
        device, pairing, client = self.unlocked()
        self.board.drop_after_send = 1
        with self.assertRaisesRegex(Exception, "NETWORK"):
            client.call("MINT", {"s": "r-1", "ttl": 1900, "lim": 200})
        pending = [e for e in device.journal.entries if e["st"] == "pending"]
        self.assertEqual(len(pending), 1)   # the key may exist: it counts against max_live_keys until it expires
        self.board.net_down = True
        with self.assertRaisesRegex(Exception, "NETWORK"):
            client.call("MINT", {"s": "r-2", "ttl": 1900, "lim": 200})
        self.assertEqual(len(device.journal.entries), 1)   # never sent: no entry kept

    def test_a_mismatched_grant_is_revoked_and_not_returned(self):
        device, pairing, client = self.unlocked()
        self.fake.mangle_create = lambda record: record.update(limit=50.0)
        with self.assertRaisesRegex(Exception, "MINT_MISMATCH"):
            client.call("MINT", {"s": "r-1", "ttl": 1900, "lim": 200})
        self.assertEqual(self.fake.keys, {})

    def test_check_reports_the_management_key_and_budget(self):
        device, pairing, client = self.unlocked()
        self.assertTrue(client.call("CHECK")["healthy"])
        self.fake.budgets = []
        self.assertFalse(client.call("CHECK")["healthy"])
        self.fake.management_key = "sk-or-v1-FAKEFAKEFAKErotated"
        with self.assertRaisesRegex(Exception, "MGMT_AUTH"):
            client.call("MINT", {"s": "r-1", "ttl": 1900, "lim": 200})

    def test_status_and_errors_never_carry_secrets(self):
        device, pairing, client = self.unlocked()
        minted = client.call("MINT", {"s": "r-1", "ttl": 1900, "lim": 200})
        key = self.fake.keys[minted["h"]]["_key"]
        status = json.dumps(client.call("STATUS"))
        for secret in (FAKE_MGMT_KEY, key, crypto.b64e(bytes(pairing.k_mac)), crypto.b64e(bytes(pairing.unlock_secret))):
            self.assertNotIn(secret, status)
        shown = json.dumps(self.board.shown)
        self.assertNotIn(FAKE_MGMT_KEY, shown)
        self.assertNotIn(key, shown)

    def test_unknown_operations_do_not_exist(self):
        device, pairing, client = self.unlocked()
        for op in ("READ_FILE", "EVAL", "GET_KEY", "DUMP", "ENROLL_SET", "ENROLL_ERASE", "UPDATE"):
            with self.assertRaisesRegex(Exception, "BAD_OP|STATE"):
                client.call(op, {"path": "/enigma/mk.bin"})

    def test_lock_wipes_the_key(self):
        device, pairing, client = self.unlocked()
        buffer = device.mk
        client.call("LOCK")
        self.assertEqual(device.state, LOCKED)
        self.assertFalse(any(buffer))

    def test_erase_needs_the_window_and_removes_every_secret(self):
        device, pairing = enroll(self.board)
        self.board.files["wifi"] = b"ssid\npw"
        self.board.enroll = True
        device = Device(self.board)
        client = DeviceClient(LoopTransport(device))
        client.enroll_begin()
        client.call("ENROLL_ERASE")
        self.assertEqual(self.board.files, {})
        self.assertEqual(device.state, UNPROVISIONED)

    def test_a_bug_in_a_handler_does_not_crash_the_loop(self):
        device, pairing, client = self.unlocked()
        device._status = lambda: 1 / 0
        with self.assertRaisesRegex(Exception, "INTERNAL") as caught:
            client.call("STATUS")
        self.assertIn("ZeroDivisionError", str(caught.exception))
        self.assertNotIn("division", str(caught.exception))      # the type only, never the message (it may hold values)
        self.assertEqual(client.call("LOCK")["state"], LOCKED)

    def test_unlock_refuses_a_secret_of_the_wrong_length(self):
        device, pairing = enroll(self.board)
        client = self.session(device, pairing)
        for secret in (bytes(pairing.unlock_secret)[:31], bytes(pairing.unlock_secret) + b"x", b""):
            with self.subTest(size=len(secret)):
                with self.assertRaisesRegex(Exception, "UNLOCK_FAILED"):
                    client.call("UNLOCK", {"us": seal_field(client.enc, secret) if secret else ""})
        self.assertEqual(device.state, LOCKED)

    def test_enrollment_refuses_a_key_openrouter_says_is_not_a_management_key(self):
        fake = FakeOpenRouter()
        real = fake._whoami

        def inference_key(bearer):
            response = real(bearer)
            if bearer == fake.management_key:
                import httpx
                return httpx.Response(200, json={"data": {"label": "x", "is_management_key": False}})
            return response
        fake._whoami = inference_key
        board = FakeBoard(fake)
        with self.assertRaisesRegex(Exception, "NOT_MANAGEMENT_KEY"):
            enroll(board)
        self.assertNotIn("mk", board.files)

    def test_sealed_blobs_are_bound_to_their_label(self):
        secret = os.urandom(32)
        blob = crypto.seal(secret, b"payload", b"mk")
        self.assertTrue(blob.startswith(b"mk|"))
        # A blob opened under another label must fail on the label itself, before any key derivation could matter:
        # same length label, and a forged tag computed with the other label's keys.
        keys = crypto.hkdf(secret, b"", b"masqai-enigma-at-rest-v1:jr", 64)
        body = blob[:-32]
        forged = body + crypto.hmac_sha256(keys[32:], body)
        with self.assertRaises(crypto.CryptoError):
            crypto.open_sealed(secret, forged, b"jr")

    def test_oversized_frames_are_refused(self):
        device, pairing, client = self.unlocked()
        big = proto.frame(client._mac, proto.TAG_REQ, {"n": 999, "op": "STATUS", "a": {"pad": "x" * 2100}})
        self.assertGreater(len(big), proto.MAX_LINE)
        reply = json.loads(device.handle(big).split(b" ", 1)[1])
        self.assertEqual(reply["e"]["code"], "BAD_FRAME")


if __name__ == "__main__":
    unittest.main()
