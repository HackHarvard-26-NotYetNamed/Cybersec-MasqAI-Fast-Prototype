"""Device custody (design: KeyEnigma.OpenRouter.doc.md §3.2, §13): the management key stays on an ESP32.

The gateway holds a pairing file (`~/.masqai/device-<id>.pair`, owner-only) with the device's frame key `k_mac` and the
`unlock_secret` that decrypts the management key on the device. It never holds the management key. `DeviceBackend`
implements `ManagementBackend` over the line protocol (§13.4); the device enforces its own policy (§13.5) whatever the
host asks for.

Transports: `serial` (production: a 3-wire UART, §13.2) and `tcp` (BENCH ONLY, for a board without a USB-TTL
adapter). The serial port is opened without touching DTR/RTS.

CLI: python -m masqai.device enroll | status | unpair  (see `main`).
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from . import (BackendStatus, BackendUnavailable, CustodyError, KeyNotFound, ManagementAuthError, MintedKey,
               RateLimited, RevokeOutcome, WorkspaceUnbudgeted)
from .openrouter import INSTANCE_RE, NAME_PREFIX, SUFFIX_RE, UUID_RE, check_hash, parse_time

PROTO_VERSION = 1
MAX_LINE = 2048
TAG_HELLO, TAG_REQ, TAG_REP = b"H", b"Q", b"R"
SESSION_INFO = b"masqai-enigma-session-v1"
ENROLL_INFO = b"masqai-enigma-enroll-v1"
DEVICE_ID_RE = re.compile(r"esp32-[0-9a-f]{8}")
PAIR_FIELDS = frozenset({"v", "id", "kmac", "us", "ws", "inst", "pol", "exp", "transport", "created"})
COMMAND_TIMEOUT = 45.0          # REVOKE is two calls (DELETE, then PATCH) on a slow link; one handshake can take 15 s (§13.6)
POLICY_FIELDS = ("max_limit_c", "max_ttl_s", "min_mint_gap_s", "burst_max", "burst_window_s", "max_mints_per_day", "max_live_keys")

# Device error codes -> host exceptions (messages from the device are short and never carry secrets).
_AUTH = {"MGMT_AUTH", "NOT_MANAGEMENT_KEY", "UNLOCK_FAILED"}
_RATE = {"RATE_GAP", "RATE_DAY", "LIVE_KEYS", "RATE_LIMITED"}
_DOWN = {"NETWORK", "UPSTREAM", "BAD_RESPONSE", "RESP_TOO_LARGE", "NO_SERVER_TIME", "NO_MEMORY", "INTERNAL",
         "TLS_VERIFY_FAILED", "CLOCK_SKEW", "STATE", "NO_SESSION"}


class DeviceError(CustodyError):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"device: {code}" + (f": {message}" if message else ""))
        self.code = code


def default_pairing_path(device_id: str) -> Path:
    return Path.home() / ".masqai" / f"device-{device_id}.pair"


# ---------------------------------------------------------------------------------------------------------------
# Crypto helpers (the device implements the same in firmware/esp32/enigma_dev/crypto.py)
# ---------------------------------------------------------------------------------------------------------------

def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = _hmac(salt or bytes(32), ikm)
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = _hmac(prk, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


def _ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: Any) -> bytes:
    if not isinstance(text, str):
        raise DeviceError("BAD_REPLY", "expected base64")
    try:
        return base64.b64decode(text, validate=True)
    except ValueError:
        raise DeviceError("BAD_REPLY", "bad base64") from None


def seal_field(key: bytes, data: bytes | str) -> str:
    raw = data.encode() if isinstance(data, str) else data
    iv = secrets.token_bytes(16)
    return _b64(iv + _ctr(key, iv, raw))


def open_field(key: bytes, text: Any) -> bytes:
    raw = _unb64(text)
    if len(raw) < 17:
        raise DeviceError("BAD_REPLY", "encrypted field too short")
    return _ctr(key, raw[:16], raw[16:])


def sas_code(keys: bytes) -> str:
    d = hashlib.sha256(b"masqai-enigma-sas" + keys).digest()
    return "%06d" % ((d[0] << 16 | d[1] << 8 | d[2]) % 1000000)


def frame(key: bytes | None, tag: bytes, obj: dict[str, Any]) -> bytes:
    text = json.dumps(obj, separators=(",", ":")).encode()
    if key is None:
        return b"- " + text + b"\n"
    return _b64(_hmac(key, tag + text)).encode() + b" " + text + b"\n"


def parse_frame(line: bytes) -> tuple[bytes | None, bytes, dict[str, Any]]:
    line = line.strip()
    if not line or len(line) > MAX_LINE:
        raise DeviceError("BAD_REPLY", "empty or oversized frame")
    head, sep, text = line.partition(b" ")
    if not sep:
        raise DeviceError("BAD_REPLY", "frame has no payload")
    try:
        msg = json.loads(text)
    except ValueError:
        raise DeviceError("BAD_REPLY", "payload is not JSON") from None
    if not isinstance(msg, dict):
        raise DeviceError("BAD_REPLY", "payload is not an object")
    if head == b"-":
        return None, text, msg
    mac = _unb64(head.decode("ascii", "replace"))
    if len(mac) != 32:
        raise DeviceError("BAD_REPLY", "bad MAC length")
    return mac, text, msg


# ---------------------------------------------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------------------------------------------

class Transport(Protocol):
    def write(self, data: bytes) -> None: ...
    def readline(self, timeout: float) -> bytes: ...
    def reset(self) -> None: ...       # drop buffered input (and reconnect if the link is a connection)
    def close(self) -> None: ...


class SerialTransport:
    """The production link: a 3.3 V USB-TTL adapter wired TX/RX/GND only (§13.2). DTR/RTS are left deasserted and
    are never toggled, so even an adapter that has them wired cannot reset the board from here."""

    def __init__(self, port: str, baud: int = 115200) -> None:
        import serial
        ser = serial.Serial()
        ser.port, ser.baudrate, ser.timeout = port, baud, 0.2
        ser.dtr = False
        ser.rts = False
        try:
            ser.open()
        except serial.SerialException as exc:
            raise BackendUnavailable(f"cannot open {port}: {exc}") from None
        self.ser = ser
        self.buf = b""

    def write(self, data: bytes) -> None:
        self.ser.write(data)
        self.ser.flush()

    def readline(self, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buf:
            if time.monotonic() > deadline:
                raise BackendUnavailable("the device did not answer in time")
            chunk = self.ser.read(self.ser.in_waiting or 1)
            self.buf += chunk
            if len(self.buf) > MAX_LINE * 2:
                self.buf = b""
                raise DeviceError("BAD_REPLY", "oversized line from the device")
        line, _, self.buf = self.buf.partition(b"\n")
        return line

    def reset(self) -> None:
        self.buf = b""
        self.ser.reset_input_buffer()

    def close(self) -> None:
        self.ser.close()


class TcpTransport:
    """BENCH ONLY: the same frames over TCP to a board running the bench firmware (no USB-TTL adapter). Frames are
    still authenticated and secrets encrypted, but §13.2's "no radio path to the host" does not hold."""

    def __init__(self, host: str, port: int) -> None:
        self.addr = (host, port)
        self.sock: socket.socket | None = None
        self.buf = b""

    def _connect(self) -> socket.socket:
        if self.sock is None:
            try:
                self.sock = socket.create_connection(self.addr, timeout=10)
            except OSError as exc:
                raise BackendUnavailable(f"cannot reach the bench device at {self.addr[0]}:{self.addr[1]}: {type(exc).__name__}") from None
            self.buf = b""
        return self.sock

    def write(self, data: bytes) -> None:
        try:
            self._connect().sendall(data)
        except OSError:
            self.reset()
            raise BackendUnavailable("lost the connection to the bench device") from None

    def readline(self, timeout: float) -> bytes:
        sock = self._connect()
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buf:
            left = deadline - time.monotonic()
            if left <= 0:
                raise BackendUnavailable("the device did not answer in time")
            sock.settimeout(min(left, 1.0))
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                self.reset()
                raise BackendUnavailable("lost the connection to the bench device") from None
            if not chunk:
                self.reset()
                raise BackendUnavailable("the bench device closed the connection")
            self.buf += chunk
            if len(self.buf) > MAX_LINE * 2:
                self.reset()
                raise DeviceError("BAD_REPLY", "oversized line from the device")
        line, _, self.buf = self.buf.partition(b"\n")
        return line

    def reset(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.buf = b""

    def close(self) -> None:
        self.reset()


def open_transport(spec: str) -> Transport:
    """`COM5`, `/dev/ttyUSB0`, or `tcp://HOST:PORT` (bench only)."""
    if spec.startswith("tcp://"):
        host, _, port = spec[len("tcp://"):].rpartition(":")
        if not host or not port.isdigit():
            raise CustodyError("a bench transport looks like tcp://192.168.1.50:7777")
        return TcpTransport(host, int(port))
    return SerialTransport(spec)


# ---------------------------------------------------------------------------------------------------------------
# Pairing file
# ---------------------------------------------------------------------------------------------------------------

@dataclass
class Pairing:
    device_id: str
    k_mac: bytearray
    unlock_secret: bytearray
    workspace_id: str
    instance_id: str
    policy: dict[str, int]
    management_expires_at: datetime | None
    transport: str
    created: str

    def __repr__(self) -> str:
        return f"Pairing({self.device_id}, <secrets hidden>)"

    def wipe(self) -> None:
        for buf in (self.k_mac, self.unlock_secret):
            for i in range(len(buf)):
                buf[i] = 0
            buf.clear()

    def to_json(self) -> bytes:
        body = {"v": 1, "id": self.device_id, "kmac": _b64(bytes(self.k_mac)), "us": _b64(bytes(self.unlock_secret)),
                "ws": self.workspace_id, "inst": self.instance_id, "pol": self.policy,
                "exp": self.management_expires_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.management_expires_at else None,
                "transport": self.transport, "created": self.created}
        return (json.dumps(body, indent=1, sort_keys=True) + "\n").encode()


def check_policy(policy: Any) -> dict[str, int]:
    if not isinstance(policy, dict) or set(policy) != set(POLICY_FIELDS):
        raise DeviceError("BAD_REPLY", "the device policy is incomplete")
    for name in POLICY_FIELDS:
        value = policy[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise DeviceError("BAD_REPLY", f"the device policy field {name} is not a count")
    return dict(policy)


def parse_pairing(data: bytes) -> Pairing:
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CustodyError("the pairing file is not JSON") from None
    if not isinstance(raw, dict) or set(raw) != PAIR_FIELDS or raw["v"] != 1:
        raise CustodyError("the pairing file has the wrong fields or version")
    if not isinstance(raw["id"], str) or not DEVICE_ID_RE.fullmatch(raw["id"]):
        raise CustodyError("the pairing file has a malformed device id")
    if not isinstance(raw["ws"], str) or not UUID_RE.fullmatch(raw["ws"]) or not isinstance(raw["inst"], str) \
            or not INSTANCE_RE.fullmatch(raw["inst"]):
        raise CustodyError("the pairing file has a malformed workspace or instance id")
    try:
        k_mac, unlock = _unb64(raw["kmac"]), _unb64(raw["us"])
    except DeviceError:
        raise CustodyError("the pairing file has malformed secrets") from None
    if len(k_mac) != 32 or len(unlock) != 32:
        raise CustodyError("the pairing file secrets must be 32 bytes each")
    try:
        policy = check_policy(raw["pol"])
    except DeviceError:
        raise CustodyError("the pairing file policy is incomplete") from None
    return Pairing(raw["id"], bytearray(k_mac), bytearray(unlock), raw["ws"], raw["inst"], policy,
                   parse_time(raw["exp"]), str(raw["transport"]), str(raw["created"]))


def read_pairing(path: Path) -> Pairing:
    path = Path(path)
    if not path.is_file():
        raise CustodyError(f"no pairing file at {path}; enroll the device with: python -m masqai.device enroll")
    with open(path, "rb") as handle:
        return parse_pairing(handle.read(64 * 1024))


def write_pairing(path: Path, pairing: Pairing) -> list[str]:
    from .vault import write_atomic
    return write_atomic(Path(path), pairing.to_json())


# ---------------------------------------------------------------------------------------------------------------
# The client: sessions, counters, MACs
# ---------------------------------------------------------------------------------------------------------------

class DeviceClient:
    """Synchronous request/response over one transport. One command at a time (a lock), new session per HELLO."""

    def __init__(self, transport: Transport, *, timeout: float = COMMAND_TIMEOUT) -> None:
        self.transport = transport
        self.timeout = timeout
        self._lock = threading.Lock()
        self._mac: bytes | None = None
        self._enc: bytes | None = None
        self._n = 0
        self.info: dict[str, Any] = {}

    @property
    def enc(self) -> bytes:
        if self._enc is None:
            raise DeviceError("NO_SESSION", "no session with the device")
        return self._enc

    def _exchange(self, data: bytes) -> bytes:
        self.transport.write(data)
        return self.transport.readline(self.timeout)

    def _open(self, request: dict[str, Any], derive: Callable[[dict[str, Any]], bytes]) -> dict[str, Any]:
        """Send an unauthenticated opener (HELLO or ENROLL_BEGIN); the reply is checked with the derived keys."""
        self._mac = self._enc = None
        self._n = 0
        self.transport.reset()
        n = secrets.randbits(30) + 1      # the opener's counter is echoed: it links the reply to this request
        request = {"n": n, **request}
        mac, text, msg = parse_frame(self._exchange(frame(None, TAG_REQ, request)))
        if msg.get("n") != n:
            raise DeviceError("BAD_REPLY", "the device answered a different request")
        if not msg.get("ok"):
            error = msg.get("e") or {}
            raise _error(str(error.get("code", "ERROR")), str(error.get("msg", "")))
        result = msg.get("r") or {}
        if result.get("pv") != PROTO_VERSION:
            raise DeviceError("VERSION", f"the device speaks protocol {result.get('pv')!r}, this gateway {PROTO_VERSION}")
        keys = derive(result)
        if keys:
            if mac is None or not hmac.compare_digest(_hmac(keys[:32], TAG_HELLO + text), mac):
                raise DeviceError("AUTH", "the device's reply does not authenticate (wrong pairing, or not this device)")
            self._mac, self._enc = keys[:32], keys[32:]
        self.info = result
        return result

    def hello(self, k_mac: bytes | None) -> dict[str, Any]:
        host_nonce = secrets.token_bytes(16)

        def derive(result: dict[str, Any]) -> bytes:
            if k_mac is None or "dn" not in result:
                return b""
            dev_nonce = _unb64(result["dn"])
            if len(dev_nonce) != 16:
                raise DeviceError("BAD_REPLY", "bad device nonce")
            return hkdf(k_mac, host_nonce + dev_nonce, SESSION_INFO, 64)
        with self._lock:
            result = self._open({"op": "HELLO", "hn": _b64(host_nonce)}, derive)
        if k_mac is not None and self._mac is None:
            raise DeviceError("NOT_ENROLLED", f"the device is {result.get('state')}, not paired")
        return result

    def enroll_begin(self) -> tuple[dict[str, Any], str]:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        holder: dict[str, bytes] = {}

        def derive(result: dict[str, Any]) -> bytes:
            device_public = _unb64(result.get("dpk"))
            if len(device_public) != 32:
                raise DeviceError("BAD_REPLY", "bad device key")
            shared = private.exchange(X25519PublicKey.from_public_bytes(device_public))
            holder["keys"] = keys = hkdf(shared, public + device_public, ENROLL_INFO, 64)
            return keys
        with self._lock:
            result = self._open({"op": "ENROLL_BEGIN", "hpk": _b64(public)}, derive)
        return result, sas_code(holder["keys"])

    def call(self, op: str, args: dict[str, Any] | None = None, *, timeout: float | None = None) -> dict[str, Any]:
        with self._lock:
            if self._mac is None:
                raise DeviceError("NO_SESSION", "no session with the device")
            self._n += 1
            n = self._n
            request = frame(self._mac, TAG_REQ, {"n": n, "op": op, "a": args or {}})
            saved = self.timeout
            if timeout is not None:
                self.timeout = timeout
            try:
                line = self._exchange(request)
            except BaseException:
                self._mac = self._enc = None    # the link state is unknown: the next call starts a new session
                raise
            finally:
                self.timeout = saved
            mac, text, msg = parse_frame(line)
            if mac is None:
                # Unauthenticated error: the device lost our session (it rebooted) or rejected the frame.
                error = msg.get("e") or {}
                self._mac = self._enc = None
                raise _error(str(error.get("code", "ERROR")), str(error.get("msg", "")), session_lost=True)
            if not hmac.compare_digest(_hmac(self._mac, TAG_REP + text), mac):
                self._mac = self._enc = None
                raise DeviceError("AUTH", "a reply from the device does not authenticate")
            if msg.get("n") != n:
                self._mac = self._enc = None
                raise DeviceError("BAD_REPLY", "the reply is for another request")
        if not msg.get("ok"):
            error = msg.get("e") or {}
            raise _error(str(error.get("code", "ERROR")), str(error.get("msg", "")))
        result = msg.get("r")
        return result if isinstance(result, dict) else {}

    @property
    def connected(self) -> bool:
        return self._mac is not None

    def close(self) -> None:
        self._mac = self._enc = None
        self.transport.close()


class SessionLost(BackendUnavailable):
    pass


def _error(code: str, message: str, *, session_lost: bool = False) -> CustodyError:
    text = f"device: {code}" + (f": {message}" if message else "")
    if session_lost and code in ("NO_SESSION", "AUTH", "REPLAY"):
        return SessionLost(text)
    if code in _AUTH:
        return ManagementAuthError(text)
    if code == "NOT_FOUND":
        return KeyNotFound(text)
    if code in _RATE:
        return RateLimited(text, None)
    if code == "NO_BUDGET":
        return WorkspaceUnbudgeted(text)
    if code in _DOWN:
        return BackendUnavailable(text)
    error = DeviceError(code, message)
    return error


# ---------------------------------------------------------------------------------------------------------------
# The backend
# ---------------------------------------------------------------------------------------------------------------

class DeviceBackend:
    """`ManagementBackend` over the device protocol. Holds no management key: `known_secrets()` is empty, and the
    inference keys arrive encrypted under the session key."""

    mode = "device"

    def __init__(self, pairing: Pairing, transport: Transport, *, workspace_id: str, instance_id: str,
                 timeout: float = COMMAND_TIMEOUT, utcnow: Callable[[], datetime] | None = None) -> None:
        if pairing.workspace_id != workspace_id:
            raise CustodyError("the device was enrolled for a different workspace than key_enigma.workspace_id")
        if pairing.instance_id != instance_id:
            raise CustodyError("the device was enrolled for a different instance_id than key_enigma.instance_id")
        self.utcnow = utcnow or (lambda: datetime.now(timezone.utc))
        self.pairing = pairing
        self.client = DeviceClient(transport, timeout=timeout)
        self.prefix = f"{NAME_PREFIX}{instance_id}-"
        self.workspace_id = workspace_id
        self.policy: dict[str, int] = dict(pairing.policy)
        self.management_expires_at = pairing.management_expires_at
        self._closed = False

    def __repr__(self) -> str:
        return f"DeviceBackend({self.pairing.device_id}, {self.prefix}*)"

    def known_secrets(self) -> list[tuple[str, str]]:
        return []   # the management key never reaches the host

    # ---- session ----
    def _connect(self) -> None:
        if self._closed:
            raise ManagementAuthError("the device backend is closed")
        info = self.client.hello(bytes(self.pairing.k_mac))
        if info.get("id") != self.pairing.device_id:
            raise CustodyError(f"the device on this port is {info.get('id')!r}, not {self.pairing.device_id}")
        unlocked = self.client.call("UNLOCK", {"us": seal_field(self.client.enc, bytes(self.pairing.unlock_secret))})
        if unlocked.get("ws") != self.workspace_id or unlocked.get("inst") != self.pairing.instance_id:
            raise CustodyError("the device holds a different workspace or instance than this gateway's config")
        self.policy = check_policy(unlocked.get("pol"))
        if unlocked.get("exp"):
            self.management_expires_at = parse_time(unlocked["exp"]) or self.management_expires_at

    def _call_sync(self, op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        for attempt in range(2):
            if not self.client.connected:
                self._connect()
            try:
                return self.client.call(op, args)
            except SessionLost:
                if attempt:
                    raise
            # The device rebooted (back to LOCKED) or our session was dropped: authenticate again once.
        raise BackendUnavailable("device session lost")

    async def _call(self, op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        return await asyncio.to_thread(self._call_sync, op, args)

    # ---- ManagementBackend ----
    async def mint(self, *, suffix: str, expires_at: datetime, limit_usd: float) -> MintedKey:
        if not isinstance(suffix, str) or not SUFFIX_RE.fullmatch(suffix):
            raise CustodyError("key name suffix must be 1-32 of [a-z0-9-]")
        if not (isinstance(limit_usd, (int, float)) and math.isfinite(limit_usd) and limit_usd > 0):
            raise CustodyError("limit_usd must be a positive number")
        # The host only says how long; the device anchors it to OpenRouter's clock and never trusts ours (§13.5).
        ttl = math.floor((expires_at - self.utcnow()).total_seconds())
        if ttl <= 0:
            raise CustodyError("expires_at must be in the future")
        cents = math.floor(limit_usd * 100 + 1e-9)
        if cents < 1:
            raise CustodyError("limit_usd must be at least $0.01")
        result = await self._call("MINT", {"s": suffix, "ttl": ttl, "lim": cents})
        key_hash = check_hash(result.get("h"))
        name = result.get("name")
        if name != self.prefix + suffix:
            raise CustodyError("the device minted a key under an unexpected name")
        granted = parse_time(result.get("x"))
        lim = result.get("lim")
        if granted is None or not isinstance(lim, int) or lim > cents:
            raise CustodyError("the device returned a key without a valid expiry or limit")
        key = open_field(self.client.enc, result.get("k")).decode("utf-8", "replace")
        if not key.startswith("sk-"):
            raise CustodyError("the device returned a malformed key")
        return MintedKey(key=key, hash=key_hash, name=name, expires_at=granted, limit_usd=lim / 100)

    async def revoke(self, key_hash: str) -> RevokeOutcome:
        check_hash(key_hash)
        result = await self._call("REVOKE", {"h": key_hash})
        outcome = result.get("outcome")
        if outcome not in ("deleted", "disabled", "already_gone"):
            raise CustodyError("the device reported an unknown revoke outcome")
        return outcome

    async def usage(self, key_hash: str) -> float:
        check_hash(key_hash)
        value = (await self._call("USAGE", {"h": key_hash})).get("u")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BackendUnavailable("the device returned no usage")
        return float(value)

    async def cleanup(self) -> int:
        """Revokes every key in the device's journal that is not dead (§6). It never lists the account."""
        result = await self._call("CLEANUP")
        revoked = result.get("revoked")
        return revoked if isinstance(revoked, int) and not isinstance(revoked, bool) else 0

    def check_rotation(self, *, ttl_seconds: float, per_key_limit_usd: float) -> None:
        """A config that exceeds the device's policy fails at startup with a clear message, not at the first mint."""
        if ttl_seconds > self.policy["max_ttl_s"]:
            raise CustodyError(f"the rotation needs keys that live {ttl_seconds:.0f} s, but the device caps them at "
                               f"{self.policy['max_ttl_s']} s; lower interval_seconds or drain_cap_seconds, or re-enroll with a higher max_ttl_s")
        if round(per_key_limit_usd * 100) > self.policy["max_limit_c"]:
            raise CustodyError(f"per_key_limit_usd {per_key_limit_usd} exceeds the device cap of "
                               f"${self.policy['max_limit_c'] / 100:.2f}")

    async def status(self) -> BackendStatus:
        def bad(detail: str) -> BackendStatus:
            return BackendStatus(mode=self.mode, healthy=False, detail=detail, management_expires_at=self.management_expires_at,
                                 max_limit_usd=self.policy["max_limit_c"] / 100, max_ttl_seconds=self.policy["max_ttl_s"])
        try:
            result = await self._call("CHECK")
        except CustodyError as exc:
            return bad(str(exc))
        if result.get("exp"):
            self.management_expires_at = parse_time(result["exp"]) or self.management_expires_at
        if result.get("healthy") is not True:
            return bad(str(result.get("detail") or "the device reports it is not ready"))
        return BackendStatus(mode=self.mode, healthy=True, management_expires_at=self.management_expires_at,
                             max_limit_usd=self.policy["max_limit_c"] / 100, max_ttl_seconds=self.policy["max_ttl_s"])

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        def close() -> None:
            try:
                if self.client.connected:
                    self.client.call("LOCK", timeout=3)
            except CustodyError:
                pass
            except OSError:
                pass
            finally:
                self.client.close()
                self.pairing.wipe()
        await asyncio.to_thread(close)


def open_device_backend(*, serial_port: str, device_id: str, pairing_file: str | None, workspace_id: str,
                        instance_id: str, transport: Transport | None = None) -> DeviceBackend:
    """Called by run_gateway before uvicorn starts: read the pairing file, open the link, authenticate, unlock."""
    if not DEVICE_ID_RE.fullmatch(device_id or ""):
        raise CustodyError("custody.device_id must look like esp32-1a2b3c4d")
    path = Path(pairing_file).expanduser() if pairing_file else default_pairing_path(device_id)
    pairing = read_pairing(path)
    if pairing.device_id != device_id:
        pairing.wipe()
        raise CustodyError(f"{path} pairs {pairing.device_id}, not {device_id}")
    if serial_port.startswith("tcp://"):
        print("  WARNING: bench transport (TCP). The §13.2 guarantee needs a 3-wire UART; do not use this in production.",
              flush=True)
    try:
        link = transport or open_transport(serial_port)
    except BaseException:
        pairing.wipe()
        raise
    try:
        backend = DeviceBackend(pairing, link, workspace_id=workspace_id, instance_id=instance_id)
        backend._connect()
    except BaseException:
        link.close()
        pairing.wipe()
        raise
    return backend


# ---------------------------------------------------------------------------------------------------------------
# CLI: python -m masqai.device enroll | status | unpair
# ---------------------------------------------------------------------------------------------------------------

WIRING = """\
  Wiring checklist (KeyEnigma.OpenRouter.doc.md §13.2):
    [ ] the gateway host reaches the board ONLY through a 3.3 V USB-TTL adapter: TX->GPIO16, RX->GPIO17, GND
    [ ] the adapter's DTR and RTS are NOT connected
    [ ] the board's own USB port goes to a charger or power bank, never to the gateway host
  If the board's USB is connected to the gateway host, the device's guarantees do not hold."""


@dataclass
class Console:
    secret: Callable[[str], str]
    ask: Callable[[str], str] = input
    say: Callable[[str], None] = print


def _default_console() -> Console:
    from .vault import tty_prompt
    return Console(secret=tty_prompt)


def _ask_policy(console: Console) -> dict[str, int]:
    overrides: dict[str, int] = {}
    text = console.ask("Policy overrides (e.g. max_limit_c=300 max_ttl_s=2400; empty for the defaults): ").strip()
    for item in text.split():
        name, _, value = item.partition("=")
        if name not in POLICY_FIELDS or not value.isdigit():
            raise CustodyError(f"unknown or malformed policy override {item!r}; fields: {', '.join(POLICY_FIELDS)}")
        overrides[name] = int(value)
    return overrides


def cmd_enroll(spec: str, console: Console, *, out: str | None, transport: Transport | None = None) -> None:
    link = transport or open_transport(spec)
    client = DeviceClient(link, timeout=90)   # enrollment checks the key with OpenRouter (Wi-Fi join, TLS)
    try:
        console.say("  Opening an enrollment session (hold BOOT for 3 s at power-on to open the 120 s window)...")
        info, code = client.enroll_begin()
        if info.get("provisioned"):
            console.say("  The device is already enrolled: enrolling again replaces its key and pairing.")
        console.say(f"  Pairing code: {code}")
        if console.ask("  Does the device show the same code? (yes/no): ").strip().lower() not in ("y", "yes"):
            raise CustodyError("the codes differ: something between this host and the device is not trusted; nothing was sent")
        key = console.secret("OpenRouter management key (input hidden): ").strip()
        from .vault import check_management_key
        check_management_key(key)
        workspace = console.ask("Key Enigma workspace id (UUID): ").strip().lower()
        if not UUID_RE.fullmatch(workspace):
            raise CustodyError("the workspace id must be a UUID")
        instance = console.ask("key_enigma.instance_id (8 hex; empty to generate one): ").strip().lower() or secrets.token_hex(4)
        if not INSTANCE_RE.fullmatch(instance):
            raise CustodyError("instance_id must be 8 lowercase hex characters")
        expiry_text = console.ask("Management key expiry (YYYY-MM-DD; empty if OpenRouter reports it): ").strip()
        expiry = None
        if expiry_text:
            try:
                expiry = datetime.strptime(expiry_text, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            except ValueError:
                raise CustodyError("expected a date like 2027-01-31") from None
        ssid = console.ask("Wi-Fi SSID for the device (empty to keep the current one): ").strip()
        args: dict[str, Any] = {"mk": seal_field(client.enc, key), "ws": workspace, "inst": instance,
                                "exp": expiry.strftime("%Y-%m-%dT%H:%M:%SZ") if expiry else None,
                                "pol": _ask_policy(console)}
        key = ""
        if ssid:
            password = console.secret("Wi-Fi password (input hidden): ")
            args["wifi"] = seal_field(client.enc, json.dumps({"ssid": ssid, "pw": password}))
            password = ""
        console.say("  The device is checking the key, the workspace and its budget with OpenRouter...")
        result = client.call("ENROLL_SET", args, timeout=90)
        device_id = result.get("id")
        if not isinstance(device_id, str) or not DEVICE_ID_RE.fullmatch(device_id):
            raise CustodyError("the device returned a malformed id")
        k_mac, unlock = open_field(client.enc, result.get("kmac")), open_field(client.enc, result.get("us"))
        if len(k_mac) != 32 or len(unlock) != 32:
            raise CustodyError("the device returned malformed pairing secrets")
        pairing = Pairing(device_id, bytearray(k_mac), bytearray(unlock), workspace, instance, check_policy(result.get("pol")),
                          parse_time(result.get("exp")), spec, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        path = Path(out).expanduser() if out else default_pairing_path(device_id)
        for warning in write_pairing(path, pairing):
            console.say(f"  warning: {warning}")
        pairing.wipe()
        console.say(f"  enrolled {device_id}; pairing file: {path}")
        console.say(f"  policy: {json.dumps(result.get('pol'))}")
        console.say('  key_enigma.custody: {"mode": "device", "serial_port": "%s", "device_id": "%s"}' % (spec, device_id))
        console.say(f'  key_enigma.instance_id: "{instance}", workspace_id: "{workspace}"')
        console.say(WIRING)
    finally:
        client.close()


def cmd_status(spec: str, console: Console, *, pairing_file: str | None, device_id: str | None,
               transport: Transport | None = None) -> None:
    link = transport or open_transport(spec)
    client = DeviceClient(link)
    pairing = None
    try:
        if device_id or pairing_file:
            path = Path(pairing_file).expanduser() if pairing_file else default_pairing_path(device_id or "")
            pairing = read_pairing(path)
        info = client.hello(bytes(pairing.k_mac) if pairing else None)
        console.say(f"  device: {info.get('id') or '(not enrolled)'}  state: {info.get('state')}  firmware: {info.get('fw')}")
        if pairing is not None:
            status = client.call("STATUS")
            shown = {k: v for k, v in status.items() if k not in ("id",)}
            console.say("  " + json.dumps(shown, sort_keys=True))
        console.say(WIRING)
    finally:
        client.close()
        if pairing is not None:
            pairing.wipe()


def cmd_unpair(spec: str, console: Console, *, pairing_file: str | None, device_id: str | None,
               transport: Transport | None = None) -> None:
    link = transport or open_transport(spec)
    client = DeviceClient(link, timeout=30)
    try:
        console.say("  Opening an enrollment session (unpairing needs the BOOT-button window too)...")
        info, code = client.enroll_begin()
        console.say(f"  Pairing code: {code}")
        if console.ask("  Does the device show the same code? (yes/no): ").strip().lower() not in ("y", "yes"):
            raise CustodyError("the codes differ; nothing was erased")
        if console.ask("  Type 'erase' to delete every secret on the device: ").strip() != "erase":
            raise CustodyError("not confirmed; nothing was erased")
        client.call("ENROLL_ERASE")
        console.say("  the device holds no secrets now. Delete the management key on OpenRouter if it is no longer needed.")
        if device_id or pairing_file:
            path = Path(pairing_file).expanduser() if pairing_file else default_pairing_path(device_id or "")
            if path.is_file():
                from .vault import destroy_file
                destroy_file(path)
                console.say(f"  pairing file destroyed: {path}")
    finally:
        client.close()


def main(argv: list[str] | None = None, console: Console | None = None, *, transport: Transport | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m masqai.device", description="Key Enigma key-provider device")
    parser.add_argument("command", choices=["enroll", "status", "unpair"])
    parser.add_argument("--port", required=True, help="serial port (COM5, /dev/ttyUSB0) or tcp://HOST:PORT (bench only)")
    parser.add_argument("--device-id", default=None)
    parser.add_argument("--pairing-file", default=None)
    args = parser.parse_args(argv)
    console = console or _default_console()
    if args.port.startswith("tcp://"):
        console.say("  WARNING: bench transport (TCP). Production uses a 3-wire UART (§13.2).")
    try:
        if args.command == "enroll":
            cmd_enroll(args.port, console, out=args.pairing_file, transport=transport)
        elif args.command == "status":
            cmd_status(args.port, console, pairing_file=args.pairing_file, device_id=args.device_id, transport=transport)
        else:
            cmd_unpair(args.port, console, pairing_file=args.pairing_file, device_id=args.device_id, transport=transport)
    except CustodyError as exc:
        console.say(f"masqai.device: {exc}")
        return 1
    except (KeyboardInterrupt, EOFError):
        console.say("masqai.device: cancelled")
        return 130
    return 0
