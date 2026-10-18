"""Enrollment (design §13.4): ENROLL_BEGIN, ENROLL_SET and ENROLL_ERASE. Imported only while an enrollment window is
open and dropped from sys.modules afterwards, so a device in run mode does not keep this code (or X25519) in RAM; the
ESP32 without PSRAM has little heap to spare beside the TLS stack (§13.6).
"""
import gc
import json

from . import FW_VERSION, PROTO_VERSION
from . import policy as pol
from .crypto import b64d, b64e, hexe, hkdf, seal, sha256, urandom, CryptoError
from .journal import Journal
from .orapi import ApiError, is_uuid
from .proto import ENROLL_INFO, TAG_HELLO, ProtoError, open_field, plain_error, seal_field
from .timeutil import iso, parse_iso


class EnrollError(Exception):
    def __init__(self, code, msg=""):
        super().__init__(code + (": " + msg if msg else ""))
        self.code = code
        self.msg = msg


def sas_code(key):
    """6-digit short authentication string: both ends display it; a person compares them."""
    d = sha256(b"masqai-enigma-sas" + key)
    return "%06d" % ((d[0] << 16 | d[1] << 8 | d[2]) % 1000000)


def instance_ok(value):
    return isinstance(value, str) and len(value) == 8 and all(c in "0123456789abcdef" for c in value)


def begin(dev, msg):
    """ENROLL_BEGIN: an X25519 exchange; the device shows the pairing code. Returns the reply line."""
    import sys
    from . import x25519
    n = msg.get("n")
    try:
        host_pub = b64d(msg.get("hpk"))
    except CryptoError:
        host_pub = b""
    if len(host_pub) != 32:
        return plain_error(n, "BAD_ARGS", "hpk must be 32 bytes")
    dev.lock()
    dev.session = None
    private, public = x25519.keypair(dev.board.feed)
    try:
        secret = x25519.shared(private, host_pub, dev.board.feed)
    except CryptoError:
        return plain_error(n, "BAD_ARGS", "bad host key")
    finally:
        # X25519 runs once per enrollment; drop it before ENROLL_SET needs the heap for TLS (§13.6).
        x25519 = private = None
        sys.modules.pop("enigma_dev.x25519", None)
        gc.collect()
    keys = hkdf(secret, host_pub + public, ENROLL_INFO, 64)
    dev.new_session(keys, "enroll")
    dev.sas = sas_code(keys)
    dev.board.show("ENROLL CODE", [dev.sas, "compare on host"])
    info = {"pv": PROTO_VERSION, "fw": FW_VERSION, "state": "ENROLL", "dpk": b64e(public),
            "provisioned": dev.ident is not None}
    return dev.reply(n, result=info, tag=TAG_HELLO)


def set_(dev, session, a):
    """ENROLL_SET: check the management key, workspace and budget with OpenRouter, then store them sealed."""
    mk = open_field(session.enc, a.get("mk", "")).decode() if isinstance(a.get("mk"), str) else ""
    ws, inst = a.get("ws"), a.get("inst")
    if not mk or len(mk) > 200 or " " in mk:
        raise EnrollError("BAD_ARGS", "management key missing or malformed")
    if not is_uuid(ws):
        raise EnrollError("BAD_ARGS", "workspace id must be a lowercase UUID")
    if not instance_ok(inst):
        raise EnrollError("BAD_ARGS", "instance id must be 8 lowercase hex characters")
    expires = None
    if a.get("exp") is not None:
        expires = parse_iso(a.get("exp"))
        if expires is None:
            raise EnrollError("BAD_ARGS", "exp must be an ISO time")
    policy = pol.build(a.get("pol") or {})
    wifi = None
    gc.collect()
    if a.get("wifi") is not None:
        try:
            wifi = json.loads(open_field(session.enc, a.get("wifi")))
            ssid, password = wifi["ssid"], wifi["pw"]
            if not (isinstance(ssid, str) and isinstance(password, str) and 0 < len(ssid) <= 32 and len(password) <= 64):
                raise ValueError("wifi")
        except (ValueError, KeyError, TypeError, ProtoError):
            raise EnrollError("BAD_ARGS", "wifi must hold an ssid (1-32) and a password (0-64)")
        dev.board.show("ENROLL", ["joining Wi-Fi"])
        if not dev.board.wifi_connect(ssid, password):
            raise EnrollError("WIFI_FAILED", "could not join that Wi-Fi network")
        dev.board.ntp()
    dev.board.show("ENROLL", ["checking key", "with OpenRouter"])
    # The key must be a management key, and the workspace must exist and have a budget (owner decision, §7).
    who = dev.api.whoami(mk)
    if who.get("is_management_key") is not True:
        raise EnrollError("NOT_MANAGEMENT_KEY", "OpenRouter says this is not a management key")
    reported = parse_iso(who.get("expires_at")) if who.get("expires_at") else None
    if reported is not None:
        expires = reported
    try:
        dev.api.workspace(mk, ws)
    except ApiError as exc:
        if exc.code == "NOT_FOUND":
            raise EnrollError("NO_WORKSPACE", "the workspace does not exist")
        raise
    if not dev.api.budgets(mk, ws):
        raise EnrollError("NO_BUDGET", "the workspace has no budget; add one on OpenRouter (required)")
    k_mac = urandom(32)
    unlock_secret = urandom(32)
    device_id = "esp32-" + hexe(urandom(4))
    cfg = {"mk": mk, "ws": ws, "inst": inst, "pol": policy, "exp": expires}
    dev.board.write("mk", seal(unlock_secret, json.dumps(cfg).encode(), b"mk"))
    dev.board.write("dev", json.dumps({"id": device_id, "kmac": b64e(k_mac)}).encode())
    if wifi is not None:
        dev.board.save_wifi(wifi["ssid"], wifi["pw"])
    dev.ident = {"id": device_id, "kmac": k_mac}
    result = {"id": device_id, "kmac": seal_field(session.enc, k_mac), "us": seal_field(session.enc, unlock_secret),
              "pol": policy, "ws": ws, "inst": inst, "exp": iso(expires) if expires else None}
    dev.board.show("ENROLLED", [device_id, "power: USB only", "data: UART2 only"])
    dev.enroll_until = dev.board.ticks_s()   # one enrollment per window
    return result


def erase(dev):
    dev.lock()
    for name in ("mk", "dev", "journal", "wifi"):
        dev.board.remove(name)
    dev.journal = Journal(dev.board)
    dev.ident = None
    dev.enroll_until = dev.board.ticks_s()
    dev.board.show("ERASED", ["no secrets left"])
    return {"state": "UNPROVISIONED"}
