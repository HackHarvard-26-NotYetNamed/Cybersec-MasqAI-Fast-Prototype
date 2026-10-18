"""The device's command loop logic (design §13.4-§13.6), independent of the hardware.

`Device(board).handle(line) -> reply line`. The board adapter (hw.py on the ESP32, a fake in tests) provides:

    read(name) -> bytes | None        write(name, data)  (atomic)       remove(name)
    ticks_s() -> int (monotonic)      wall() -> int | None (RTC, Unix s; only for the skew check)
    https(method, path, bearer, body) -> (status, headers, body)   raises orapi.ApiError
    show(title, lines)  (display + log; never secrets)             feed()  (watchdog)
    enroll_requested() -> bool  (button held at boot, or the bench flag)
    wifi_connect(ssid, password) -> bool      save_wifi(ssid, password)      ntp() -> bool

There is no operation that returns the management key, k_mac, the unlock secret or any file (§13.4).
Enrollment lives in enroll.py, imported only while an enrollment window is open (RAM, §13.6).
"""
import gc
import json
import sys

from . import FW_VERSION, PROTO_VERSION
from .crypto import CryptoError, b64d, b64e, hkdf, open_sealed, urandom, wipe
from . import policy as pol
from .journal import Journal
from .orapi import ApiError, OpenRouterApi, is_hash, is_uuid, to_cents
from .proto import SESSION_INFO, TAG_HELLO, TAG_REP, TAG_REQ, ProtoError, frame, open_field, parse, plain_error, \
    seal_field, verify
from .timeutil import iso, parse_iso

UNPROVISIONED, LOCKED, UNLOCKED, ENROLL = "UNPROVISIONED", "LOCKED", "UNLOCKED", "ENROLL"
ENROLL_WINDOW_S = 120
SKEW_MAX_S = 300
NAME_PREFIX = "masqai-enigma-"
SUFFIX_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"
INSTANCE_CHARS = "0123456789abcdef"


class DeviceError(Exception):
    def __init__(self, code, msg=""):
        super().__init__(code + (": " + msg if msg else ""))
        self.code = code
        self.msg = msg


def _suffix_ok(value):
    return isinstance(value, str) and 1 <= len(value) <= 32 and value[0] != "-" and all(c in SUFFIX_CHARS for c in value)


def _instance_ok(value):
    return isinstance(value, str) and len(value) == 8 and all(c in INSTANCE_CHARS for c in value)


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _enroll_module():
    from . import enroll
    return enroll


def _drop_enroll_module():
    """Forget enroll.py and x25519.py once the window has closed, so their code can be collected."""
    for name in ("enigma_dev.enroll", "enigma_dev.x25519"):
        if name in sys.modules:
            del sys.modules[name]
    pkg = sys.modules.get("enigma_dev")
    for attr in ("enroll", "x25519"):
        if pkg is not None and attr in getattr(pkg, "__dict__", {}):
            try:
                delattr(pkg, attr)
            except AttributeError:
                pass
    gc.collect()


class Session:
    def __init__(self, mac_key, enc_key, kind):
        self.mac = mac_key
        self.enc = enc_key
        self.kind = kind      # "run" (HELLO) or "enroll" (ENROLL_BEGIN)
        self.n = 0


class Device:
    def __init__(self, board):
        self.board = board
        self.api = OpenRouterApi(board)
        self.journal = Journal(board)
        self.session = None
        self.mk = None            # bytearray: the management key, only while UNLOCKED
        self.cfg = None           # decrypted: workspace, instance, policy, management expiry
        self.ident = None         # dev file: device id + k_mac
        self.last_error = ""
        self.enroll_until = None
        self.sas = None
        self._load_ident()
        if board.enroll_requested():
            self.enroll_until = board.ticks_s() + ENROLL_WINDOW_S
            board.show("ENROLL", ["window open", "%d s" % ENROLL_WINDOW_S])

    # ---------- state ----------
    def _load_ident(self):
        raw = self.board.read("dev")
        self.ident = None
        if raw and self.board.read("mk"):
            try:
                ident = json.loads(raw)
                k_mac = b64d(ident["kmac"])
                if len(k_mac) == 32 and isinstance(ident.get("id"), str):
                    self.ident = {"id": ident["id"], "kmac": k_mac}
            except (ValueError, KeyError, TypeError, CryptoError):
                self.ident = None

    @property
    def state(self):
        if self.enroll_until is not None:
            if self.board.ticks_s() < self.enroll_until:
                return ENROLL
            self._close_enroll()
        if self.ident is None:
            return UNPROVISIONED
        return UNLOCKED if self.mk is not None else LOCKED

    def _close_enroll(self):
        self.enroll_until = None
        self.sas = None
        if self.session is not None and self.session.kind == "enroll":
            self.session = None
        _drop_enroll_module()

    def new_session(self, keys, kind):
        self.session = Session(keys[:32], keys[32:], kind)

    def lock(self):
        if self.mk is not None:
            wipe(self.mk)
        self.mk = None
        self.cfg = None
        gc.collect()

    def _key(self):
        return bytes(self.mk).decode()

    # ---------- framing ----------
    def handle(self, line):
        try:
            mac, text, msg = parse(line)
        except ProtoError as exc:
            return plain_error(None, "BAD_FRAME", str(exc))
        n = msg.get("n")
        op = msg.get("op")
        if mac is None:
            if op == "HELLO":
                return self._hello(msg)
            if op == "ENROLL_BEGIN":
                if self.state != ENROLL:
                    return plain_error(msg.get("n"), "STATE", "no enrollment window: hold BOOT for 3 s at power-on")
                return _enroll_module().begin(self, msg)
            return plain_error(n, "AUTH", "this operation needs an authenticated session")
        session = self.session
        if session is None:
            return plain_error(n, "NO_SESSION", "send HELLO first")
        if not verify(session.mac, TAG_REQ, text, mac):
            return plain_error(n, "AUTH", "bad frame MAC")
        if not _int(n) or n <= session.n:
            return plain_error(n, "REPLAY", "counter must increase")
        session.n = n
        args = msg.get("a") or {}
        if not isinstance(args, dict) or not isinstance(op, str):
            return self.reply(n, error=("BAD_ARGS", "malformed request"))
        try:
            result = self._dispatch(session, op, args)
        except DeviceError as exc:
            self.last_error = exc.code
            return self.reply(n, error=(exc.code, exc.msg))
        except pol.PolicyError as exc:
            self.last_error = exc.code
            return self.reply(n, error=(exc.code, exc.msg))
        except ApiError as exc:
            self.last_error = exc.code
            return self.reply(n, error=(exc.code, exc.msg))
        except MemoryError:
            gc.collect()
            self.last_error = "NO_MEMORY"
            return self.reply(n, error=("NO_MEMORY", ""))
        except Exception as exc:   # never let a bug crash the command loop; report the type only (no values)
            code = getattr(exc, "code", None)
            if type(exc).__name__ == "EnrollError" and isinstance(code, str):
                self.last_error = code
                return self.reply(n, error=(code, exc.msg))
            self.last_error = "INTERNAL"
            return self.reply(n, error=("INTERNAL", type(exc).__name__))
        return self.reply(n, result=result)

    def reply(self, n, result=None, error=None, tag=TAG_REP):
        body = {"n": n, "ok": error is None}
        if error is None:
            body["r"] = result if result is not None else {}
        else:
            body["e"] = {"code": error[0], "msg": error[1][:160]}
        key = self.session.mac if self.session is not None else None
        return frame(key, tag, body)

    def _dispatch(self, session, op, args):
        if session.kind == "enroll":
            if self.state != ENROLL:
                raise DeviceError("STATE", "the enrollment window closed")
            if op == "ENROLL_SET":
                return _enroll_module().set_(self, session, args)
            if op == "ENROLL_ERASE":
                return _enroll_module().erase(self)
            raise DeviceError("BAD_OP", "only ENROLL_SET and ENROLL_ERASE in an enrollment session")
        if op == "STATUS":
            return self._status()
        if op == "UNLOCK":
            return self._unlock(session, args)
        if op == "LOCK":
            self.lock()
            self.board.show("LOCKED", [self.ident["id"]] if self.ident else [])
            return {"state": self.state}
        if self.state != UNLOCKED:
            raise DeviceError("STATE", "%s needs UNLOCKED (device is %s)" % (op, self.state))
        if op == "CHECK":
            return self._check()
        if op == "MINT":
            return self._mint(session, args)
        if op == "REVOKE":
            return self._revoke(args.get("h"))
        if op == "USAGE":
            return self._usage(args.get("h"))
        if op == "CLEANUP":
            return self._cleanup()
        raise DeviceError("BAD_OP", "unknown operation")

    # ---------- sessions ----------
    def _hello(self, msg):
        n = msg.get("n")
        try:
            host_nonce = b64d(msg.get("hn"))
        except CryptoError:
            host_nonce = b""
        if len(host_nonce) != 16:
            return plain_error(n, "BAD_ARGS", "hn must be 16 bytes")
        # A new session always relocks: the host proves itself again with UNLOCK (cheap, no network).
        self.lock()
        self.session = None
        state = self.state
        info = {"pv": PROTO_VERSION, "fw": FW_VERSION, "state": state}
        if self.ident is None:
            return frame(None, None, {"n": n, "ok": True, "r": info})
        dev_nonce = urandom(16)
        self.new_session(hkdf(self.ident["kmac"], host_nonce + dev_nonce, SESSION_INFO, 64), "run")
        info["id"] = self.ident["id"]
        info["dn"] = b64e(dev_nonce)
        return self.reply(n, result=info, tag=TAG_HELLO)

    # ---------- unlock / status ----------
    def _unlock(self, session, a):
        if self.state != LOCKED:
            raise DeviceError("STATE", "UNLOCK needs LOCKED (device is %s)" % self.state)
        try:
            secret = open_field(session.enc, a.get("us", "")) if isinstance(a.get("us"), str) else b""
        except ProtoError:
            secret = b""
        blob = self.board.read("mk")
        try:
            if len(secret) != 32 or not blob:
                raise CryptoError("bad secret")
            plain = open_sealed(secret, blob, b"mk")
            cfg = json.loads(plain)
            cfg["pol"] = pol.check(cfg["pol"])
            if not (is_uuid(cfg["ws"]) and _instance_ok(cfg["inst"]) and isinstance(cfg["mk"], str)):
                raise ValueError("config")
        except (CryptoError, ValueError, KeyError, TypeError, pol.PolicyError):
            raise DeviceError("UNLOCK_FAILED", "wrong unlock secret, or the stored key does not authenticate")
        self.mk = bytearray(cfg.pop("mk").encode())
        self.cfg = cfg
        self.board.show("UNLOCKED", [self.ident["id"]])
        return self._public_cfg()

    def _public_cfg(self):
        cfg = self.cfg
        return {"state": self.state, "ws": cfg["ws"], "inst": cfg["inst"], "pol": cfg["pol"],
                "exp": iso(cfg["exp"]) if cfg.get("exp") else None}

    def _status(self):
        now = self.api.now()
        out = {"state": self.state, "id": self.ident["id"] if self.ident else None, "fw": FW_VERSION,
               "last_error": self.last_error, "server_time": iso(now) if now else None,
               "journal": len(self.journal.entries), "mem_free": gc.mem_free() if hasattr(gc, "mem_free") else None}
        if self.cfg is not None and now is not None:
            out.update(pol.counts(self.cfg["pol"], self.journal.entries, now))
        if self.cfg is not None:
            out.update(self._public_cfg())
        return out

    def _check(self):
        """The same readiness check as passphrase mode (§7): management key, workspace, budget."""
        key = self._key()
        who = self.api.whoami(key)
        if who.get("is_management_key") is not True:
            return {"healthy": False, "detail": "the stored key is no longer a management key"}
        expires = parse_iso(who.get("expires_at")) if who.get("expires_at") else None
        if expires is not None:
            self.cfg["exp"] = expires
        try:
            self.api.workspace(key, self.cfg["ws"])
        except ApiError as exc:
            if exc.code == "NOT_FOUND":
                return {"healthy": False, "detail": "the Key Enigma workspace does not exist"}
            raise
        if not self.api.budgets(key, self.cfg["ws"]):
            return {"healthy": False, "detail": "the Key Enigma workspace has no budget; add one on OpenRouter (required)"}
        self._skew_check()
        return {"healthy": True, "detail": "", "exp": iso(self.cfg["exp"]) if self.cfg.get("exp") else None}

    def _skew_check(self):
        wall, server = self.board.wall(), self.api.now()
        if wall is not None and server is not None and abs(wall - server) > SKEW_MAX_S:
            raise DeviceError("CLOCK_SKEW", "the board clock and OpenRouter differ by %d s" % abs(wall - server))

    def _server_now(self):
        if not self.api.fresh():
            self.api.whoami(self._key())   # any authenticated response carries OpenRouter's Date header
        now = self.api.now()
        if now is None:
            raise DeviceError("NO_SERVER_TIME", "OpenRouter's response carried no Date header")
        self._skew_check()
        return now

    # ---------- keys ----------
    def _mint(self, session, a):
        suffix, ttl, limit_c = a.get("s"), a.get("ttl"), a.get("lim")
        if not _suffix_ok(suffix):
            raise DeviceError("BAD_ARGS", "suffix must be 1-32 of [a-z0-9-]")
        policy = self.cfg["pol"]
        now = self._server_now()
        self.journal.prune(now)
        ttl, burst = pol.admit(policy, self.journal.entries, now, ttl, limit_c)
        expires = now + ttl
        name = NAME_PREFIX + self.cfg["inst"] + "-" + suffix
        # Journal first: if we crash after OpenRouter creates the key, it still counts against the live-key cap until
        # it expires (we can't revoke it without its hash).
        entry = self.journal.add(suffix, now, expires, burst)
        gc.collect()
        try:
            payload = self.api.create(self._key(), name, self.cfg["ws"], limit_c, iso(expires))
        except ApiError as exc:
            if not exc.sent or exc.code in ("MGMT_AUTH", "BAD_REQUEST", "RATE_LIMITED", "NOT_FOUND"):
                self.journal.drop(entry)   # a definite refusal: no key was created
            raise
        data = payload["data"]
        key_hash = data.get("hash")
        if not is_hash(key_hash):
            raise DeviceError("BAD_RESPONSE", "OpenRouter returned a key without a valid hash")
        self.journal.set(entry, h=key_hash, st="live")
        problems = []
        granted = parse_iso(data.get("expires_at"))
        if granted is None or granted > expires:
            problems.append("expiry")
        granted_c = to_cents(data.get("limit"))
        if granted_c is None or granted_c > limit_c:
            problems.append("limit")
        if data.get("workspace_id") not in (None, self.cfg["ws"]):
            problems.append("workspace")
        if data.get("name") not in (None, name):
            problems.append("name")
        if problems:
            try:
                self._revoke(key_hash)
            except (ApiError, DeviceError):
                pass
            raise DeviceError("MINT_MISMATCH", "OpenRouter did not apply the requested " + ", ".join(problems) +
                              "; the key was revoked")
        key = payload["key"]
        result = {"k": seal_field(session.enc, key), "h": key_hash, "name": name, "x": iso(granted), "lim": granted_c}
        payload = data = key = None
        gc.collect()
        return result

    def _entry(self, key_hash):
        if not is_hash(key_hash):
            raise DeviceError("BAD_ARGS", "malformed hash")
        entry = self.journal.find(key_hash)
        if entry is None:
            # Revoke scope is the journal: the device never deletes keys it did not mint (§13.5).
            raise DeviceError("NOT_IN_JOURNAL", "this device did not mint that key")
        return entry

    def _revoke(self, key_hash):
        entry = self._entry(key_hash)
        if entry["st"] == "revoked":
            return {"outcome": "already_gone"}
        key = self._key()
        delete_error = None
        try:
            self.api.delete(key, key_hash)
            outcome = "deleted"
        except ApiError as exc:
            if exc.code == "NOT_FOUND":
                outcome = "already_gone"
            elif exc.code == "MGMT_AUTH":
                raise
            else:
                delete_error = exc
                outcome = None
        if outcome is None:
            try:
                self.api.disable(key, key_hash)
                outcome = "disabled"
            except ApiError as exc:
                if exc.code == "NOT_FOUND":
                    outcome = "already_gone"
                else:
                    self.journal.set(entry, st="failed")
                    raise DeviceError("REVOKE_FAILED", "delete: %s; disable: %s" % (delete_error.code, exc.code))
        self.journal.set(entry, st="revoked")
        return {"outcome": outcome}

    def _usage(self, key_hash):
        self._entry(key_hash)
        data = self.api.get(self._key(), key_hash)
        usage = data.get("usage")
        if isinstance(usage, bool) or not isinstance(usage, (int, float)):
            raise DeviceError("BAD_RESPONSE", "no usage in the key details")
        return {"u": usage}

    def _cleanup(self):
        count = 0
        failed = 0
        for entry in self.journal.open_entries():
            self.board.feed()
            try:
                if self._revoke(entry["h"])["outcome"] != "already_gone":
                    count += 1
            except DeviceError:
                failed += 1
        return {"revoked": count, "failed": failed}
