"""Wire format between the gateway host and the device (design §13.4).

One frame per line, at most MAX_LINE bytes:

    <mac> <payload JSON>\n

- `mac` is base64 HMAC-SHA256 over a one-byte direction tag plus the exact payload bytes, or `-` for the two
  unauthenticated openers (HELLO, ENROLL_BEGIN) and for error replies sent without a session. MACing the bytes as
  sent avoids any canonical-JSON rules between MicroPython and CPython.
- Tags: H (device HELLO reply), Q (host request), R (device reply). A frame can't be replayed in the other direction.
- Requests carry a counter `n` that must strictly increase within a session; replies echo it.
- Secrets inside payloads (inference keys, the unlock secret, enrollment secrets) are additionally encrypted with
  AES-256-CTR under the session's encryption key: `b64(iv || ciphertext)`. The frame MAC covers them.
"""
import json

from .crypto import aes_ctr, b64d, b64e, ct_equal, hmac_sha256, urandom, CryptoError

MAX_LINE = 2048
TAG_HELLO, TAG_REQ, TAG_REP = b"H", b"Q", b"R"
SESSION_INFO = b"masqai-enigma-session-v1"
ENROLL_INFO = b"masqai-enigma-enroll-v1"


class ProtoError(Exception):
    pass


def parse(line):
    """-> (mac bytes or None, payload bytes, payload dict)."""
    if isinstance(line, str):
        line = line.encode()
    line = line.strip()
    if not line or len(line) > MAX_LINE:
        raise ProtoError("empty or oversized frame")
    cut = line.find(b" ")
    if cut < 0:
        raise ProtoError("frame has no payload")
    head, text = line[:cut], line[cut + 1:]
    try:
        msg = json.loads(text)
    except ValueError:
        raise ProtoError("payload is not JSON")
    if not isinstance(msg, dict):
        raise ProtoError("payload is not an object")
    if head == b"-":
        return None, text, msg
    try:
        mac = b64d(head.decode())
    except (CryptoError, UnicodeError):
        raise ProtoError("bad mac field")
    if len(mac) != 32:
        raise ProtoError("bad mac length")
    return mac, text, msg


def verify(key, tag, text, mac):
    return ct_equal(hmac_sha256(key, tag + text), mac)


def frame(key, tag, obj):
    text = json.dumps(obj).encode()
    if key is None:
        return b"- " + text + b"\n"
    return b64e(hmac_sha256(key, tag + text)).encode() + b" " + text + b"\n"


def plain_error(n, code, msg=""):
    return frame(None, None, {"n": n, "ok": False, "e": {"code": code, "msg": msg}})


def seal_field(key, data):
    if isinstance(data, str):
        data = data.encode()
    iv = urandom(16)
    return b64e(iv + aes_ctr(key, iv, data))


def open_field(key, text):
    try:
        raw = b64d(text)
    except CryptoError:
        raise ProtoError("encrypted field is not base64")
    if len(raw) < 17:
        raise ProtoError("encrypted field too short")
    return aes_ctr(key, raw[:16], raw[16:])
