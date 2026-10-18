"""Primitives for the device, written for MicroPython (and CPython, for tests).

- HMAC-SHA256 and HKDF (RFC 2104 / RFC 5869), built on hashlib: MicroPython has no hmac module.
- AES-256-CTR built on AES-ECB (cryptolib mode 1 on the device), so it does not depend on cryptolib's optional CTR
  mode. The counter is the whole 16-byte block, big-endian, as in NIST SP 800-38A and the `cryptography` package.
- `seal`/`open_sealed`: encrypt-then-MAC (AES-256-CTR + HMAC-SHA256) for data at rest.
"""
import binascii
import hashlib

try:
    import cryptolib

    def _ecb(key, data):
        return cryptolib.aes(key, 1).encrypt(data)
except ImportError:   # CPython (tests)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _ecb(key, data):
        enc = Cipher(algorithms.AES(bytes(key)), modes.ECB()).encryptor()
        return enc.update(bytes(data)) + enc.finalize()

try:
    import os
    urandom = os.urandom
except (ImportError, AttributeError):   # pragma: no cover
    from os import urandom


class CryptoError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).digest()


def hmac_sha256(key, data):
    if len(key) > 64:
        key = sha256(key)
    key = bytes(key) + bytes(64 - len(key))
    inner = bytearray(64)
    outer = bytearray(64)
    for i in range(64):
        inner[i] = key[i] ^ 0x36
        outer[i] = key[i] ^ 0x5C
    h = hashlib.sha256(bytes(inner))
    h.update(data)
    o = hashlib.sha256(bytes(outer))
    o.update(h.digest())
    return o.digest()


def hkdf(ikm, salt, info, length):
    if not salt:
        salt = bytes(32)
    prk = hmac_sha256(salt, ikm)
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


def ct_equal(a, b):
    """Constant-time comparison of two byte strings."""
    if len(a) != len(b):
        return False
    diff = 0
    for i in range(len(a)):
        diff |= a[i] ^ b[i]
    return diff == 0


def aes_ctr(key, iv, data):
    if len(key) != 32 or len(iv) != 16:
        raise CryptoError("aes_ctr needs a 32-byte key and a 16-byte iv")
    n = (len(data) + 15) // 16
    counter = int.from_bytes(iv, "big")
    blocks = bytearray()
    for i in range(n):
        blocks += ((counter + i) & ((1 << 128) - 1)).to_bytes(16, "big")
    stream = _ecb(key, bytes(blocks)) if n else b""
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ stream[i]
    return bytes(out)


def wipe(buf):
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


# ---- data at rest: encrypt-then-MAC ---------------------------------------------------------------------------

def seal(secret, plaintext, label):
    """`secret` (32 random bytes) -> label | iv | ct | tag. Keys are derived per label."""
    keys = hkdf(secret, b"", b"masqai-enigma-at-rest-v1:" + label, 64)
    iv = urandom(16)
    ct = aes_ctr(keys[:32], iv, plaintext)
    body = label + b"|" + iv + ct
    return body + hmac_sha256(keys[32:], body)


def open_sealed(secret, blob, label):
    keys = hkdf(secret, b"", b"masqai-enigma-at-rest-v1:" + label, 64)
    head = label + b"|"
    if len(blob) < len(head) + 16 + 32 or blob[:len(head)] != head:
        raise CryptoError("sealed blob is malformed")
    body, tag = blob[:-32], blob[-32:]
    if not ct_equal(hmac_sha256(keys[32:], body), tag):
        raise CryptoError("sealed blob does not authenticate")
    iv = body[len(head):len(head) + 16]
    return aes_ctr(keys[:32], iv, body[len(head) + 16:])


# ---- encodings --------------------------------------------------------------------------------------------------

def b64e(data):
    return binascii.b2a_base64(data).strip().decode()


def b64d(text):
    if not isinstance(text, str):
        raise CryptoError("expected base64 text")
    try:
        return binascii.a2b_base64(text)
    except Exception:
        raise CryptoError("bad base64")


def hexe(data):
    return binascii.hexlify(data).decode()
