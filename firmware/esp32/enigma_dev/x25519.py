"""X25519 (RFC 7748) in pure Python, used once per enrollment (design §13.4). Kept out of crypto.py so a device in
run mode never loads it (RAM, §13.6). It is not constant-time; the private key is ephemeral and used once.
"""
from .crypto import CryptoError, urandom

_P = (1 << 255) - 19
_A24 = 121665
BASE = bytes([9]) + bytes(31)


def x25519(scalar, u_bytes, tick=None):
    """scalar: 32 bytes; u_bytes: 32 bytes. `tick` is called every 32 ladder steps (to feed a watchdog)."""
    if len(scalar) != 32 or len(u_bytes) != 32:
        raise CryptoError("x25519 needs 32-byte inputs")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(bytes(k), "little")
    u = bytearray(u_bytes)
    u[31] &= 127
    x1 = int.from_bytes(bytes(u), "little") % _P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        s = (da + cb) % _P
        x3 = s * s % _P
        s = (da - cb) % _P
        z3 = x1 * (s * s % _P) % _P
        x2 = aa * bb % _P
        z2 = e * ((aa + _A24 * e) % _P) % _P
        if tick is not None and not (t & 31):
            tick()
    if swap:
        x2, z2 = x3, z3
    out = x2 * _modexp(z2, _P - 2) % _P
    return out.to_bytes(32, "little")


def _modexp(base, exp):
    # Not pow(b, e, m): three-argument pow is an optional MicroPython feature.
    result = 1
    base %= _P
    while exp:
        if exp & 1:
            result = result * base % _P
        base = base * base % _P
        exp >>= 1
    return result


def keypair(tick=None):
    private = urandom(32)
    return private, x25519(private, BASE, tick)


def shared(private, peer_public, tick=None):
    secret = x25519(private, peer_public, tick)
    if secret == bytes(32):
        raise CryptoError("x25519: low-order peer key")
    return secret
