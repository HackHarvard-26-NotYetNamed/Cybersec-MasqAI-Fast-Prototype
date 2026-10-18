"""BENCH ONLY: compatibility self-test of the firmware's pure modules on the board itself (run as /app.py).
Prints PASS/FAIL lines to /ota-stdout.log. Vectors are the same ones the CPython tests use."""
import time

time.sleep(5)   # owner rule for every /app.py: wait 5 s first, so OTA can always be reached right after a reboot

import gc  # noqa: E402
import sys  # noqa: E402

print("SELFTEST START free", gc.mem_free())
results = []


def check(name, fn):
    try:
        ok = fn()
    except Exception as exc:
        sys.print_exception(exc)
        ok = False
    results.append(ok)
    print("PASS" if ok else "FAIL", name)


from enigma_dev import crypto, httpwire, policy, proto, timeutil, x25519  # noqa: E402

check("hmac/hkdf rfc5869", lambda: crypto.hkdf(bytes([0x0b] * 22), bytes(range(13)), bytes(range(0xf0, 0xfa)), 42) ==
      bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
# AES-256-CTR, NIST SP 800-38A F.5.5 (first block)
check("aes-256-ctr sp800-38a", lambda: crypto.aes_ctr(
    bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
    bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")) ==
      bytes.fromhex("601ec313775789a5b7a7f504bbf3d228"))
t = time.ticks_ms()
check("x25519 rfc7748", lambda: x25519.x25519(
    bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
    bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")) ==
      bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"))
print("x25519 took", time.ticks_diff(time.ticks_ms(), t), "ms")
check("seal/open", lambda: crypto.open_sealed(b"k" * 32, crypto.seal(b"k" * 32, b"secret", b"mk"), b"mk") == b"secret")
check("iso/http dates", lambda: timeutil.parse_http_date("Sun, 18 Oct 2026 12:00:00 GMT") == 1792324800 and
      timeutil.iso(1792324800) == "2026-10-18T12:00:00Z" and timeutil.parse_iso("2024-02-29T23:59:59.123Z") == 1709251199)


def _raises(fn, kind):
    try:
        fn()
    except kind:
        return True
    return False


class S:
    def __init__(self, d):
        self.d = d

    def read(self, n):
        out, self.d = self.d[:7], self.d[7:]
        return out


check("http chunked", lambda: httpwire.read_response(S(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n"))[2] == b"hello")
check("http too large", lambda: _raises(lambda: httpwire.read_response(S(b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\n")), httpwire.HttpError))


check("policy", lambda: policy.admit(policy.build(), [], 1800000000, 1900, 200) == (1900, 0) and
      _raises(lambda: policy.admit(policy.build(), [], 1800000000, 1901, 200), policy.PolicyError))
check("frames", lambda: proto.parse(proto.frame(b"m" * 32, b"Q", {"n": 1}))[2] == {"n": 1})
print("SELFTEST", "ALL PASS" if all(results) else "FAILED", sum(results), "/", len(results), "free", gc.mem_free())
