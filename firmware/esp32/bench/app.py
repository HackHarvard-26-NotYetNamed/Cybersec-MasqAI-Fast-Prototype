"""BENCH ONLY: run the device firmware as the ESP32-OTA board's /app.py, serving the protocol over TCP (no USB-TTL
adapter on the bench). Not part of the production firmware (firmware/esp32/main.py serves UART2 only).

Bench differences, each deliberate and printed at startup:
- link: TCP port 7777 instead of UART2 (§13.2's "no radio path to the host" does not hold on the bench);
- enrollment window: opened at boot when /enigma/bench_enroll exists (the owner chose this over pressing BOOT);
  the file is deleted as soon as it is read, so it opens one window only;
- OpenRouter: when /enigma/bench_target.json exists ({"host": ip, "port": n, "ca": path}), the board dials that
  host and trusts that CA, still checking the name openrouter.ai. Without it, it talks to the real openrouter.ai
  with GTS Root R4 (/enigma/ca.der);
- no watchdog: the OTA launcher's own loop would not feed it.
Wi-Fi is already up (the OTA launcher connected it).
"""
import time

time.sleep(5)   # owner rule for every /app.py: wait 5 s first, so OTA can always be reached right after a reboot

import gc  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402

print("ENIGMA BENCH START", sys.implementation, "free", gc.mem_free())

try:
    import ntptime
    ntptime.settime()
    print("ntp ok", time.gmtime()[:6])
except Exception as exc:
    print("ntp failed:", exc)

from enigma_dev import heap  # noqa: E402

# Bounded, early Python-heap growth so the firmware imports leave room for TLS (§13.6). UART2 is borrowed briefly.
print("heap pregrow", heap.pregrow(), "system heap (free, largest)", heap.heap_state())
from enigma_dev import hw  # noqa: E402
from enigma_dev.core import Device  # noqa: E402
print("firmware loaded; system heap", heap.heap_state(), "gc free", gc.mem_free())

connect, ca = None, hw.DIR + "/ca.der"
try:
    with open(hw.DIR + "/bench_target.json") as f:
        target = json.load(f)
    connect, ca = (target["host"], target["port"]), target["ca"]
    print("bench target: %s:%d (TLS name openrouter.ai, CA %s)" % (target["host"], target["port"], ca))
except OSError:
    print("target: the real openrouter.ai, trusting", ca)


class BenchBoard(hw.Board):
    def _button_held(self):
        try:
            os.stat(hw.DIR + "/bench_enroll")
        except OSError:
            return False
        os.remove(hw.DIR + "/bench_enroll")
        print("bench: enrollment window opened by /enigma/bench_enroll (one window)")
        return True

    def https(self, method, path, bearer, body):
        started = time.ticks_ms()
        print("https", method, path.split("/")[3], "start; system heap", heap.heap_state())
        try:
            result = hw.Board.https(self, method, path, bearer, body)
            print("https", method, path.split("/")[3], result[0], time.ticks_diff(time.ticks_ms(), started), "ms; system heap", heap.heap_state())
            return result
        except Exception as exc:
            print("https", method, path.split("/")[3], "error", type(exc).__name__, exc)
            raise


board = BenchBoard(ca_path=ca, connect=connect, wdt=False, log=print)
device = Device(board)
print("state", device.state, "id", device.ident["id"] if device.ident else None, "free", gc.mem_free())
link = hw.TcpLink(7777)
print("serving the device protocol on tcp/7777 (BENCH ONLY)")
# Bench sessions are bounded so the board always returns to the OTA launcher's idle loop on its own.
_deadline = time.ticks_add(time.ticks_ms(), 20 * 60 * 1000)


def _idle():
    if time.ticks_diff(_deadline, time.ticks_ms()) < 0:
        raise SystemExit("bench session over (20 min)")
    time.sleep_ms(20)   # yield to the OTA thread between polls


try:
    hw.serve(device, link, board, idle=_idle)
except (SystemExit, MemoryError) as exc:
    # Bench: never reset the board from here (OTA must stay reachable); just stop and relock.
    print("bench serve stopped:", exc)
    device.lock()
    link.srv.close()
