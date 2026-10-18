"""Key Enigma device firmware entry point (design §13.6). Copy to the board as /main.py with enigma_dev/ and
/enigma/ca.der (see README.md).

Boot: watchdog -> (BOOT held 3 s? enrollment window) -> Wi-Fi -> NTP -> LOCKED, serving the protocol on UART2 only.
The board's USB port must carry power only (§13.2): the REPL on UART0/USB is not a path the gateway host may have.
"""
import time

from enigma_dev import heap
from enigma_dev.hw import Board, UartLink, serve

board = Board()
board.show("BOOT", ["key enigma"])
if board.wifi_connect():
    board.ntp()
else:
    board.show("NO WIFI", ["enroll to set it"])
# Grow the Python heap once, by a bounded amount, before loading the large modules: otherwise MicroPython grows it by
# ~59 KB on its own and leaves too little system heap for a TLS handshake (§13.6). UART2 is borrowed and released.
heap.pregrow()
from enigma_dev.core import Device  # noqa: E402

device = Device(board)
board.show(device.state, [device.ident["id"] if device.ident else "not enrolled"])
_last_wifi = [time.ticks_ms()]


def _idle():
    # Rejoin Wi-Fi if it dropped, at most every 30 s.
    if time.ticks_diff(time.ticks_ms(), _last_wifi[0]) > 30000:
        _last_wifi[0] = time.ticks_ms()
        board.wifi_connect(timeout_s=5)


serve(device, UartLink(), board, idle=_idle)
