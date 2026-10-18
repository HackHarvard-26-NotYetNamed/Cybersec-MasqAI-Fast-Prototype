"""Persistent Wi-Fi entry point for the Key Enigma ESP32 device.

Deploy as the OTA launcher's /app.py. OTA stays available through its own thread.
Pairing is opened only by a one-shot /enigma/lan_enroll marker, after an owner
creates that marker through the authenticated OTA channel.
"""
import time

time.sleep(5)

import gc
import os
import sys

print("KEY ENIGMA LAN START", sys.implementation, "free", gc.mem_free())

from enigma_dev import heap
heap.pregrow()
from enigma_dev.hw import Board, TcpLink, serve


class LanBoard(Board):
    def _button_held(self):
        marker = None
        for candidate in ("/enigma/lan_enroll", "/enigma/lan_enroll.bin"):
            try:
                os.stat(candidate)
                marker = candidate
                break
            except OSError:
                pass
        if marker is None:
            return False
        os.remove(marker)
        self.show("PAIRING", ["owner opened via OTA", "120 seconds"])
        return True

    def show(self, title, lines=()):
        from machine import I2C, Pin
        try:
            import ssd1306
            display = ssd1306.SSD1306_I2C(128, 64, I2C(0, scl=Pin(18), sda=Pin(23), freq=100000))
            display.fill(0)
            display.text(str(title)[:21], 0, 0)
            for index, line in enumerate(lines[:6]):
                display.text(str(line)[:21], 0, 12 + index * 8)
            display.show()
        except Exception as exc:
            print("display update failed", type(exc).__name__)
        print("[enigma]", title, "|", " | ".join(lines))


board = LanBoard(wdt=True, log=print)
board.show("BOOT", ["Key Enigma LAN"])
if not board.wifi_connect(timeout_s=20):
    import network
    if not network.WLAN(network.STA_IF).isconnected():
        board.show("NO WIFI", ["retrying"])
board.ntp()

from enigma_dev.core import Device

device = Device(board)
board.show(device.state, [device.ident["id"] if device.ident else "not enrolled"])
link = TcpLink(7777)
print("serving authenticated Key Enigma protocol on LAN tcp/7777")
_last_wifi = [time.ticks_ms()]


def _idle():
    if time.ticks_diff(time.ticks_ms(), _last_wifi[0]) > 30000:
        _last_wifi[0] = time.ticks_ms()
        if not board.wifi_connect(timeout_s=5):
            import network
            if not network.WLAN(network.STA_IF).isconnected():
                board.show("NO WIFI", ["retrying"])
    time.sleep_ms(20)


try:
    serve(device, link, board, idle=_idle)
finally:
    device.lock()
    link.close()
