"""Keep the system heap free for TLS (design §13.6, bench findings 2026-10-18).

MicroPython on a no-PSRAM ESP32 starts with a 56 KB Python heap and grows it on demand by
min(largest free system block, current heap size), i.e. about 59 KB at once. A TLS handshake needs about 31 KB of
system heap (measured), so an uncontrolled growth, which loading this firmware always triggers, leaves too little
and the handshake stalls. `pregrow()` grows the Python heap once, early, by a chosen amount: it holds the rest of the
largest system block with a UART receive buffer (allocated by the IDF driver), allocates until MicroPython adds a heap
area, keeps one object in that area (an emptied area is freed at the next collection), then releases the UART.

Bench measurements (run-mode firmware ~39 KB of Python heap, OTA launcher ~20 KB): note that on this port
gc.mem_free() includes the largest free system block (the heap could grow into it), so real Python free space is
gc.mem_free() - largest system block. A 26 KB growth left ~22 KB of real Python heap in run mode but only ~6 KB in
an enrollment session (enroll.py + X25519), and the next allocation that did not fit grew the heap by the whole
largest system block (59 KB), leaving 680 bytes: TLS failed with ENOMEM and the OTA listener died. 34 KB is the
compromise: ~53 KB of system heap left (a handshake peaks at ~31 KB). The IDF UART driver refuses a receive buffer
above ~64 KB (ESP_FAIL), which bounds how small a growth can be forced.
`tls_ok()` refuses a handshake unless both heaps have room, so a call fails cleanly instead of starving the board;
`collapsed()` tells the command loop that the system heap is gone anyway (reset, fail-closed).
"""
import gc

_anchor = None
DEFAULT_GROW = 34 * 1024
UART_RXBUF_MAX = 60 * 1024
PY_MIN_FREE = 10 * 1024      # real Python heap needed for one call (request, response up to 8 KB, JSON)
SYS_COLLAPSED = 16 * 1024
# Measured on the bench: one handshake takes ~31.7 KB of system heap at its peak (87.4 KB free -> 55.7 KB low-water
# mark), in several buffers, the largest ~16.4 KB (the TLS record buffer). A closed connection leaves a small lwIP
# block behind for a while, which splits the largest free block, so the total and the largest block are checked apart.
TLS_MIN_FREE = 36 * 1024
TLS_MIN_BLOCK = 18 * 1024


def heap_state():
    import esp32
    info = esp32.idf_heap_info(esp32.HEAP_DATA)
    return sum(r[1] for r in info), max(r[2] for r in info)


def tls_room():
    return heap_state()[1]


def py_free():
    """Real free Python heap: gc.mem_free() counts the largest system block as potential heap on this port."""
    return gc.mem_free() - tls_room()


def tls_ok():
    gc.collect()
    free, largest = heap_state()
    py = gc.mem_free() - largest
    return free >= TLS_MIN_FREE and largest >= TLS_MIN_BLOCK and py >= PY_MIN_FREE, free, largest, py


def collapsed():
    return heap_state()[0] < SYS_COLLAPSED


def _idf_free():
    return heap_state()[0]


def pregrow(grow=DEFAULT_GROW, uart_id=2):
    """Returns the number of bytes the Python heap grew by (0 if it did not, or if it was already done)."""
    global _anchor
    if _anchor is not None:
        return 0
    import machine
    gc.collect()
    hold = min(tls_room() - grow, UART_RXBUF_MAX)
    uart = machine.UART(uart_id, baudrate=115200, rxbuf=hold) if hold > 256 else None
    chunks = []
    base = _idf_free()
    grown = 0
    try:
        for _ in range(256):
            c = bytearray(1024)
            now = _idf_free()
            if now < base - 8192:
                _anchor, grown = c, base - now
                break
            chunks.append(c)
    finally:
        if uart is not None:
            uart.deinit()
        del chunks
        gc.collect()
    return grown
