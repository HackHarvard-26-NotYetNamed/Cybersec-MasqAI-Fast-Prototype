"""Key Enigma device firmware (design: KeyEnigma.OpenRouter.doc.md §13).

Pure modules (crypto, timeutil, httpwire, policy, journal, proto, orapi, core) run under MicroPython and CPython, so
they are tested in CI. `hw` is the MicroPython-only adapter: Wi-Fi, NTP, TLS sockets, flash, UART, button, watchdog.
"""
FW_VERSION = "enigma-dev 1.0"
PROTO_VERSION = 1
