# Key Enigma device firmware (ESP32, MicroPython)

The ESP32 holds the OpenRouter management key and mints short-lived inference keys for the gateway. The gateway
never sees the management key. Design: `KeyEnigma.OpenRouter.doc.md` §13.

Target: original ESP32 (no PSRAM), MicroPython v1.27.0. A board with PSRAM, or a MicroPython build with `enigma_dev`
frozen in, has far more memory headroom (§13.6).

## Layout

```
enigma_dev/        the firmware package
  crypto.py        HMAC/HKDF, AES-256-CTR (on cryptolib ECB), encrypt-then-MAC
  x25519.py        X25519 for enrollment (loaded only in an enrollment window)
  enroll.py        ENROLL_BEGIN / ENROLL_SET / ENROLL_ERASE (loaded only in an enrollment window)
  timeutil.py      dates without the RTC
  httpwire.py      one capped HTTP/1.1 exchange per connection
  orapi.py         OpenRouter management calls; OpenRouter's Date header is the device clock
  policy.py        firmware policy (caps, rate limits)
  journal.py       minted keys (hashes, times, states; never key values)
  proto.py         frames between host and device
  core.py          the command state machine (run mode)
  heap.py          memory controls: bounded early heap growth, TLS-room checks (§13.6)
  hw.py            MicroPython-only adapter: flash, Wi-Fi, NTP, TLS, UART2, BOOT button, watchdog
main.py            production entry point: serves UART2 only
ca/gts_root_r4.der the trust anchor for openrouter.ai (SHA-256 349dfa40…1b3c7d)
bench/             BENCH ONLY (see below)
```

Everything except `hw.py`, `heap.py` and `main.py` also runs under CPython. The tests are
`tests/test_device_firmware.py` and `tests/test_device.py`.

## Memory (read this before changing the firmware)

On an ESP32 without PSRAM, MicroPython's heap starts at 56 KB and grows on demand into the system heap that TLS
needs: by about 59 KB in one step, which leaves too little for a handshake (about 31 KB). So:

- `main.py` calls `heap.pregrow()` **before** importing `enigma_dev.core`. It grows the Python heap once by 34 KB, by
  briefly holding system heap with a UART2 receive buffer. UART2 is the host link; it is opened for real afterwards.
- Keep `core` and anything imported in run mode small. Enrollment code goes in `enroll.py`.
- `Board.https` refuses a call when either heap is short; the command loop resets the board if the system heap
  collapses (production only).
- On this port `gc.mem_free()` includes the largest free system block. Use `heap.py_free()` for the real figure.

## Flashing (on a trusted computer, over the board's USB)

```bash
pip install mpy-cross==1.27.0.post2 mpremote
for f in enigma_dev/*.py; do python -m mpy_cross -march=xtensawin -O1 "$f"; done
mpremote mkdir :/enigma_dev ; mpremote mkdir :/enigma
mpremote cp enigma_dev/*.mpy :/enigma_dev/
mpremote cp ca/gts_root_r4.der :/enigma/ca.der
mpremote cp main.py :/main.py
```

## Wiring (the critical rule, §13.2)

```
gateway host --USB-- [3.3 V USB-TTL adapter] --TX->GPIO16, RX->GPIO17, GND--> ESP32 UART2
charger / power bank --USB (power only)--> ESP32 USB port
```

- Do not connect the adapter's DTR or RTS.
- Never connect the board's USB port to the gateway host. Its REPL and auto-reset circuit would let the host read
  the flash.

## Enrolling

1. Power on while holding BOOT (GPIO0) for 3 s. A 120 s enrollment window opens.
2. Run `python -m masqai.device enroll --port COM5`.
3. Compare the 6-digit code with the board's display or log.
4. Enter the management key, the workspace and the Wi-Fi details at the hidden prompts.

The board checks the key, the workspace and its budget with OpenRouter before it stores anything.

## Bench (no USB-TTL adapter)

These tools are **bench only**. They are not part of the production firmware, and only FAKE keys go through them.

- `bench/fake_openrouter.py`: a fake OpenRouter management API over TLS 1.2 on the LAN. It uses a throwaway CA and a
  certificate for `openrouter.ai` (valid 7 days; delete the `--out` directory to make new ones), and has a control
  port on 127.0.0.1:8444.
- `bench/app.py`: the device core running as the ESP32-OTA board's `/app.py`. It serves the protocol on TCP 7777.
  - It waits 5 s first (owner rule), stops itself after 20 min, and never resets the board, so OTA stays reachable.
  - `/enigma/bench_enroll` opens one enrollment window in place of the button.
  - `/enigma/bench_target.json` points TLS at the fake (the name `openrouter.ai` is still checked).
- `bench/drive.py enroll|run|soak`: drives the board with the real host code over `tcp://BOARD:7777`. `run` mints
  5 keys, so the board's rate limits need about 10 min between runs.
- `bench/selftest.py`: runs the crypto, date, HTTP, policy and frame vectors on the board itself.

Results (2026-10-18, ESP32 without PSRAM under the ESP32-OTA launcher): self-test 9/9; `enroll` passed; `run` 17/17;
`soak` 102 TLS handshakes with flat memory. Not yet run: the real openrouter.ai, and `main.py` on UART2 with the
watchdog (needs a USB-TTL adapter).
