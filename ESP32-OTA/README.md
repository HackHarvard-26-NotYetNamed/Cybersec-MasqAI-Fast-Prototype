# ESP32 MicroPython OTA port

This directory is a one-time uploadable MicroPython driver. It starts on every boot, connects to Wi-Fi, and exposes an authenticated HTTP port for file transfer and a small interactive shell.

For a coding-agent-focused operating guide, see [`AGENT-OTA.md`](AGENT-OTA.md). It documents the full wireless edit/run/observe/restore loop, including how to retrieve `print()` output from uploaded programs.

The OTA runtime can also drive an SSD1306 I2C status display. The configured wiring is `SCL -> GPIO18` and `SDA -> GPIO23`; the default I2C addresses checked are `0x3C` and `0x3D`. After each boot it shows boot/Wi-Fi status and, once connected, the device IP address.

## One-time install

1. Copy [`device/ota_config.example.py`](device/ota_config.example.py) to `device/ota_config.py`, then set `WIFI_SSID`, `WIFI_PASSWORD`, and a unique `OTA_TOKEN`. The real config is git-ignored because it contains credentials.
2. Keep your application as `device/app.py`. If you already have a `main.py`, move its contents to `app.py` or merge it into the supplied launcher.
3. With a working data cable and `mpremote` installed, run each command separately:

```powershell
mpremote connect auto fs cp device/main.py :main.py
mpremote connect auto fs cp device/main-OTA.py :main-OTA.py
mpremote connect auto fs cp device/ota_config.py :ota_config.py  # local, git-ignored config
mpremote connect auto fs cp device/app.py :app.py
mpremote connect auto fs cp ssd1306.py :ssd1306.py
```

The launcher starts `main-OTA.py` and then executes `app.py` as the main application. The OTA thread survives application exceptions and keeps the device reachable. Application `print()` output and Python tracebacks are copied to `/ota-stdout.log` and remain available for OTA download. The log is reset on each boot and capped at 32 KiB. A reboot is only needed after the initial upload.

## Host port

The host requires Python 3.9+ and uses only the standard library. The compact MicroPython HTTP service buffers one request in RAM, so keep individual uploads within the board's available RAM (scripts and configuration files are the intended use):

```text
python port.py --host esp32-ota.local --token replace-this-token ls /
python port.py --host 192.168.1.50 --token replace-this-token put local.txt /local.txt
python port.py --host 192.168.1.50 --token replace-this-token get /app.py downloaded-app.py
python port.py --host 192.168.1.50 --token replace-this-token rm /old.txt
python port.py --host 192.168.1.50 --token replace-this-token shell
```

Use `python port.py --help` for all commands, including `reboot`. The token is sent in `X-OTA-Token`; the service should be used only on a trusted LAN or behind an appropriate network boundary.

## Hardware smoke test

After upload, reboot the ESP32 and run:

```text
python port.py --host esp32-ota.local --token replace-this-token health
python port.py --host esp32-ota.local --token replace-this-token put README.md /ota-test.txt
python port.py --host esp32-ota.local --token replace-this-token get /ota-test.txt ota-test.downloaded
python port.py --host esp32-ota.local --token replace-this-token rm /ota-test.txt
```

The final downloaded file must match the original. This verifies boot, Wi-Fi, authentication, upload, download, and deletion without replacing application code.
