# OTA CLI runbook for coding agents

This is the operating guide for an agent debugging the MicroPython ESP32 wirelessly after the one-time USB installation. Treat the device as a small remote filesystem and command endpoint, not as an interactive serial REPL.

## Connection contract

The service is HTTP on port `80` by default and requires the token configured in `device/ota_config.py`. Every request made by `port.py` includes the token as `X-OTA-Token`.

The preferred invocation uses an explicit IP address because `.local` mDNS names are not available on every Windows network:

```powershell
$host = "192.168.219.225"
$token = "YOUR_OTA_TOKEN"
$portArgs = @("ESP32-OTA/port.py", "--host=$host", "--token=$token")
```

If the address is unknown, connect the USB cable temporarily and ask MicroPython for it:

```powershell
mpremote connect COM6 exec "import network; print(network.WLAN(network.STA_IF).ifconfig())"
```

The first tuple element is the device IP. A device may receive a different address after a router reconnect, so repeat this discovery when health checks fail.

## Agent startup checklist

Run these in order before changing code:

```powershell
python @portArgs health
python @portArgs ls /
python @portArgs get /ota-stdout.log .\device-stdout-before.log
```

`health` proves that Wi-Fi, the OTA thread, HTTP, and authentication are working. `ls /` confirms the deployed files. The stdout download is best-effort because the log may not exist until the application has printed something.

Expected root files include:

```text
/main.py          persistent launcher
/main-OTA.py      OTA server
/ota_config.py    Wi-Fi and token configuration
/app.py           user application executed as __main__
/ota-stdout.log   bounded application stdout capture
/ssd1306.py       SSD1306 I2C driver, if a display is installed
```

## SSD1306 boot display

The supplied runtime initializes an SSD1306 over I2C on every boot. The default mapping is:

```text
SSD1306 SCL -> ESP32 GPIO18
SSD1306 SDA -> ESP32 GPIO23
```

It displays `BOOTING`, then `WIFI CONNECTING`, and finally `ONLINE`, the hostname, and the assigned IP address. The runtime checks address `0x3C` first and falls back to `0x3D`. If no display is detected, OTA continues normally and `health` reports `display: false` with the diagnostic in `display_error`.

The relevant health check is:

```powershell
python @portArgs health
```

An installed display should produce JSON containing `"display": true`, its I2C address in `display_addr`, and the current IP in `ip`.

## Uploading a program

Upload the file to a temporary or deliberate remote path:

```powershell
python @portArgs put .\sensor_debug.py /sensor_debug.py
```

Uploading a file does not execute it. The OTA shell deliberately supports only filesystem operations and does not evaluate arbitrary Python received over HTTP.

## Running an uploaded program and getting stdout

The recommended debugging pattern is to make the uploaded program write its results to stdout, then run it through the existing application slot and download the captured log. For a one-shot script, preserve the current application first, replace `/app.py`, reboot, collect output, then restore the application:

```powershell
python @portArgs get /app.py .\app.before-debug.py
python @portArgs put .\sensor_debug.py /app.py
python @portArgs shell cat /ota-stdout.log
```

The last command only reads the old log. Clear it before the run and reboot the board through the USB connection or the application’s own reset mechanism:

```powershell
python @portArgs rm /ota-stdout.log
mpremote connect COM6 reset
Start-Sleep -Seconds 3
python @portArgs get /ota-stdout.log .\sensor_debug.stdout.log
Get-Content .\sensor_debug.stdout.log
```

`print()` output from `/app.py` is duplicated to the serial console and `/ota-stdout.log`. The log is capped at `STDOUT_LOG_MAX` bytes, configured by default to 32 KiB. When it reaches that limit it is rotated and begins again with `[stdout log rotated]`.

For a fully wireless run, use the OTA reboot command instead of `mpremote`:

```powershell
python @portArgs rm /ota-stdout.log
python @portArgs reboot
Start-Sleep -Seconds 3
python @portArgs health
python @portArgs get /ota-stdout.log .\sensor_debug.stdout.log
Get-Content .\sensor_debug.stdout.log
```

The `shell` command returns the output of the OTA shell command itself. It does not attach to the application’s stdout and it cannot launch arbitrary Python. To get output from an uploaded program, put that program in `/app.py`, clear the old log, call `reboot`, wait for `health`, and download `/ota-stdout.log`.

For repeated debugging, use a program that writes a clear start/end marker:

```python
print("DEBUG START")
try:
    print(repr(read_sensor()))
except Exception as exc:
    import sys
    sys.print_exception(exc)
print("DEBUG END")
```

The agent should download the log after the program has had enough time to run, search for those markers, and report the relevant lines. Do not rely on the HTTP shell to stream a long-running process: shell commands are request/response operations and the supported shell has no arbitrary process execution command.

## Filesystem commands

```powershell
python @portArgs ls /
python @portArgs ls /lib
python @portArgs mkdir /debug
python @portArgs put .\config.json /debug/config.json
python @portArgs get /debug/config.json .\config.downloaded.json
python @portArgs rm /debug/config.json
```

The shell provides a small set of read/write checks:

```powershell
python @portArgs shell pwd
python @portArgs shell ls /
python @portArgs shell cat /ota-stdout.log
python @portArgs shell help
```

Use `get` for binary-safe downloads. `shell cat` is text-oriented and should not be used for binary files.

## Updating the application safely

Use a backup and a temporary upload path. Verify the transfer locally, then promote it:

```powershell
python @portArgs get /app.py .\app.backup.py
python @portArgs put .\new_app.py /app.next.py
python @portArgs get /app.next.py .\app.next.downloaded.py
```

The current filesystem shell has no rename operation. To make `/app.next.py` the active program, upload it directly to `/app.py` after the download verification. A bad application cannot remove the OTA listener because `main.py` starts OTA before executing `/app.py`, and application exceptions are caught by the launcher.

Always preserve `/app.py` before replacing it. If the new program fails, restore the backup with:

```powershell
python @portArgs put .\app.backup.py /app.py
mpremote connect COM6 reset
```

## Health, authentication, and failures

```powershell
python @portArgs health
```

Common results:

- `401 Unauthorized`: token mismatch; use the exact configured token. Tokens beginning with `-` require `--token=VALUE` in PowerShell.
- Connection refused or timeout: check the IP, Wi-Fi association, port, and whether the device has rebooted. Discover the IP over USB if needed.
- `404 Not Found`: wrong endpoint or an older OTA file is installed.
- `error: path escapes filesystem`: the requested path contained `..`; use an absolute path under `/`.
- Empty stdout log: the program has not printed yet, printed before the tee was installed, or failed before producing output. Check serial output through USB for boot-time exceptions.

The service is intentionally limited to a trusted LAN. It is plain HTTP, so the token protects access but does not encrypt traffic. Do not expose port 80 to the public internet.

## Complete agent loop

For each wireless debugging iteration:

1. Run `health`.
2. Download the current `/app.py` and `/ota-stdout.log` when they exist.
3. Upload the candidate program to `/app.py` or a temporary path.
4. Clear the old stdout log.
5. Reboot with `python @portArgs reboot` (use the USB cable only as recovery if OTA is unavailable).
6. Wait for Wi-Fi and run `health` again.
7. Download `/ota-stdout.log` and inspect the output and traceback.
8. Keep the working version or restore the backup.
9. Remove temporary files.

This loop gives the agent a reproducible wireless edit, run, observe, and restore workflow while retaining a USB recovery path.
