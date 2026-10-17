"""Persistent MicroPython launcher. Upload this file as /main.py."""

import sys
import time

import ota_config


def _boot_marker(message):
    try:
        with open("/ota-boot.log", "a") as marker:
            marker.write(message + "\n")
    except Exception:
        pass


class _LogWriter:
    def __init__(self, filename, maximum):
        self.filename = filename
        self.maximum = maximum
        try:
            self.log = open(filename, "w")
        except Exception:
            self.log = None

    def write(self, text):
        if self.log:
            try:
                self.log.write(text)
                self.log.flush()
                if self.log.tell() > self.maximum:
                    self.log.close()
                    self.log = open(self.filename, "w")
                    self.log.write("[stdout log rotated]\n")
                    self.log.flush()
            except Exception:
                pass

    def flush(self):
        if self.log:
            self.log.flush()

ota_namespace = {}
_boot_marker("launcher:begin")
with open("main-OTA.py", "r") as ota_file:
    exec(ota_file.read(), ota_namespace)

ota_namespace["start"]()
_boot_marker("launcher:ota-started")

# Keep a bounded copy of application stdout so an agent can retrieve it over OTA.
try:
    output_tee = _LogWriter(ota_config.STDOUT_LOG, ota_config.STDOUT_LOG_MAX)
    _boot_marker("launcher:stdout-ready")
except Exception as exc:
    _boot_marker("launcher:stdout-error:" + str(exc))

# Keep application code separate so OTA remains available after app failures.
try:
    def _app_print(*args, **kwargs):
        # Keep normal MicroPython print behavior (serial/REPL dupterm), then tee
        # default-output calls to a file because MicroPython may not expose sys.stdout.
        print(*args, **kwargs)
        if kwargs.get("file") is None:
            sep = kwargs.get("sep", " ")
            end = kwargs.get("end", "\n")
            output_tee.write(sep.join(str(value) for value in args) + end)

    app_globals = {"__name__": "__main__", "__file__": "app.py", "print": _app_print}
    with open("app.py", "r") as app_file:
        exec(compile(app_file.read(), "app.py", "exec"), app_globals)
    _boot_marker("launcher:app-finished")
except Exception as exc:
    _boot_marker("launcher:app-error:" + str(exc))
    try:
        sys.print_exception(exc, output_tee)
    except Exception:
        print("application error: " + str(exc))

while True:
    time.sleep(60)
