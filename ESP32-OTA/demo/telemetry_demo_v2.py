"""Fixed demo sensor service with correct centi-degree conversion."""

import time


DEVICE_NAME = "greenhouse-01"
SAMPLE_COUNT = 5


def read_temperature_celsius():
    return 2345


def run():
    print("DEBUG START telemetry-demo v2")
    print("device=%s samples=%d" % (DEVICE_NAME, SAMPLE_COUNT))
    for index in range(SAMPLE_COUNT):
        raw = read_temperature_celsius()
        temperature = raw / 100
        print("sample=%d raw=%d temperature_c=%.2f" % (index, raw, temperature))
        time.sleep_ms(50)
    print("DEBUG END telemetry-demo v2")


run()
