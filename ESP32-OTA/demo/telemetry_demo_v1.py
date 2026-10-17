"""Demo sensor service with an intentional first-run calibration bug."""

import time


DEVICE_NAME = "greenhouse-01"
SAMPLE_COUNT = 5


def read_temperature_celsius():
    # Simulates a sensor returning centi-degrees.
    return 2345


def run():
    print("DEBUG START telemetry-demo v1")
    print("device=%s samples=%d" % (DEVICE_NAME, SAMPLE_COUNT))
    for index in range(SAMPLE_COUNT):
        raw = read_temperature_celsius()
        # Intentional defect for the debugging exercise: raw is centi-degrees.
        temperature = raw
        print("sample=%d raw=%d temperature_c=%.2f" % (index, raw, temperature))
        time.sleep_ms(50)
    print("DEBUG END telemetry-demo v1")


run()
