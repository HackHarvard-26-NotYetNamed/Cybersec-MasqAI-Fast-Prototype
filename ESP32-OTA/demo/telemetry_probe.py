"""OTA-only probe to check app execution and MicroPython stdout capture."""

with open("/ota-probe.marker", "w") as marker:
    marker.write("app executed\n")
print("STDOUT PROBE: print reached application")
with open("/ota-probe.direct", "w") as direct:
    direct.write("direct file write succeeded\n")
