# OTA telemetry debug demonstration

This demo represents a small sensor application. Version 1 reports a centi-degree sensor value as degrees Celsius. The agent installs it as `/app.py`, reboots the board over OTA, downloads `/ota-stdout.log`, identifies the bad value, uploads version 2, reboots again, and verifies the corrected output.
