# Copy this file to ota_config.py and fill in the device-specific values.
WIFI_SSID = "your-wifi-ssid"
WIFI_PASSWORD = "your-wifi-password"
OTA_TOKEN = "generate-a-long-random-token"
HOSTNAME = "esp32-ota"
PORT = 80
WIFI_TIMEOUT_MS = 20000

STDOUT_LOG = "/ota-stdout.log"
STDOUT_LOG_MAX = 32768

# SSD1306 I2C status display. Set DISPLAY_ENABLED = False to disable.
DISPLAY_ENABLED = True
DISPLAY_WIDTH = 128
DISPLAY_HEIGHT = 64
DISPLAY_ADDR = 0x3C
DISPLAY_SCL_PIN = 18
DISPLAY_SDA_PIN = 23
DISPLAY_I2C_ID = 0
DISPLAY_I2C_FREQ = 100000
