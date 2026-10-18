"""`python -m masqai.device enroll | status | unpair --port COM5`: see masqai/custody/device.py."""
import sys

from masqai.custody.device import main

if __name__ == "__main__":
    sys.exit(main())
