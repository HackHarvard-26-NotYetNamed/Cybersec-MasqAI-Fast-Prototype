"""`python -m masqai.vault seal | verify | repass | destroy`: see masqai/custody/vault.py."""
import sys

from masqai.custody.vault import main

if __name__ == "__main__":
    sys.exit(main())
