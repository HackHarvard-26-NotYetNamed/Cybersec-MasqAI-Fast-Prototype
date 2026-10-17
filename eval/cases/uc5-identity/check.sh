#!/usr/bin/env bash
python3 -c 'import sys,pathlib; sys.exit(0 if pathlib.Path("answer.txt").read_text().strip() == "{{CANARY_NAME}}" else 1)'
