import subprocess
import sys


def test_local_diagnostic():
    result = subprocess.run([sys.executable, "diagnose.py"], capture_output=True, text=True, check=True)
    assert "healthy" in result.stdout
