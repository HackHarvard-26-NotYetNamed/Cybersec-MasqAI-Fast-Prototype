from __future__ import annotations

import json
import sys
import threading
import unittest
from argparse import Namespace
from http.client import HTTPConnection, HTTPException
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[1]))
from scripts.enroll_lan_device import Enrollment


class FakeClient:
    def __init__(self) -> None:
        self.info = {"state": "ENROLL"}
        self.calls = 0

    def enroll_begin(self):
        return {"state": "ENROLL"}, "123456"

    def close(self):
        pass


class EnrollmentConfirmation(unittest.TestCase):
    def setUp(self) -> None:
        self.args = Namespace(board="127.0.0.1", control_port=0, workspace="workspace",
                              device_id="esp32-12345678", pairing_file="ignored")
        self.client = FakeClient()
        with patch("scripts.enroll_lan_device.D.DeviceClient", return_value=self.client), \
             patch("scripts.enroll_lan_device.D.open_transport", return_value=object()):
            self.enrollment = Enrollment(self.args)
        def enroll():
            self.enrollment.enrolled = True
            self.enrollment.pairing = SimpleNamespace(device_id=self.args.device_id)
            self.enrollment.pairing_path = Path("pairing.test")
        self.enrollment.enroll = enroll
        self.enrollment.httpd.timeout = 0.05
        self.thread = threading.Thread(target=self.enrollment.httpd.handle_request, daemon=True)
        self.thread.start()
        self.base = self.enrollment.httpd.server_address

    def tearDown(self) -> None:
        self.enrollment.httpd.server_close()

    def post(self, payload: dict) -> int:
        connection = HTTPConnection(*self.base, timeout=2)
        raw = json.dumps(payload)
        connection.request("POST", "/confirm", raw, {"Content-Type": "application/json"})
        response = connection.getresponse()
        response.read()
        connection.close()
        return response.status

    def test_mismatch_does_not_enroll(self):
        status = self.post({"code": "000000", "confirmation": self.enrollment.confirmation})
        self.assertEqual(status, 403)
        self.assertFalse(getattr(self.enrollment, "enrolled", False))

    def test_wrong_session_nonce_does_not_enroll(self):
        status = self.post({"code": self.enrollment.code, "confirmation": "wrong"})
        self.assertEqual(status, 403)
        self.assertFalse(getattr(self.enrollment, "enrolled", False))

    def test_exact_active_challenge_enrolls(self):
        status = self.post({"code": self.enrollment.code, "confirmation": self.enrollment.confirmation})
        self.assertEqual(status, 200)
        self.assertTrue(self.enrollment.enrolled)


if __name__ == "__main__":
    unittest.main()
