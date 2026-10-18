import unittest
from report import build_report


class ReportTests(unittest.TestCase):
    def test_report_has_incident_lines(self):
        self.assertIn("incident lines: 3", build_report())


if __name__ == "__main__":
    unittest.main()
