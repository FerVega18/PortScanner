"""Tests for the command-line application's report-saving outcome."""

from contextlib import redirect_stdout
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

import main


class MainTests(TestCase):
    @patch("main.SecurityReporter")
    @patch("main.PortScanner")
    def test_failed_report_save_exits_with_error(self, scanner_class, reporter_class):
        """
        Verify that a completed scan reports a failed JSON export to the caller.

        Scenario:
            The scan succeeds, but save_json_report returns None.

        Expected result:
            The console explains that the report was not saved and main exits
            with status 1.
        """
        reporter_class.return_value.save_json_report.return_value = None
        scanner_class.return_value.scan_ports.return_value = []
        scanner_class.return_value.get_summary.return_value = {
            "total_scanned": 1,
            "open_count": 0,
            "closed_count": 1,
            "filtered_count": 0,
            "open_ports_list": [],
        }
        reporter_class.return_value.generate_report.return_value = {}
        output = StringIO()

        with patch("sys.argv", ["main.py", "127.0.0.1"]), \
                patch("main.load_config", return_value={}), \
                redirect_stdout(output):
            with self.assertRaises(SystemExit) as exit_error:
                main.main()

        self.assertEqual(exit_error.exception.code, 1)
        self.assertIn("JSON report could not be saved", output.getvalue())
        self.assertNotIn("Scan completed successfully", output.getvalue())

    @patch("main.SecurityReporter")
    @patch("main.PortScanner")
    def test_successful_report_save_completes_successfully(
        self, scanner_class, reporter_class
    ):
        """
        Verify that a successful JSON export preserves the normal CLI outcome.

        Scenario:
            The scan succeeds and save_json_report returns report.json.

        Expected result:
            main returns normally and prints the successful scan completion
            message.
        """
        reporter_class.return_value.save_json_report.return_value = "report.json"
        scanner_class.return_value.scan_ports.return_value = []
        scanner_class.return_value.get_summary.return_value = {
            "total_scanned": 1,
            "open_count": 0,
            "closed_count": 1,
            "filtered_count": 0,
            "open_ports_list": [],
        }
        reporter_class.return_value.generate_report.return_value = {}
        output = StringIO()

        with patch("sys.argv", ["main.py", "127.0.0.1"]), \
                patch("main.load_config", return_value={}), \
                redirect_stdout(output):
            result = main.main()

        self.assertIsNone(result)
        self.assertIn("Scan completed successfully", output.getvalue())
