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

    @patch("main.PortScanner")
    @patch("main.load_config", return_value={})
    def test_out_of_range_ports_are_rejected_before_scan(
        self, load_config, scanner_class
    ):
        """
        Verify that the CLI rejects ports outside the supported range.

        Scenario:
            The user supplies port 0 or 65536 through --ports.

        Expected result:
            The command exits with status 1, explains the valid range,
            and stops before creating a scanner.
        """
        for port in ("0", "65536"):
            with self.subTest(port=port):
                output = StringIO()
                args = ["main.py", "127.0.0.1", "--ports", port]
                with patch("sys.argv", args), redirect_stdout(output):
                    with self.assertRaises(SystemExit) as exit_error:
                        main.main()

                self.assertEqual(exit_error.exception.code, 1)
                self.assertIn("1–65535", output.getvalue())

        scanner_class.assert_not_called()

    def test_port_range_accepts_both_boundaries(self):
        """
        Verify that parsing accepts the first and last supported ports.

        Scenario:
            The user supplies a comma-separated list containing 1 and 65535.

        Expected result:
            The parser returns both boundary ports as integers.
        """
        self.assertEqual(main.parse_ports("1,65535"), [1, 65535])
