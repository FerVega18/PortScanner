"""
Test the RDP alert rule in the JSON report.

These tests load the project's config.json so they can detect changes
to the actual rules used by SecurityReporter. They simulate the port
results that the scanner would pass to the reporter, making both
scenarios reproducible without opening network connections.

Run from the project directory:
    python -m unittest discover -s tests -v
"""
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from portscanner.reporter import SecurityReporter


class SecurityReporterTests(unittest.TestCase):
    """
    Verify alert generation, console output, and JSON report persistence.

    The tests use simulated scan results and temporary paths so they do not
    require network access or leave generated reports in the project.
    """

    def test_open_rdp_port_generates_alert(self) -> None:
        """
        Verify that an open port 3389 produces an RDP alert.

        Scenario:
            The project configuration contains a rule for port 3389.
            The reporter receives one simulated result marked as open.

        Expected result:
            The report contains exactly one alert. The alert identifies
            port 3389 and uses the configured service label, RDP.

        Regression covered:
            If the RDP rule is removed from config.json, the reporter
            produces an empty alert list and this test fails.

        Returns:
            None
        """
        config_path = (
            Path(__file__).resolve().parent.parent / "portscanner" / "config.json"
        )
        config = json.loads(config_path.read_text(encoding="utf-8"))
        reporter = SecurityReporter(config)

        results = [{"port": 3389, "state": "open"}]
        summary = {"total_scanned": 1, "open_count": 1}

        report = reporter.generate_report("127.0.0.1", results, summary)
        alerts = report["security_analysis"]["alerts"]

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["port"], 3389)
        self.assertEqual(alerts[0]["service"], "RDP")

    def test_closed_rdp_port_does_not_generate_alert(self) -> None:
        """
        Verify that a closed port 3389 leaves the alert list empty.

        Scenario:
            The reporter receives one simulated result for port 3389.
            The result is marked as closed and the summary reports zero
            open ports.

        Expected result:
            The security analysis contains an empty alert list because
            the reporter applies alert rules only to open ports.

        Returns:
            None
        """
        config_path = (
            Path(__file__).resolve().parent.parent / "portscanner" / "config.json"
        )
        config = json.loads(config_path.read_text(encoding="utf-8"))
        reporter = SecurityReporter(config)

        results = [{"port": 3389, "state": "closed"}]
        summary = {"total_scanned": 1, "open_count": 0}

        report = reporter.generate_report("127.0.0.1", results, summary)

        self.assertEqual(report["security_analysis"]["alerts"], [])

    def test_no_alerts_message_describes_rule_matches(self) -> None:
        """
        Verify the console message for a report with no alerts.

        Scenario:
            The reporter displays a report whose alert list is empty.

        Expected result:
            The message explains that no open ports matched the
            configured alert rules.

        Returns:
            None
        """
        reporter = SecurityReporter({})
        report = {"security_analysis": {"alerts": []}}
        output = StringIO()

        with redirect_stdout(output):
            reporter.display_alerts(report)

        self.assertIn(
            "No open ports matched the configured alert rules.",
            output.getvalue(),
        )

    def test_save_json_report_preserves_statistics_and_alerts(self) -> None:
        """
        Verify that an exported JSON report preserves its contents.

        Scenario:
            The reporter saves a sample report with statistics and an
            RDP alert to a file in a temporary directory.

        Expected result:
            The method returns the requested path, and reading the JSON
            file reconstructs the original report dictionary.

        Returns:
            None
        """
        reporter = SecurityReporter({})
        report = {
            "statistics": {"total_scanned": 1, "open_count": 1},
            "security_analysis": {
                "alerts": [{"port": 3389, "service": "RDP", "risk": "HIGH"}],
                "total_risks": 1,
                "risk_level": "HIGH",
            },
        }

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.json"
            saved_path = reporter.save_json_report(report, str(output_path))

            self.assertEqual(saved_path, str(output_path))
            saved_report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(saved_report, report)

    def test_save_json_report_uses_reports_directory_by_default(self) -> None:
        """
        Verify that the default export is placed in the project's reports folder.

        Scenario:
            The reporter receives no custom filename and its module is located
            in a temporary project structure.

        Expected result:
            It creates reports/ and saves the generated JSON file there.

        Returns:
            None
        """
        reporter = SecurityReporter({})
        report = {
            "scan_metadata": {"target_ip": "127.0.0.1"},
            "statistics": {},
            "security_analysis": {"alerts": []},
        }

        with TemporaryDirectory() as directory:
            module_path = Path(directory) / "portscanner" / "reporter.py"
            with patch("portscanner.reporter.__file__", str(module_path)):
                saved_path = reporter.save_json_report(report)

            expected_directory = Path(directory) / "reports"
            self.assertEqual(Path(saved_path).parent, expected_directory)
            self.assertTrue(Path(saved_path).is_file())

    def test_save_json_report_returns_none_when_write_fails(self) -> None:
        """
        Verify how the reporter signals a failed JSON export.

        Scenario:
            The destination file is inside a parent directory that
            does not exist, so opening the file for writing fails.

        Expected result:
            The method returns None to signal that the report was not saved.

        Returns:
            None
        """
        reporter = SecurityReporter({})

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "missing" / "report.json"
            saved_path = reporter.save_json_report({}, str(output_path))

        self.assertIsNone(saved_path)