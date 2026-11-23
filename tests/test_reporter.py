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

from reporter import SecurityReporter


class SecurityReporterTests(unittest.TestCase):
    """
    Verify how the reporter applies the configured RDP alert rule.

    Both tests use TCP port 3389. One supplies an open result to check
    that the rule produces an alert. The other supplies a closed result
    to check that the reporter filters it out before applying the rule.
    """

    def test_open_rdp_port_generates_alert(self):
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
        """
        config_path = Path(__file__).resolve().parent.parent / "config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        reporter = SecurityReporter(config)

        results = [{"port": 3389, "state": "open"}]
        summary = {"total_scanned": 1, "open_count": 1}

        report = reporter.generate_report("127.0.0.1", results, summary)
        alerts = report["security_analysis"]["alerts"]

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["port"], 3389)
        self.assertEqual(alerts[0]["service"], "RDP")

    def test_closed_rdp_port_does_not_generate_alert(self):
        """
        Verify that a closed port 3389 leaves the alert list empty.

        Scenario:
            The reporter receives one simulated result for port 3389.
            The result is marked as closed and the summary reports zero
            open ports.

        Expected result:
            The security analysis contains an empty alert list because
            the reporter applies alert rules only to open ports.
        """
        config_path = Path(__file__).resolve().parent.parent / "config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        reporter = SecurityReporter(config)

        results = [{"port": 3389, "state": "closed"}]
        summary = {"total_scanned": 1, "open_count": 0}

        report = reporter.generate_report("127.0.0.1", results, summary)

        self.assertEqual(report["security_analysis"]["alerts"], [])

    def test_no_alerts_message_describes_rule_matches(self):
        """
        Verify the console message for a report with no alerts.

        Scenario:
            The reporter displays a report whose alert list is empty.

        Expected result:
            The message explains that no open ports matched the
            configured alert rules.
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

    def test_save_json_report_preserves_statistics_and_alerts(self):
        """
        Verify that an exported JSON report preserves its contents.

        Scenario:
            The reporter saves a sample report with statistics and an
            RDP alert to a file in a temporary directory.

        Expected result:
            The method returns the requested path, and reading the JSON
            file reconstructs the original report dictionary.
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

    def test_save_json_report_returns_none_when_write_fails(self):
        """
        Verify how the reporter signals a failed JSON export.

        Scenario:
            The destination file is inside a parent directory that
            does not exist, so opening the file for writing fails.

        Expected result:
            The method returns None to signal that the report was not saved.
        """
        reporter = SecurityReporter({})

        with TemporaryDirectory() as directory:
            output_path = Path(directory) / "missing" / "report.json"
            saved_path = reporter.save_json_report({}, str(output_path))

        self.assertIsNone(saved_path)