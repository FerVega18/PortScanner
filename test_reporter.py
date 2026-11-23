"""
Test the RDP alert rule in the JSON report.

These tests load the project's config.json so they can detect changes
to the actual rules used by SecurityReporter. They simulate the port
results that the scanner would pass to the reporter, making both
scenarios reproducible without opening network connections.

Run from the project directory:
    python -m unittest -v test_reporter
"""

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
        config_path = Path(__file__).with_name("config.json")
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
        config_path = Path(__file__).with_name("config.json")
        config = json.loads(config_path.read_text(encoding="utf-8"))
        reporter = SecurityReporter(config)

        results = [{"port": 3389, "state": "closed"}]
        summary = {"total_scanned": 1, "open_count": 0}

        report = reporter.generate_report("127.0.0.1", results, summary)

        self.assertEqual(report["security_analysis"]["alerts"], [])