"""
reporter.py - Report generation and alert system
Handles JSON output, security alerts, and result formatting
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Create logger for this module
logger = logging.getLogger(__name__)


class SecurityReporter:
    """
    Create scan reports, analyze alerts, and export JSON results.

    Attributes:
        dangerous_ports (Dict[str, Any]): Risk rules from ``config.json``.
        scan_settings (Dict[str, Any]): Scan settings from ``config.json``.
    """
    
    def __init__(self, config: Dict[str, Any]) -> None:
        """
        Initialize the reporter with application configuration.

        Args:
            config (Dict[str, Any]): Parsed configuration mapping.

        Returns:
            None
        """
        self.dangerous_ports: Dict[str, Any] = config.get('dangerous_ports', {})
        self.scan_settings: Dict[str, Any] = config.get('scan_settings', {})

    def generate_report(
        self,
        ip: str,
        scan_results: List[Dict[str, Any]],
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Create a structured report from scan results.

        Combines scan metadata, results, and security analysis into a
        structured dictionary ready for JSON export.

        Args:
            ip (str): Target IPv4 address that was scanned.
            scan_results (List[Dict[str, Any]]): Port results from the scanner.
            summary (Dict[str, Any]): Statistics returned by the scanner.

        Returns:
            Dict[str, Any]: Metadata, statistics, open-port details, and
            security analysis for the scan.

        Raises:
            KeyError: If an open-port result does not contain its port number.
        """
        # Filter to only open ports for security analysis
        open_ports = [r for r in scan_results if r.get('state') == 'open']

        # Identify dangerous ports from open ones
        security_alerts = self._analyze_security_risks(open_ports)

        report = {
            'scan_metadata': {
                'target_ip': ip,
                'scan_timestamp': datetime.now().isoformat(),
                'scanner_version': '1.0.0',
                'tool_name': 'Python Port Scanner'
            },
            'statistics': summary,
            'open_ports_details': open_ports,
            'security_analysis': {
                'alerts': security_alerts,
                'total_risks': len(security_alerts),
                'risk_level': self._calculate_risk_level(security_alerts)
            }
        }
        return report

    def save_json_report(self, report: Dict[str, Any],
                         filename: Optional[str] = None) -> Optional[str]:
        """
        Save the generated report as a JSON file.

        Args:
            report (Dict[str, Any]): Complete report mapping to serialize.
            filename (Optional[str]): Custom path. If omitted, the report is
                saved in the project-level ``reports`` directory.

        Returns:
            Optional[str]: Saved path, or ``None`` if writing fails.

        Raises:
            KeyError: If the default filename is requested and the report lacks
                ``scan_metadata.target_ip``.
        """
        report_directory: Optional[Path] = None
        if filename is None:
            report_directory = Path(__file__).resolve().parent.parent / "reports"
            ip = report['scan_metadata']['target_ip'].replace('.', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = str(report_directory / f"scan_report_{ip}_{timestamp}.json")

        try:
            if report_directory is not None:
                report_directory.mkdir(parents=True, exist_ok=True)

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)

            logger.info(f"Report saved successfully: {filename}")
            print(f"\n Report saved: {filename}")
            return filename

        except PermissionError:
            logger.error(f"Cannot write to {filename}: Permission denied")
            print(f"\n Error: Cannot save report to {filename}. Permission denied.")
            return None
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            print(f"\n Error: {e}")
            return None

    def display_alerts(self, report: Dict[str, Any]) -> None:
        """
        Display the report's security alerts in the console.

        Args:
            report (Dict[str, Any]): Complete scan report.

        Returns:
            None

        Raises:
            KeyError: If the report does not include ``security_analysis.alerts``.
        """
        alerts = report['security_analysis']['alerts']

        if not alerts:
            print("\nNo open ports matched the configured alert rules.")
            return

        risk_level = report['security_analysis']['risk_level']
        risk_icons = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
        icon = risk_icons.get(risk_level, '⚪')

        print(f"\n{icon} SECURITY ALERTS - Risk Level: {risk_level} {icon}")
        print("=" * 60)
        print(f"Found {len(alerts)} potentially dangerous open ports:\n")

        for alert in alerts:
            print(f"⚠️  PORT {alert['port']} - {alert['service']}")
            print(f"   Risk: {alert['risk']}")
            print(f"   Issue: {alert['message']}")
            print(f"   Recommendation: {alert.get('recommendation', 'Review security configuration')}")
            print("-" * 40)

        # Special warning for high-risk findings
        high_risk_count = len([a for a in alerts if a.get('risk') == 'HIGH'])
        if high_risk_count > 0:
            print(f"\n CRITICAL ALERT: {high_risk_count} HIGH-RISK port(s) detected! ")
            print("   Immediate action recommended to mitigate these risks")

    def _analyze_security_risks(
        self, open_ports: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Create alerts for open ports matching configured risk rules.

        Args:
            open_ports (List[Dict[str, Any]]): Open-port scan results.

        Returns:
            List[Dict[str, Any]]: Alert mappings for matching ports.

        Raises:
            KeyError: If an open-port result does not contain ``port``.
        """
        alerts = []

        for port_info in open_ports:
            port_str = str(port_info['port'])

            if port_str in self.dangerous_ports:
                config = self.dangerous_ports[port_str]
                alert = {
                    'port': port_info['port'],
                    'service': config.get('service', 'Unknown'),
                    'risk': config.get('risk', 'MEDIUM'),
                    'message': config.get('message', 'Potentially dangerous service exposed'),
                    'recommendation': self._get_recommendation(port_str)
                }
                alerts.append(alert)

        return alerts

    def _calculate_risk_level(self, alerts: List[Dict[str, Any]]) -> str:
        """
        Determine the aggregate risk level for a set of alerts.

        Args:
            alerts (List[Dict[str, Any]]): Security alerts to evaluate.

        Returns:
            str: ``"HIGH"``, ``"MEDIUM"``, or ``"LOW"``.
        """
        if not alerts:
            return 'LOW'
        if any(alert.get('risk') == 'HIGH' for alert in alerts):
            return 'HIGH'
        if any(alert.get('risk') == 'MEDIUM' for alert in alerts):
            return 'MEDIUM'
        return 'LOW'

    def _get_recommendation(self, port: str) -> str:
        """
        Return a security recommendation for a known port.

        Args:
            port (str): Port number represented as a string.

        Returns:
            str: Recommendation for the port or a general review instruction.
        """
        recommendations = {
            '21': 'Disable FTP and use SFTP or FTPS with encryption',
            '23': 'Disable Telnet and use SSH for remote administration',
            '3306': 'Restrict access by IP, use strong passwords, disable remote root login',
            '3389': 'Use VPN or RDP Gateway, enable Network Level Authentication (NLA)'
        }
        return recommendations.get(port, 'Review security configuration and restrict access')

        
