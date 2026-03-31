"""
reporter.py - Report generation and alert system
Handles JSON output, security alerts, and result formatting
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any

# Create logger for this module
logger = logging.getLogger(__name__)


class SecurityReporter:
    """
    Generates formatted reports and security alerts from scan results.
    
    This class handles all output-related operations: creating JSON reports,
    displaying console alerts for dangerous ports, and saving results to disk.

    Attributes:
        dangerous_ports (dict): Configuration of high-risk ports from config.json
        scan_settings (dict): Scan configuration settings
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize reporter with configuration data.

        Args:
            config: Loaded configuration dictionary from config.json
        """
        self.dangerous_ports = config.get('dangerous_ports', {})
        self.scan_settings = config.get('scan_settings', {})

    def generate_report(self, ip: str, scan_results: List[Dict], 
                        summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a structured report from scan results.

        Combines scan metadata, results, and security analysis into a
        structured dictionary ready for JSON export.

        Args:
            ip: Target IP address that was scanned
            scan_results: List of dictionaries with port scan results
            summary: Summary statistics from the scanner

        Returns:
            Complete report dictionary with all scan information
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
                         filename: str = None) -> str:
        """
        Save the generated report as a JSON file.

        Args:
            report: The report dictionary to save
            filename: Optional custom filename. If not provided, auto-generates

        Returns:
            The path to the saved JSON file
        """
        if filename is None:
            # Generate filename: scan_report_IP_YYYYMMDD_HHMMSS.json
            ip = report['scan_metadata']['target_ip'].replace('.', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scan_report_{ip}_{timestamp}.json"

        try:
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

    def display_alerts(self, report: Dict[str, Any]):
        """
        Show security alerts in the console.

        Displays formatted alerts for any dangerous ports found during scanning.

        Args:
            report: Complete report dictionary
        """
        alerts = report['security_analysis']['alerts']

        if not alerts:
            print("\n SECURITY ALERTS: No dangerous ports detected")
            print(" System appears secure based on known vulnerable ports")
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

    def _analyze_security_risks(self, open_ports: List[Dict]) -> List[Dict]:
        """
        Identify dangerous ports from the list of open ports.

        Args:
            open_ports: List of dictionaries with open port details

        Returns:
            List of security alerts with details
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

    def _calculate_risk_level(self, alerts: List[Dict]) -> str:
        """
        Determine overall risk level based on found alerts.

        Args:
            alerts: List of security alerts

        Returns:
            Risk level string: 'HIGH', 'MEDIUM', or 'LOW'
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
        Get specific security recommendations for a port.

        Args:
            port: Port number as string

        Returns:
            Recommendation text
        """
        recommendations = {
            '21': 'Disable FTP and use SFTP or FTPS with encryption',
            '23': 'Disable Telnet and use SSH for remote administration',
            '3306': 'Restrict access by IP, use strong passwords, disable remote root login',
            '3389': 'Use VPN or RDP Gateway, enable Network Level Authentication (NLA)'
        }
        return recommendations.get(port, 'Review security configuration and restrict access')

        
