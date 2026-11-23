"""
portscanner/cli.py - Port Scanner command-line interface
Coordinates argument parsing, scanning, and report generation.

Usage:
    python main.py 192.168.1.1
    python main.py 192.168.1.1 --ports 22,80,443
    python main.py 192.168.1.1 --timeout 2.0
"""

import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import the scanner and reporter from this package.
from .scanner import PortScanner
from .reporter import SecurityReporter


def configure_logging(debug_mode: bool = False) -> None:
    """
    Configure application-wide logging.

    Args:
        debug_mode (bool): Whether to show DEBUG messages and detailed logs.

    Returns:
        None
    """
    if debug_mode:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format='%(levelname)s: %(message)s'
        )


def load_config(config_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from a JSON file.

    Args:
        config_file (Optional[str]): Optional configuration path. Defaults to
            config.json next to this module.

    Returns:
        Dict[str, Any]: The parsed configuration.

    Raises:
        SystemExit: If the configuration file is missing or contains invalid JSON.
        PermissionError: If the current process cannot read the configuration file.
    """
    config_path = (
        Path(config_file)
        if config_file is not None
        else Path(__file__).resolve().with_name("config.json")
    )

    try:
        with config_path.open('r', encoding='utf-8') as f:
            config = json.load(f)
        return config
        
    except FileNotFoundError:
        print(f" Error: Configuration file '{config_path}' not found")
        print("   Make sure portscanner/config.json exists")
        sys.exit(1)
        
    except json.JSONDecodeError as e:
        print(f" Error: Invalid JSON in {config_path}")
        print(f"   {e}")
        sys.exit(1)


def validate_ip(ip: str) -> bool:
    """
    Validate an IPv4 address.

    Args:
        ip (str): Address string to validate.

    Returns:
        bool: True if the string contains four integer octets from 0 to 255.
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except ValueError:
        return False


def parse_ports(ports_str: str) -> List[int]:
    """
    Parse and validate a comma-separated list of TCP ports.

    Args:
        ports_str (str): Port list such as ``"22,80,443"``.

    Returns:
        List[int]: Port numbers, each between 1 and 65535.

    Raises:
        SystemExit: If a value is not an integer or is outside the valid range.
    """
    try:
        ports = [int(p.strip()) for p in ports_str.split(',')]
    except ValueError:
        print(f"Error: Invalid port format: {ports_str}")
        print("   Use comma-separated numbers, e.g., 22,80,443")
        sys.exit(1)

    if any(port < 1 or port > 65535 for port in ports):
        print("Error: Ports must be in the range 1–65535.")
        sys.exit(1)

    return ports


def print_banner() -> None:
    """
    Display the PortScanner command-line banner.

    Returns:
        None
    """
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║            PYTHON PORT SCANNER - Security Automation Tool    ║
    ║                   Professional Port Scanner                  ║
    ║                        Version 1.0.0                         ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main() -> None:
    """
    Run the port scanner command-line application.

    A completed scan still returns an error if its JSON report cannot be
    saved, so users know the requested output was not produced.

    Returns:
        None

    Raises:
        SystemExit: If arguments, the target IP, the scan, or report saving fails.
    """
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Professional TCP port scanner with security alerts',
        epilog='Example: python main.py 192.168.1.1 --ports 22,80,443'
    )
    
    parser.add_argument(
        'ip',
        help='Target IP address (e.g., 192.168.1.1)'
    )
    
    parser.add_argument(
        '-p', '--ports',
        help='Comma-separated ports to scan (e.g., 22,80,443). If not provided, uses common ports from config.json'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=None,
        help='Connection timeout in seconds (default: from config.json or 1.0)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Custom output filename for JSON report'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging (shows detailed connection attempts)'
    )
    
    args = parser.parse_args()
    
    # Configure logging
    configure_logging(args.debug)
    logger = logging.getLogger(__name__)
    
    # Display banner
    print_banner()
    
    # Validate IP address
    if not validate_ip(args.ip):
        print(f"Error: '{args.ip}' is not a valid IPv4 address")
        print("   Format should be: XXX.XXX.XXX.XXX (each part 0-255)")
        sys.exit(1)
    
    print(f"Target: {args.ip}")
    
    # Load configuration
    config = load_config()
    logger.debug("Configuration loaded successfully")
    
    # Determine ports to scan
    if args.ports:
        ports = parse_ports(args.ports)
        print(f"Scanning custom ports: {ports}")
    else:
        ports = config.get('scan_settings', {}).get('common_ports', [21, 22, 80, 443])
        print(f"Scanning common ports: {ports}")
        print("   (Use -p to specify custom ports)")
    
    # Determine timeout
    if args.timeout is None:
        timeout = config.get('scan_settings', {}).get('default_timeout', 1.0)
    else:
        timeout = args.timeout
    
    print(f"⏱ Timeout: {timeout} seconds\n")
    
    # Initialize scanner and perform scan
    scanner = PortScanner(timeout=timeout)
    
    try:
        scan_results = scanner.scan_ports(args.ip, ports)
        summary = scanner.get_summary()
        logger.info(f"Scan completed. Found {summary['open_count']} open ports")
        
    except KeyboardInterrupt:
        print("\n\n Scan interrupted by user")
        logger.info("Scan cancelled by user")
        sys.exit(0)
        
    except Exception as e:
        print(f"\nScan failed: {e}")
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)
    
    # Generate and save report
    reporter = SecurityReporter(config)
    report = reporter.generate_report(args.ip, scan_results, summary)
    
    # Display security alerts
    reporter.display_alerts(report)
    
    # Save JSON report
    saved_file = reporter.save_json_report(report, args.output)
    # A completed scan is only a successful CLI run if its report is saved.
    if saved_file is None:
        print("\nError: Scan completed, but the JSON report could not be saved.")
        logger.error("Scan completed, but the JSON report could not be saved")
        sys.exit(1)
    
    # Final summary
    print("\n" + "=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)
    print(f"Total ports scanned: {summary['total_scanned']}")
    print(f"Open ports: {summary['open_count']}")
    print(f"Closed ports: {summary['closed_count']}")
    print(f"Filtered ports: {summary['filtered_count']}")
    
    if summary['open_ports_list']:
        print(f"\nOpen ports found: {summary['open_ports_list']}")
    
    print("\n Scan completed successfully ")
    logger.info("Application finished successfully")


if __name__ == "__main__":
    main()