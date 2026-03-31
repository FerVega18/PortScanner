print("Hola Mundo de la Ciberseguridad ")

"""
main.py - Port Scanner CLI Entry Point
Orchestrates the scanning process by coordinating scanner and reporter modules

Usage:
    python main.py 192.168.1.1
    python main.py 192.168.1.1 --ports 22,80,443
    python main.py 192.168.1.1 --timeout 2.0
"""

import sys
import json
import argparse
import logging
from typing import Optional

# Import our custom modules
from scanner import PortScanner
from reporter import SecurityReporter


def configure_logging(debug_mode: bool = False):
    """
    Configure logging for the entire application.
    
    This should be called ONCE at program startup.
    
    Args:
        debug_mode: If True, show DEBUG level messages and detailed format
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


def load_config(config_file: str = 'config.json') -> dict:
    """
    Load configuration from JSON file.
    
    Args:
        config_file: Path to configuration file
        
    Returns:
        Dictionary with configuration data
        
    Raises:
        SystemExit: If config file not found or invalid
    """
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
        
    except FileNotFoundError:
        print(f" Error: Configuration file '{config_file}' not found")
        print("   Make sure config.json exists in the same directory")
        sys.exit(1)
        
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in {config_file}")
        print(f"   {e}")
        sys.exit(1)


def validate_ip(ip: str) -> bool:
    """
    Validate IPv4 address format.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IPv4 address, False otherwise
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


def parse_ports(ports_str: str) -> list:
    """
    Parse comma-separated port list from command line.
    
    Args:
        ports_str: String like "22,80,443"
        
    Returns:
        List of integers
    """
    try:
        return [int(p.strip()) for p in ports_str.split(',')]
    except ValueError:
        print(f"Error: Invalid port format: {ports_str}")
        print("   Use comma-separated numbers, e.g., 22,80,443")
        sys.exit(1)


def print_banner():
    """Display application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║            PYTHON PORT SCANNER - Security Automation Tool    ║
    ║                   Professional Port Scanner                  ║
    ║                        Version 1.0.0                         ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point for the port scanner application"""
    
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