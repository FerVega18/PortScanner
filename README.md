# PortScanner Pro - Security Automation Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-pep8-yellow.svg)](https://www.python.org/dev/peps/pep-0008/)

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Configuration](#configuration)
- [Output](#output)
- [Security Best Practices](#security-best-practices)
- [Roadmap](#roadmap)
- [Author](#author)

---

## Overview

**PortScanner Pro** is a professional-grade TCP port scanning tool written in Python. It identifies open ports on target systems, evaluates security risks, and generates structured JSON reports with actionable security alerts.

### Why This Tool Matters

In cybersecurity, reconnaissance is the first and most critical phase of any security assessment. Before an attacker can exploit a system, they must find open doors (ports). This tool automates that discovery process and helps security professionals:

- Identify exposed services before attackers do
- Audit internal networks for compliance
- Generate structured reports for documentation
- Learn networking fundamentals through clean, documented code

### Key Differentiators

Unlike simple port scanners, this tool:
- Prioritizes security with built-in risk assessment
- Produces professional reports in JSON format
- Follows clean architecture principles (separation of concerns)
- Includes comprehensive documentation for learning

---

## Features

| Feature | Description |
|---------|-------------|
| TCP Port Scanning | Scans specified ports with configurable timeouts |
| Risk Assessment | Identifies dangerous ports (FTP, Telnet, MySQL, RDP) |
| JSON Reports | Generates structured, timestamped reports |
| Console Alerts | Color-coded security alerts with recommendations |
| Configurable | External JSON configuration (no code changes needed) |
| Type Hints | Full type annotations for better code documentation |
| Error Handling | Robust exception handling for network failures |

---

## Architecture

### Module Responsibilities

| Module | Responsibility | Knows About |
|--------|---------------|-------------|
| `main.py` | Orchestrates the flow, parses CLI arguments | Nothing about networking or JSON |
| `scanner.py` | TCP connections, port state detection | Sockets, but NOT JSON or reports |
| `reporter.py` | JSON output, security alerts | JSON, but NOT networking |
| `config.json` | Stores configuration data | Pure data, no code |

**This separation ensures:**
- Maintainability - change one module without breaking others
- Testability - each module can be tested independently
- Readability - clear purpose for each file

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Git (optional, for cloning)

### Step-by-Step Setup

**1. Clone the repository**
git clone https://github.com/yourusername/portscanner-pro.git
cd portscanner-pro


**2. Verify Python installation**
python --version
# Should output: Python 3.8+


**3. No additional dependencies required**  
This tool uses only Python standard libraries:
- `socket` - for network connections
- `json` - for configuration and reports
- `argparse` - for command-line interface
- `logging` - for debug and error tracking
- `datetime` - for timestamps

**4. Verify the installation**
python main.py --help


---

## Usage

### Basic Syntax
python main.py <TARGET_IP> [OPTIONS]


### Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `TARGET_IP` | IP address to scan (required) | `192.168.1.1` |
| `-p, --ports` | Comma-separated ports to scan | `-p 22,80,443` |
| `-t, --timeout` | Connection timeout in seconds | `-t 2.0` |
| `-o, --output` | Custom output filename | `-o report.json` |
| `--debug` | Enable debug logging | `--debug` |
| `-h, --help` | Show help menu | `-h` |

### Quick Start Examples

# Scan common ports (from config.json)
python main.py 192.168.1.1

# Scan specific ports
python main.py 192.168.1.1 -p 22,80,443,3306

# Scan with custom timeout (slower networks)
python main.py 192.168.1.1 -t 2.5

# Scan with debug output (for troubleshooting)
python main.py 127.0.0.1 --debug

# Save report with custom name
python main.py 192.168.1.1 -o security_audit.json


---

## Examples

### Example 1: Scanning Localhost


$ python main.py 127.0.0.1

    ╔══════════════════════════════════════════════════════════════╗
    ║     PYTHON PORT SCANNER - Security Automation Tool           ║
    ║                   Professional Port Scanner                  ║
    ║                        Version 1.0.0                         ║
    ╚══════════════════════════════════════════════════════════════╝

Target: 127.0.0.1
Scanning common ports: [21, 22, 23, 80, 443, 3306, 3389]
Timeout: 1.0 seconds

Scanning 127.0.0.1 - 7 ports to check...
--------------------------------------------------
Progress: 7/7 - Checking port 3389...
==================================================
Scan completed. Open ports found: 2
==================================================

SECURITY ALERTS: No dangerous ports detected
System appears secure based on known vulnerable ports

Report saved: scan_report_127_0_0_1_20260330_171530.json

==================================================
SCAN SUMMARY
==================================================
Total ports scanned: 7
Open ports: 2
Closed ports: 3
Filtered ports: 2

Open ports found: [22, 80]

Scan completed successfully


### Example 2: Detecting Dangerous Ports


$ python main.py 192.168.1.100

SECURITY ALERTS - Risk Level: HIGH
============================================================
Found 2 potentially dangerous open ports:

PORT 21 - FTP
   Risk: HIGH
   Issue: FTP transmits credentials in plain text
   Recommendation: Disable FTP and use SFTP or FTPS with encryption
----------------------------------------
PORT 3389 - RDP
   Risk: HIGH
   Issue: Remote Desktop exposed to network
   Recommendation: Use VPN or RDP Gateway, enable NLA
----------------------------------------

CRITICAL ALERT: 2 HIGH-RISK port(s) detected
   Immediate action recommended to mitigate these risks
```

---

## Configuration

All configuration is stored in `config.json`. You can modify it without touching the code.

### Default Configuration


{
    "dangerous_ports": {
        "21": {
            "service": "FTP",
            "risk": "HIGH",
            "message": "FTP transmits credentials in plain text"
        },
        "23": {
            "service": "Telnet",
            "risk": "HIGH",
            "message": "Telnet is completely insecure"
        },
        "3306": {
            "service": "MySQL",
            "risk": "MEDIUM",
            "message": "Database exposed to network"
        }
    },
    "scan_settings": {
        "common_ports": [21, 22, 23, 80, 443, 3306, 3389],
        "default_timeout": 1.0
    }
}


### Customizing Your Scanner

1. **Add new dangerous ports** → Add entries under `dangerous_ports`
2. **Change default ports** → Modify the `common_ports` array
3. **Adjust timeout** → Change `default_timeout` value

---

## Output

### JSON Report Structure

Each scan generates a JSON file with this structure:


{
    "scan_metadata": {
        "target_ip": "192.168.1.1",
        "scan_timestamp": "2026-03-30T17:15:30.123456",
        "scanner_version": "1.0.0",
        "tool_name": "Python Port Scanner"
    },
    "statistics": {
        "total_scanned": 7,
        "open_count": 2,
        "closed_count": 3,
        "filtered_count": 2,
        "open_ports_list": [22, 80]
    },
    "open_ports_details": [
        {
            "port": 22,
            "state": "open",
            "service": "ssh"
        }
    ],
    "security_analysis": {
        "alerts": [],
        "total_risks": 0,
        "risk_level": "LOW"
    }
}

### Filename Convention
Reports are automatically named: `scan_report_<IP>_<YYYYMMDD_HHMMSS>.json`

---

## Security Best Practices

**IMPORTANT: Use Responsibly**

This tool is designed for authorized security assessments only.

### Ethical Guidelines

| DO | DON'T |
|----|-------|
| Scan systems you own | Scan systems without permission |
| Test your own network | Attack production systems |
| Use in CTF competitions | Use for unauthorized reconnaissance |
| Document findings properly | Share results without authorization |

### Legal Considerations

Unauthorized port scanning may violate:
- Computer Fraud and Abuse Act (CFAA) in the US
- Similar laws in other jurisdictions
- Terms of Service of cloud providers
- Corporate security policies

**Always obtain written permission before scanning any system you don't own.**

---

## Roadmap

### Version 1.0 (Current)
- TCP port scanning with socket library
- JSON configuration for dangerous ports
- Structured JSON report generation
- Console alerts with risk assessment
- Type hints and comprehensive documentation

### Version 1.1 (Planned)
- Multi-threading for faster scans
- IP range scanning (CIDR notation)
- Service version detection (banner grabbing)
- CSV export option
- Progress bar visualization

### Version 2.0 (Future)
- OS fingerprinting
- Vulnerability database integration
- Web dashboard for reports
- Scheduled scans
- Email alerts for critical findings

---

## Author

**María Fernanda Quesada Vega**

- Cybersecurity Professional
- Python Automation Specialist
- [GitHub Profile](https://github.com/FerVega18)
- [LinkedIn Profile](https://www.linkedin.com/in/mar%C3%ADa-fernanda-quesada-vega-44652b302/)

### Why This Project?

This tool demonstrates:
- Deep understanding of network protocols (TCP/IP)
- Proficiency in Python automation and clean architecture
- Knowledge of security best practices and risk assessment
- Ability to write production-ready, documented code

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with Python and Security in mind**


