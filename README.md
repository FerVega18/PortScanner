# PortScanner Pro - Security Automation Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-pep8-yellow.svg)](https://www.python.org/dev/peps/pep-0008/)

---

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
|--------|-------------|
| TCP Port Scanning | Scans specified ports with configurable timeouts |
| Risk Assessment | Identifies dangerous ports (FTP, Telnet, MySQL, RDP) |
| JSON Reports | Generates structured, timestamped reports |
| Console Alerts | Color-coded security alerts with recommendations |
| Configurable | External JSON configuration (no code changes needed) |
| Type Hints | Full type annotations for better code documentation |
| Error Handling | Robust exception handling for network failures |

---

## Architecture

This project follows clean architecture principles with clear separation of concerns:

```bash
PortScanner/
├── main.py           # Entry point and orchestrator
├── scanner.py        # Network scanning engine (socket logic)
├── reporter.py       # Report generation and alerts (JSON output)
├── config.json       # External configuration (dangerous ports)
└── README.md         # Documentation
````

### Module Responsibilities

| Module        | Responsibility                              | Knows About                      |
| ------------- | ------------------------------------------- | -------------------------------- |
| `main.py`     | Orchestrates the flow, parses CLI arguments | Nothing about networking or JSON |
| `scanner.py`  | TCP connections, port state detection       | Sockets, but NOT JSON or reports |
| `reporter.py` | JSON output, security alerts                | JSON, but NOT networking         |
| `config.json` | Stores configuration data                   | Pure data, no code               |

**This separation ensures:**

* Maintainability
* Testability
* Readability

---

## Installation

### Prerequisites

* Python 3.8 or higher
* Git (optional)

### Step-by-Step Setup

**1. Clone the repository**

```bash
git clone https://github.com/yourusername/portscanner-pro.git
cd portscanner-pro
```

**2. Verify Python installation**

```bash
python --version
```

**3. No additional dependencies required**

Uses only standard libraries:

* `socket`
* `json`
* `argparse`
* `logging`
* `datetime`

**4. Verify installation**

```bash
python main.py --help
```

---

## Usage

### Basic Syntax

```bash
python main.py <TARGET_IP> [OPTIONS]
```

### Command-Line Options

| Option          | Description                   | Example          |
| --------------- | ----------------------------- | ---------------- |
| `TARGET_IP`     | IP address to scan (required) | `192.168.1.1`    |
| `-p, --ports`   | Comma-separated ports         | `-p 22,80,443`   |
| `-t, --timeout` | Timeout in seconds            | `-t 2.0`         |
| `-o, --output`  | Output filename               | `-o report.json` |
| `--debug`       | Debug logging                 | `--debug`        |
| `-h, --help`    | Help menu                     | `-h`             |

### Quick Start Examples

```bash
# Scan common ports
python main.py 192.168.1.1

# Scan specific ports
python main.py 192.168.1.1 -p 22,80,443,3306

# Custom timeout
python main.py 192.168.1.1 -t 2.5

# Debug mode
python main.py 127.0.0.1 --debug

# Custom output
python main.py 192.168.1.1 -o security_audit.json
```

---

## Examples

### Example 1: Scanning Localhost

```bash
$ python main.py 127.0.0.1

Target: 127.0.0.1
Scanning common ports: [21, 22, 23, 80, 443, 3306, 3389]
Timeout: 1.0 seconds

Scan completed. Open ports found: 2

Open ports found: [22, 80]

Report saved: scan_report_127_0_0_1_20260330_171530.json
```

---

### Example 2: Detecting Dangerous Ports

```bash
$ python main.py 192.168.1.100

SECURITY ALERTS - Risk Level: HIGH

PORT 21 - FTP
Risk: HIGH
Issue: FTP transmits credentials in plain text
Recommendation: Use SFTP or FTPS

PORT 3389 - RDP
Risk: HIGH
Issue: Remote Desktop exposed
Recommendation: Use VPN or enable NLA
```

---

## Configuration

All configuration is stored in `config.json`.

### Default Configuration

```json
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
```

---

## Output

### JSON Report Structure

```json
{
  "scan_metadata": {
    "target_ip": "192.168.1.1",
    "scan_timestamp": "2026-03-30T17:15:30",
    "scanner_version": "1.0.0"
  },
  "statistics": {
    "total_scanned": 7,
    "open_count": 2
  }
}
```

### Filename Convention

```
scan_report_<IP>_<YYYYMMDD_HHMMSS>.json
```

---

## Security Best Practices

### Ethical Guidelines

| DO                   | DON'T                     |
| -------------------- | ------------------------- |
| Scan systems you own | Scan without permission   |
| Test your network    | Attack production systems |
| Use in CTF           | Unauthorized recon        |

### Legal Considerations

Unauthorized port scanning may violate laws and policies.

**Always obtain permission before scanning.**

---

## Roadmap

### Version 1.1

* Multi-threading
* IP range scanning
* Banner grabbing

### Version 2.0

* OS fingerprinting
* Vulnerability integration
* Web dashboard

---

## Author

**María Fernanda Quesada Vega**

* Cybersecurity Enthusiast
* Python Developer

---

## License

MIT License - see `LICENSE`

---

**Made with Python and Security in mind**

```

Si quieres, puedo ayudarte a dejarlo aún más “pro nivel GitHub” (con badges reales, screenshots, demo GIF, etc.).
```

