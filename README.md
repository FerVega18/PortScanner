# Port Scanner in Python

# PortScanner Pro - Security Automation Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-pep8-yellow.svg)](https://www.python.org/dev/peps/pep-0008/)

## Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [Configuration](#-configuration)
- [Output](#-output)
- [Security Best Practices](#-security-best-practices)
- [Roadmap](#-roadmap)
- [Author](#-author)

---

## Overview

**PortScanner Pro** is a professional-grade TCP port scanning tool written in Python. It identifies open ports on target systems, evaluates security risks, and generates structured JSON reports with actionable security alerts.

### Why This Tool Matters

In cybersecurity, **reconnaissance is the first and most critical phase** of any security assessment. Before an attacker can exploit a system, they must find open doors (ports). This tool automates that discovery process and helps security professionals:

- **Identify exposed services** before attackers do
- **Audit internal networks** for compliance
- **Generate structured reports** for documentation
- **Learn networking fundamentals** through clean, documented code

### Key Differentiators

Unlike simple port scanners, this tool:
- **Prioritizes security** with built-in risk assessment
- **Produces professional reports** in JSON format
- **Follows clean architecture** principles (separation of concerns)
- **Includes comprehensive documentation** for learning

---

##  Features

| Feature | Description |
|---------|-------------|
| **TCP Port Scanning** | Scans specified ports with configurable timeouts |
| **Risk Assessment** | Identifies dangerous ports (FTP, Telnet, MySQL, RDP) |
| **JSON Reports** | Generates structured, timestamped reports |
| **Console Alerts** | Color-coded security alerts with recommendations |
| **Configurable** | External JSON configuration (no code changes needed) |
| **Type Hints** | Full type annotations for better code documentation |
| **Error Handling** | Robust exception handling for network failures |

---

## Architecture

This project follows **clean architecture principles** with clear separation of concerns:

PortScanner/
├── main.py # Entry point & orchestrator
├── scanner.py # Network scanning engine (socket logic)
├── reporter.py # Report generation & alerts (JSON output)
├── config.json # External configuration (dangerous ports)
└── README.md # Documentation


### Module Responsibilities

| Module | Responsibility | Knows About |
|--------|---------------|-------------|
| `main.py` | Orchestrates the flow, parses CLI arguments | Nothing about networking or JSON |
| `scanner.py` | TCP connections, port state detection | Sockets, but NOT JSON or reports |
| `reporter.py` | JSON output, security alerts | JSON, but NOT networking |
| `config.json` | Stores configuration data | Pure data, no code |

**This separation ensures:**
- **Maintainability** - change one module without breaking others
- **Testability** - each module can be tested independently
- **Readability** - clear purpose for each file

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Git (optional, for cloning)

### Step-by-Step Setup

**Clone the repository**
   ```bash
   git clone https://github.com/yourusername/portscanner-pro.git
   cd portscanner-pro

2.Verify Python installation
   python --version
# Should output: Python 3.8+

3. No additional dependencies required — this tool uses only Python standard libraries:
socket - for network connections
json - for configuration and reports
argparse - for command-line interface
logging - for debug and error tracking
datetime - for timestamps

4. Verify the installation
python main.py --help


