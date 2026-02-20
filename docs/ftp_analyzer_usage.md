# SOC FTP Analyzer - Usage Documentation

## Overview

SOC FTP Analyzer is a security tool designed to analyze FTP servers, logs, and traffic for signs of malicious activity, unauthorized access, and data exfiltration. It helps SOC analysts and system administrators identify potential security incidents involving FTP services.

## Features

- **Log Analysis**: Parses FTP server logs (vsftpd, proftpd, pure-ftpd) for suspicious activities
- **Brute Force Detection**: Identifies multiple failed login attempts from single IPs
- **Suspicious Command Detection**: Monitors for dangerous FTP commands
- **File Transfer Analysis**: Detects transfers of files with suspicious extensions
- **Configuration Auditing**: Checks FTP server configurations for security issues
- **User Account Analysis**: Identifies suspicious FTP user accounts
- **Known Malicious IP Checking**: Compares connections against threat intelligence
- **Comprehensive Reporting**: Generates detailed JSON reports

## Installation

### Prerequisites

- Python 3.6 or higher
- Linux/Unix operating system
- Access to FTP server logs
- Root privileges for complete analysis

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/soc-ftp-analyzer.git
cd soc-ftp-analyzer

# No external dependencies required - uses Python standard library only
