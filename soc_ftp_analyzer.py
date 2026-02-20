#!/usr/bin/env python3
"""
SOC FTP Analyzer
Tool for analyzing FTP servers, logs, and traffic to detect malicious activities,
unauthorized access, and data exfiltration attempts.
"""

import os
import sys
import re
import socket
import argparse
import json
import hashlib
import datetime
import ipaddress
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional

class FTPAnalyzer:
    def __init__(self, config_path: Optional[str] = None):
        self.results = {
            'timestamp': datetime.datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'findings': [],
            'statistics': {
                'total_log_entries': 0,
                'failed_logins': 0,
                'successful_logins': 0,
                'suspicious_commands': 0,
                'data_transfers': 0
            }
        }
        
        self.config = self.load_config(config_path)
        self.suspicious_ips = set()
        self.brute_force_attempts = defaultdict(list)
        
    def load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "ftp_log_paths": [
                "/var/log/vsftpd.log",
                "/var/log/proftpd/proftpd.log",
                "/var/log/messages",
                "/var/log/syslog"
            ],
            "suspicious_commands": [
                "STOR", "APPE", "STOU", "RETR", "DELE", "RMD", "MKD",
                "RNFR", "RNTO", "SITE", "CHMOD", "ABOR"
            ],
            "suspicious_extensions": [
                ".exe", ".bat", ".sh", ".php", ".asp", ".jsp", ".py",
                ".pl", ".rb", ".dll", ".so", ".scr", ".pif", ".vbs"
            ],
            "brute_force_threshold": 10,  # Failed attempts within time window
            "brute_force_window_seconds": 300,  # 5 minutes
            "data_exfiltration_threshold_mb": 100,
            "known_malicious_ips": [],
            "alert_on_suspicious_commands": True,
            "alert_on_data_exfiltration": True,
            "alert_on_brute_force": True
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                print(f"[INFO] Configuration loaded from {config_path}")
            except Exception as e:
                print(f"[ERROR] Failed to load config: {e}")
        
        return default_config
    
    def analyze_ftp_logs(self, log_path: str) -> None:
        """Analyze FTP server logs for suspicious activities"""
        if not os.path.exists(log_path):
            print(f"[WARNING] Log file not found: {log_path}")
            return
            
        print(f"[INFO] Analyzing FTP log: {log_path}")
        
        # Log format patterns for different FTP servers
        patterns = {
            'vsftpd': [
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*\[(?P<pid>\d+)\].*\[(?P<user>[^\]]+)\].*(?P<command>\w+)\s+(?P<file>\S+)',
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*FAIL LOGIN.*Client\s+(?P<ip>\d+\.\d+\.\d+\.\d+)',
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*OK LOGIN.*Client\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
            ],
            'proftpd': [
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*proftpd.*\(.*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?\):\s+(?P<command>\w+)\s+(?P<file>\S+)',
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*USER.*?\(.*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?\):\s+(?P<user>\S+)',
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Maximum login attempts.*(?P<ip>\d+\.\d+\.\d+\.\d+)'
            ]
        }
        
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    self.results['statistics']['total_log_entries'] += 1
                    self.parse_log_line(line, patterns)
        except Exception as e:
            print(f"[ERROR] Error reading log file {log_path}: {e}")
    
    def parse_log_line(self, line: str, patterns: Dict) -> None:
        """Parse a single log line using defined patterns"""
        # Check for failed logins
        if 'FAIL LOGIN' in line or 'authentication failure' in line or 'login failed' in line.lower():
            self.results['statistics']['failed_logins'] += 1
            self.extract_ip_from_log(line)
            
        # Check for successful logins
        elif 'OK LOGIN' in line or 'login successful' in line.lower():
            self.results['statistics']['successful_logins'] += 1
            
        # Check for suspicious commands
        for cmd in self.config['suspicious_commands']:
            if cmd in line:
                self.results['statistics']['suspicious_commands'] += 1
                self.add_finding({
                    'type': 'suspicious_command',
                    'description': f'Suspicious FTP command detected: {cmd}',
                    'log_line': line.strip(),
                    'severity': 'MEDIUM'
                })
                
        # Check for file transfers with suspicious extensions
        for ext in self.config['suspicious_extensions']:
            if ext in line.lower():
                self.results['statistics']['data_transfers'] += 1
                self.add_finding({
                    'type': 'suspicious_file_transfer',
                    'description': f'Transfer of file with suspicious extension: {ext}',
                    'log_line': line.strip(),
                    'severity': 'HIGH'
                })
    
    def extract_ip_from_log(self, line: str) -> Optional[str]:
        """Extract IP address from log line"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, line)
        if match:
            ip = match.group()
            self.track_ip_activity(ip, line)
            return ip
        return None
    
    def track_ip_activity(self, ip: str, log_line: str) -> None:
        """Track IP activity for brute force detection"""
        current_time = datetime.datetime.now()
        self.brute_force_attempts[ip].append({
            'timestamp': current_time,
            'log_line': log_line
        })
        
        # Check for brute force within time window
        recent_attempts = [
            attempt for attempt in self.brute_force_attempts[ip]
            if (current_time - attempt['timestamp']).seconds < self.config['brute_force_window_seconds']
        ]
        
        if len(recent_attempts) >= self.config['brute_force_threshold']:
            self.add_finding({
                'type': 'brute_force_attack',
                'description': f'Possible brute force attack from IP: {ip}',
                'ip': ip,
                'attempts': len(recent_attempts),
                'window_seconds': self.config['brute_force_window_seconds'],
                'severity': 'CRITICAL'
            })
    
    def check_known_malicious_ips(self) -> None:
        """Check if any IPs match known malicious IPs"""
        for ip in self.brute_force_attempts.keys():
            if ip in self.config['known_malicious_ips']:
                self.add_finding({
                    'type': 'known_malicious_ip',
                    'description': f'Connection from known malicious IP: {ip}',
                    'ip': ip,
                    'severity': 'CRITICAL'
                })
    
    def analyze_ftp_configuration(self) -> None:
        """Check FTP server configuration for security issues"""
        config_files = [
            '/etc/vsftpd.conf',
            '/etc/proftpd/proftpd.conf',
            '/etc/pure-ftpd/pure-ftpd.conf'
        ]
        
        insecure_settings = {
            'anonymous_enable=YES': 'Anonymous FTP access enabled',
            'write_enable=YES': 'Write access enabled (potential risk)',
            'anon_upload_enable=YES': 'Anonymous upload enabled',
            'anon_mkdir_write_enable=YES': 'Anonymous directory creation enabled',
            'chown_uploads=YES': 'File ownership changes allowed',
            'ssl_enable=NO': 'SSL/TLS disabled - credentials transmitted in clear',
            'require_ssl_reuse=NO': 'SSL session reuse not required',
            'allow_writeable_chroot=YES': 'Writeable chroot jail - privilege escalation risk'
        }
        
        for config_file in config_files:
            if os.path.exists(config_file):
                print(f"[INFO] Checking FTP configuration: {config_file}")
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                        for setting, description in insecure_settings.items():
                            if setting in content:
                                self.add_finding({
                                    'type': 'insecure_configuration',
                                    'description': description,
                                    'config_file': config_file,
                                    'setting': setting,
                                    'severity': 'HIGH'
                                })
                except Exception as e:
                    print(f"[ERROR] Error reading config {config_file}: {e}")
    
    def check_ftp_users(self) -> None:
        """Check FTP users for suspicious accounts"""
        user_files = [
            '/etc/passwd',
            '/etc/vsftpd/user_list',
            '/etc/vsftpd/chroot_list',
            '/etc/proftpd/ftpusers'
        ]
        
        suspicious_shells = ['/bin/bash', '/bin/sh', '/bin/zsh', '/bin/dash']
        
        for user_file in user_files:
            if os.path.exists(user_file):
                try:
                    with open(user_file, 'r') as f:
                        for line in f:
                            if 'ftp' in line.lower() or 'anonymous' in line.lower():
                                parts = line.split(':')
                                if len(parts) > 6:
                                    username = parts[0]
                                    shell = parts[6].strip()
                                    
                                    if shell in suspicious_shells and username not in ['root', 'daemon']:
                                        self.add_finding({
                                            'type': 'ftp_user_suspicious_shell',
                                            'description': f'FTP user {username} has shell access: {shell}',
                                            'user': username,
                                            'shell': shell,
                                            'severity': 'MEDIUM'
                                        })
                except Exception as e:
                    print(f"[ERROR] Error reading {user_file}: {e}")
    
    def analyze_data_transfers(self) -> None:
        """Analyze FTP data transfers for exfiltration attempts"""
        # This would typically integrate with log analysis
        # For now, we'll flag large file transfers from logs
        pass
    
    def add_finding(self, finding: Dict) -> None:
        """Add a finding to the results"""
        finding['timestamp'] = datetime.datetime.now().isoformat()
        self.results['findings'].append(finding)
        print(f"[!] {finding['severity']}: {finding['description']}")
    
    def generate_report(self, output_file: Optional[str] = None) -> None:
        """Generate analysis report"""
        print("\n" + "="*70)
        print("SOC FTP ANALYZER REPORT")
        print("="*70)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Hostname: {self.results['hostname']}")
        print(f"Total findings: {len(self.results['findings'])}")
        print("-"*70)
        
        # Statistics
        print("\nSTATISTICS:")
        for key, value in self.results['statistics'].items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        
        # Findings by severity
        if self.results['findings']:
            print("\nFINDINGS BY SEVERITY:")
            severity_count = Counter([f['severity'] for f in self.results['findings']])
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity in severity_count:
                    print(f"  {severity}: {severity_count[severity]}")
            
            print("\nDETAILED FINDINGS:")
            for i, finding in enumerate(self.results['findings'], 1):
                print(f"\n  [{i}] {finding['type'].upper()}")
                print(f"      Severity: {finding['severity']}")
                print(f"      Description: {finding['description']}")
                if 'ip' in finding:
                    print(f"      IP: {finding['ip']}")
                if 'user' in finding:
                    print(f"      User: {finding['user']}")
        else:
            print("\n[OK] No suspicious activities detected")
        
        print("\n" + "="*70)
        
        # Save report
        if output_file:
            report_path = output_file
        else:
            report_path = f"ftp_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n[INFO] Report saved to: {report_path}")
    
    def run_analysis(self, log_files: Optional[List[str]] = None) -> None:
        """Run complete FTP analysis"""
        print("="*70)
        print("SOC FTP ANALYZER - Starting Analysis")
        print("="*70)
        
        # Analyze FTP logs
        logs_to_analyze = log_files if log_files else self.config['ftp_log_paths']
        for log_file in logs_to_analyze:
            self.analyze_ftp_logs(log_file)
        
        # Check for known malicious IPs
        self.check_known_malicious_ips()
        
        # Analyze FTP configuration
        self.analyze_ftp_configuration()
        
        # Check FTP users
        self.check_ftp_users()
        
        # Generate report
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description='SOC FTP Analyzer - Detect malicious FTP activities')
    parser.add_argument('--log-files', nargs='+', help='Specific FTP log files to analyze')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--output', help='Output report file path')
    parser.add_argument('--check-config', action='store_true', help='Check FTP server configuration only')
    parser.add_argument('--check-users', action='store_true', help='Check FTP users only')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[WARNING] Some checks require root privileges")
        print("[WARNING] Run with sudo for complete results")
    
    analyzer = FTPAnalyzer(args.config)
    
    if args.check_config:
        analyzer.analyze_ftp_configuration()
        analyzer.generate_report(args.output)
    elif args.check_users:
        analyzer.check_ftp_users()
        analyzer.generate_report(args.output)
    else:
        analyzer.run_analysis(args.log_files)

if __name__ == "__main__":
    main()