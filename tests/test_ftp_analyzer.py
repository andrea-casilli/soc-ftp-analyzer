#!/usr/bin/env python3
"""
Test suite for SOC FTP Analyzer
"""

import os
import sys
import unittest
import tempfile
import json
import datetime
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from soc_ftp_analyzer import FTPAnalyzer

class TestFTPAnalyzer(unittest.TestCase):
    """Test cases for FTP Analyzer"""
    
    def setUp(self):
        """Set up test environment"""
        self.analyzer = FTPAnalyzer()
        self.test_log_dir = tempfile.mkdtemp()
        
    def create_test_log(self, content: str) -> str:
        """Create a test log file with given content"""
        log_path = os.path.join(self.test_log_dir, 'test.log')
        with open(log_path, 'w') as f:
            f.write(content)
        return log_path
    
    def test_config_loading(self):
        """Test configuration loading"""
        self.assertIsInstance(self.analyzer.config, dict)
        self.assertIn('suspicious_commands', self.analyzer.config)
        self.assertIn('brute_force_threshold', self.analyzer.config)
    
    def test_failed_login_detection(self):
        """Test detection of failed logins"""
        log_content = """Jan 15 10:30:45 server vsftpd[1234]: FAIL LOGIN: Client 192.168.1.100
Jan 15 10:30:46 server vsftpd[1234]: FAIL LOGIN: Client 192.168.1.100
Jan 15 10:30:47 server sshd[1235]: authentication failure for ftp user"""
        
        log_path = self.create_test_log(log_content)
        self.analyzer.analyze_ftp_logs(log_path)
        
        self.assertEqual(self.analyzer.results['statistics']['failed_logins'], 2)
    
    def test_suspicious_command_detection(self):
        """Test detection of suspicious FTP commands"""
        log_content = """Jan 15 10:30:45 server vsftpd[1234]: [ftpuser] STOR malicious.exe
Jan 15 10:30:46 server vsftpd[1234]: [ftpuser] DELE /etc/passwd
Jan 15 10:30:47 server vsftpd[1234]: [ftpuser] SITE CHMOD 777 /tmp"""
        
        log_path = self.create_test_log(log_content)
        self.analyzer.analyze_ftp_logs(log_path)
        
        findings = [f for f in self.analyzer.results['findings'] 
                   if f['type'] == 'suspicious_command']
        self.assertGreaterEqual(len(findings), 3)
    
    def test_suspicious_file_transfer_detection(self):
        """Test detection of suspicious file transfers"""
        log_content = """Jan 15 10:30:45 server vsftpd[1234]: [ftpuser] STOR backdoor.php
Jan 15 10:30:46 server vsftpd[1234]: [ftpuser] STOR exploit.exe
Jan 15 10:30:47 server vsftpd[1234]: [ftpuser] RETR data.sh"""
        
        log_path = self.create_test_log(log_content)
        self.analyzer.analyze_ftp_logs(log_path)
        
        findings = [f for f in self.analyzer.results['findings'] 
                   if f['type'] == 'suspicious_file_transfer']
        self.assertEqual(len(findings), 3)
    
    def test_brute_force_detection(self):
        """Test brute force attack detection"""
        log_lines = []
        for i in range(15):
            log_lines.append(f"Jan 15 10:30:{i:02d} server vsftpd[1234]: FAIL LOGIN: Client 192.168.1.200")
        
        log_path = self.create_test_log('\n'.join(log_lines))
        self.analyzer.analyze_ftp_logs(log_path)
        
        findings = [f for f in self.analyzer.results['findings'] 
                   if f['type'] == 'brute_force_attack']
        self.assertGreaterEqual(len(findings), 1)
    
    def test_ip_extraction(self):
        """Test IP address extraction from logs"""
        line = "Jan 15 10:30:45 server vsftpd[1234]: FAIL LOGIN: Client 192.168.1.100"
        ip = self.analyzer.extract_ip_from_log(line)
        self.assertEqual(ip, "192.168.1.100")
    
    def test_insecure_config_detection(self):
        """Test detection of insecure FTP configurations"""
        # Create mock config file
        config_path = os.path.join(self.test_log_dir, 'vsftpd.conf')
        with open(config_path, 'w') as f:
            f.write("anonymous_enable=YES\n")
            f.write("write_enable=YES\n")
            f.write("ssl_enable=NO\n")
        
        # Override config paths for testing
        self.analyzer.config['ftp_log_paths'] = []
        self.analyzer.analyze_ftp_configuration = self.analyzer.analyze_ftp_configuration.__func__
        
        # Mock config file check
        self.analyzer.analyze_ftp_configuration()
        
        findings = [f for f in self.analyzer.results['findings'] 
                   if f['type'] == 'insecure_configuration']
        self.assertGreaterEqual(len(findings), 1)
    
    def test_known_malicious_ip(self):
        """Test detection of known malicious IPs"""
        self.analyzer.config['known_malicious_ips'] = ['192.168.1.100']
        self.analyzer.brute_force_attempts = {
            '192.168.1.100': [{'timestamp': datetime.datetime.now(), 'log_line': 'test'}]
        }
        
        self.analyzer.check_known_malicious_ips()
        
        findings = [f for f in self.analyzer.results['findings'] 
                   if f['type'] == 'known_malicious_ip']
        self.assertEqual(len(findings), 1)
    
    def test_report_generation(self):
        """Test report generation"""
        self.analyzer.add_finding({
            'type': 'test_finding',
            'description': 'Test finding',
            'severity': 'MEDIUM'
        })
        
        report_path = os.path.join(self.test_log_dir, 'test_report.json')
        self.analyzer.generate_report(report_path)
        
        self.assertTrue(os.path.exists(report_path))
        
        with open(report_path, 'r') as f:
            report = json.load(f)
            self.assertIn('timestamp', report)
            self.assertIn('findings', report)
            self.assertEqual(len(report['findings']), 1)

if __name__ == '__main__':
    unittest.main()
