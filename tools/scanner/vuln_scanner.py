"""
BYMA TOOLS - Vulnerability Scanner
Tools untuk scanning kerentanan umum pada target
"""
import requests
import json
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class VulnScanner:
    """General vulnerability scanner"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.vulnerabilities = []
    
    def scan(self, target, output=None):
        """Main scan function"""
        print_section(f"Vulnerability Scan: {target}")
        
        scan_id = self.db.create_scan("vuln_scanner", target, "vulnerability")
        self.logger.scan_start("vuln_scanner", target)
        
        try:
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            
            # Check various vulnerabilities
            print_info("Checking security headers...")
            self._check_security_headers(target)
            
            print_info("Checking server information disclosure...")
            self._check_info_disclosure(target)
            
            print_info("Checking for common vulnerabilities...")
            self._check_common_vulns(target)
            
            # Save to database
            for vuln in self.vulnerabilities:
                self.db.add_vulnerability(
                    scan_id, target, vuln['type'], vuln.get('severity'),
                    vuln.get('title'), vuln.get('description'),
                    vuln.get('evidence'), vuln.get('remediation')
                )
            
            self.db.update_scan(scan_id, "completed", len(self.vulnerabilities))
            self.logger.scan_complete("vuln_scanner", target, len(self.vulnerabilities))
            
            self._display_results()
            
            if output:
                self._save_results(target, output)
            
            return self.vulnerabilities
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("vuln_scanner", target, str(e))
            print_error(f"Scan failed: {e}")
            return []
    
    def _check_security_headers(self, target):
        """Check for missing security headers"""
        try:
            response = requests.get(target, timeout=10, verify=False)
            headers = response.headers
            
            # Check for missing headers
            missing_headers = {
                'X-Frame-Options': ('Missing X-Frame-Options header', 'MEDIUM',
                    'Clickjacking attack possible'),
                'X-Content-Type-Options': ('Missing X-Content-Type-Options header', 'LOW',
                    'MIME type sniffing possible'),
                'X-XSS-Protection': ('Missing X-XSS-Protection header', 'LOW',
                    'XSS protection not enabled'),
                'Strict-Transport-Security': ('Missing HSTS header', 'MEDIUM',
                    'HTTPS not enforced'),
                'Content-Security-Policy': ('Missing CSP header', 'MEDIUM',
                    'XSS and injection attacks possible'),
                'Referrer-Policy': ('Missing Referrer-Policy header', 'LOW',
                    'Referrer information may leak'),
                'Permissions-Policy': ('Missing Permissions-Policy header', 'LOW',
                    'Browser features not restricted'),
            }
            
            for header, (title, severity, description) in missing_headers.items():
                if header.lower() not in {k.lower() for k in headers.keys()}:
                    self.vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': severity,
                        'title': title,
                        'description': description,
                        'evidence': f'Header {header} not found in response',
                        'remediation': f'Add {header} header to HTTP response'
                    })
        
        except Exception as e:
            print_warning(f"Header check failed: {e}")
    
    def _check_info_disclosure(self, target):
        """Check for information disclosure"""
        try:
            response = requests.get(target, timeout=10, verify=False)
            headers = response.headers
            
            # Check server header
            if 'server' in headers:
                server = headers['server']
                if any(x in server.lower() for x in ['apache', 'nginx', 'iis', 'php']):
                    self.vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'LOW',
                        'title': 'Server Version Disclosure',
                        'description': f'Server header reveals: {server}',
                        'evidence': f'Server: {server}',
                        'remediation': 'Remove or obfuscate server version information'
                    })
            
            # Check X-Powered-By
            if 'x-powered-by' in headers:
                powered_by = headers['x-powered-by']
                self.vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'LOW',
                    'title': 'Technology Disclosure',
                    'description': f'X-Powered-By header reveals: {powered_by}',
                    'evidence': f'X-Powered-By: {powered_by}',
                    'remediation': 'Remove X-Powered-By header'
                })
        
        except Exception as e:
            print_warning(f"Info disclosure check failed: {e}")
    
    def _check_common_vulns(self, target):
        """Check for common vulnerabilities"""
        # Check for directory listing
        try:
            response = requests.get(f"{target}/icons/", timeout=5, verify=False)
            if 'Index of' in response.text:
                self.vulnerabilities.append({
                    'type': 'Directory Listing',
                    'severity': 'MEDIUM',
                    'title': 'Directory Listing Enabled',
                    'description': 'Directory listing is enabled on the server',
                    'evidence': 'Found Index of page',
                    'remediation': 'Disable directory listing in web server configuration'
                })
        except:
            pass
        
        # Check for common backup files
        backup_files = ['.bak', '.old', '.backup', '.save', '.swp', '~']
        for ext in backup_files:
            try:
                response = requests.get(f"{target}/index.php{ext}", timeout=5, verify=False)
                if response.status_code == 200 and len(response.content) > 0:
                    self.vulnerabilities.append({
                        'type': 'Backup File',
                        'severity': 'HIGH',
                        'title': f'Backup File Found: index.php{ext}',
                        'description': 'Backup file accessible on web server',
                        'evidence': f'GET /index.php{ext} returned {response.status_code}',
                        'remediation': 'Remove backup files from web-accessible directories'
                    })
            except:
                pass
    
    def _display_results(self):
        """Display scan results"""
        print_section("Vulnerability Scan Results")
        
        if not self.vulnerabilities:
            print_success("No vulnerabilities found")
            return
        
        # Group by severity
        by_severity = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        # Display summary
        print_warning(f"Found {len(self.vulnerabilities)} potential vulnerabilities:")
        print()
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                color = {
                    'CRITICAL': Colors.BRED,
                    'HIGH': Colors.RED,
                    'MEDIUM': Colors.BYELLOW,
                    'LOW': Colors.BCYAN,
                    'INFO': Colors.BWHITE
                }.get(severity, Colors.BWHITE)
                
                cprint(f"    {severity}: {len(by_severity[severity])} findings", color)
        
        print()
        
        # Display details
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            color = {
                'CRITICAL': Colors.BRED,
                'HIGH': Colors.RED,
                'MEDIUM': Colors.BYELLOW,
                'LOW': Colors.BCYAN,
                'INFO': Colors.BWHITE
            }.get(severity, Colors.BWHITE)
            
            cprint(f"    [{severity}] {vuln.get('title', 'Unknown')}", color)
            if vuln.get('description'):
                cprint(f"      Description: {vuln['description']}", Colors.BWHITE)
            if vuln.get('evidence'):
                cprint(f"      Evidence: {vuln['evidence'][:100]}", Colors.BBLACK)
            print()
    
    def _save_results(self, target, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'target': target,
                    'vulnerabilities': self.vulnerabilities,
                    'total': len(self.vulnerabilities)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
