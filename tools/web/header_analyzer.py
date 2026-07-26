"""
BYMA TOOLS - HTTP Header Analyzer
Tools untuk menganalisis HTTP headers
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


class HeaderAnalyzer:
    """HTTP header security analyzer"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.issues = []
    
    def analyze(self, url, output=None):
        """Main analyze function"""
        print_section(f"HTTP Header Analysis: {url}")
        
        scan_id = self.db.create_scan("header_analyzer", url, "vulnerability")
        self.logger.scan_start("header_analyzer", url)
        
        try:
            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            # Get HTTP headers
            print_info("Fetching HTTP headers...")
            headers = self._get_headers(url)
            
            if not headers:
                print_error("Could not fetch HTTP headers")
                return {}
            
            # Analyze headers
            print_info("Analyzing security headers...")
            self._analyze_headers(headers)
            
            # Display results
            self._display_results(headers)
            
            # Save to database
            for issue in self.issues:
                self.db.add_vulnerability(
                    scan_id, url, 'Header Issue', issue['severity'],
                    issue['title'], issue['description'],
                    issue.get('evidence'), issue.get('remediation')
                )
            
            self.db.update_scan(scan_id, "completed", len(self.issues))
            self.logger.scan_complete("header_analyzer", url, len(self.issues))
            
            # Save to file if requested
            if output:
                self._save_results(url, headers, output)
            
            return headers
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("header_analyzer", url, str(e))
            print_error(f"Header analysis failed: {e}")
            return {}
    
    def _get_headers(self, url):
        """Get HTTP headers"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            return dict(response.headers)
        except Exception as e:
            print_error(f"Failed to fetch headers: {e}")
            return {}
    
    def _analyze_headers(self, headers):
        """Analyze security headers"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check for missing security headers
        security_headers = {
            'x-frame-options': {
                'title': 'Missing X-Frame-Options',
                'severity': 'MEDIUM',
                'description': 'Clickjacking attack possible',
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN header'
            },
            'x-content-type-options': {
                'title': 'Missing X-Content-Type-Options',
                'severity': 'LOW',
                'description': 'MIME type sniffing possible',
                'remediation': 'Add X-Content-Type-Options: nosniff header'
            },
            'strict-transport-security': {
                'title': 'Missing HSTS Header',
                'severity': 'MEDIUM',
                'description': 'HTTPS not enforced',
                'remediation': 'Add Strict-Transport-Security header'
            },
            'content-security-policy': {
                'title': 'Missing CSP Header',
                'severity': 'MEDIUM',
                'description': 'XSS and injection attacks possible',
                'remediation': 'Implement Content-Security-Policy header'
            },
            'x-xss-protection': {
                'title': 'Missing X-XSS-Protection',
                'severity': 'LOW',
                'description': 'XSS protection not enabled',
                'remediation': 'Add X-XSS-Protection: 1; mode=block header'
            },
            'referrer-policy': {
                'title': 'Missing Referrer-Policy',
                'severity': 'LOW',
                'description': 'Referrer information may leak',
                'remediation': 'Add Referrer-Policy header'
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers_lower:
                self.issues.append(info)
        
        # Check for dangerous headers
        if 'server' in headers_lower:
            server = headers_lower['server']
            if any(x in server.lower() for x in ['apache', 'nginx', 'iis']):
                self.issues.append({
                    'title': 'Server Version Disclosure',
                    'severity': 'LOW',
                    'description': f'Server header reveals: {server}',
                    'evidence': f'Server: {server}',
                    'remediation': 'Remove or obfuscate server version'
                })
        
        if 'x-powered-by' in headers_lower:
            self.issues.append({
                'title': 'Technology Disclosure',
                'severity': 'LOW',
                'description': f'X-Powered-By reveals technology stack',
                'evidence': f'X-Powered-By: {headers_lower["x-powered-by"]}',
                'remediation': 'Remove X-Powered-By header'
            })
    
    def _display_results(self, headers):
        """Display header analysis results"""
        print_section("HTTP Headers")
        
        # Display all headers
        cprint(f"    {'All Headers:':<25}", Colors.BCYAN)
        for key, value in headers.items():
            cprint(f"      {key}: {value}", Colors.BWHITE)
        
        # Display issues
        if self.issues:
            print()
            cprint(f"    {'Security Issues:':<25}", Colors.BRED)
            for issue in self.issues:
                severity = issue['severity']
                color = Colors.BRED if severity in ['CRITICAL', 'HIGH'] else Colors.BYELLOW
                cprint(f"      [{severity}] {issue['title']}", color)
    
    def _save_results(self, url, headers, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'url': url,
                    'headers': headers,
                    'issues': self.issues
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
