"""
BYMA TOOLS - SQL Injection Scanner
Tools untuk testing SQL Injection vulnerability
"""
import requests
import time
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database
from config.settings import SQLI_PAYLOADS


class SQLInjectionScanner:
    """SQL Injection vulnerability scanner"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.vulnerable_params = []
    
    def scan(self, url, output=None):
        """Main scan function"""
        print_section(f"SQL Injection Scan: {url}")
        
        scan_id = self.db.create_scan("sqli_scanner", url, "vulnerability")
        self.logger.scan_start("sqli_scanner", url)
        
        try:
            # Parse URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                print_warning("No parameters found in URL")
                print_info("Testing path-based injection...")
                self._test_path_injection(url)
            else:
                print_info(f"Found {len(params)} parameters to test")
                for param in params:
                    print_info(f"Testing parameter: {param}")
                    self._test_parameter(url, param, params[param][0])
            
            # Save to database
            for vuln in self.vulnerable_params:
                self.db.add_vulnerability(
                    scan_id, url, 'SQL Injection', 'CRITICAL',
                    f"SQL Injection in {vuln['parameter']}",
                    f"Parameter {vuln['parameter']} is vulnerable to SQL injection",
                    f"Payload: {vuln['payload']}",
                    "Use parameterized queries or prepared statements"
                )
            
            self.db.update_scan(scan_id, "completed", len(self.vulnerable_params))
            self.logger.scan_complete("sqli_scanner", url, len(self.vulnerable_params))
            
            self._display_results()
            
            if output:
                self._save_results(url, output)
            
            return self.vulnerable_params
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("sqli_scanner", url, str(e))
            print_error(f"Scan failed: {e}")
            return []
    
    def _test_parameter(self, url, param_name, original_value):
        """Test single parameter for SQL injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload in SQLI_PAYLOADS:
            try:
                # Replace parameter value with payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                # Build test URL
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                
                # Send request
                start_time = time.time()
                response = requests.get(test_url, timeout=10, verify=False)
                response_time = time.time() - start_time
                
                # Check for SQL injection indicators
                if self._check_sqli_response(response, response_time, payload):
                    self.vulnerable_params.append({
                        'parameter': param_name,
                        'payload': payload,
                        'response_code': response.status_code,
                        'response_time': response_time,
                        'evidence': self._extract_evidence(response.text)
                    })
                    print_success(f"Vulnerable! Parameter: {param_name}, Payload: {payload}")
                    break  # Move to next parameter after finding vulnerability
            
            except requests.RequestException:
                continue
    
    def _test_path_injection(self, url):
        """Test path-based SQL injection"""
        test_urls = [
            f"{url}/' OR '1'='1",
            f"{url}/' OR '1'='1' --",
            f"{url}/1' AND '1'='1",
        ]
        
        for test_url in test_urls:
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                if response.status_code == 200:
                    print_info(f"Path test returned 200 for: {test_url}")
            except:
                pass
    
    def _check_sqli_response(self, response, response_time, payload):
        """Check if response indicates SQL injection"""
        text = response.text.lower()
        
        # Error-based indicators
        error_indicators = [
            'sql syntax', 'mysql_fetch', 'oci_fetch', 'postgresql',
            'ora-', 'sqlite', 'microsoft jet', 'odbc', 'sql server',
            'unclosed quotation', 'quoted string', 'syntax error',
            'mysql_num_rows', 'pg_query', 'sqlite3', 'warning:',
            'fatal error', 'mysql_', 'pg_', 'sqlite_'
        ]
        
        for indicator in error_indicators:
            if indicator in text:
                return True
        
        # Time-based indicator
        if response_time > 5:
            return True
        
        # Boolean-based indicator
        if "' or '1'='1" in payload.lower():
            if 'login' in text or 'welcome' in text or 'dashboard' in text:
                return True
        
        # Union-based indicator
        if 'union' in payload.lower():
            if 'column' in text or 'select' in text:
                return True
        
        return False
    
    def _extract_evidence(self, html):
        """Extract evidence from response"""
        # Look for error messages
        import re
        error_patterns = [
            r'(?:sql|mysql|ora|sqlite|postgresql)[^<]{0,100}',
            r'(?:syntax|error|warning)[^<]{0,100}'
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(0)[:200]
        
        return "SQL injection indicators found in response"
    
    def _display_results(self):
        """Display scan results"""
        print_section("SQL Injection Results")
        
        if not self.vulnerable_params:
            print_success("No SQL injection vulnerabilities found")
            return
        
        print_error(f"Found {len(self.vulnerable_params)} vulnerable parameters:")
        print()
        
        for vuln in self.vulnerable_params:
            cprint(f"    Parameter: {vuln['parameter']}", Colors.BRED)
            cprint(f"    Payload: {vuln['payload']}", Colors.BYELLOW)
            cprint(f"    Response Code: {vuln['response_code']}", Colors.BWHITE)
            cprint(f"    Response Time: {vuln['response_time']:.2f}s", Colors.BWHITE)
            print()
    
    def _save_results(self, url, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'url': url,
                    'vulnerable_parameters': self.vulnerable_params,
                    'total': len(self.vulnerable_params)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
