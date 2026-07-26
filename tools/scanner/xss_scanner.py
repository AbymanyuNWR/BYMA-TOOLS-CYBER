"""
BYMA TOOLS - XSS Scanner
Tools untuk testing Cross-Site Scripting vulnerability
"""
import requests
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database
from config.settings import XSS_PAYLOADS


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.vulnerable_params = []
    
    def scan(self, url, output=None):
        """Main scan function"""
        print_section(f"XSS Scan: {url}")
        
        scan_id = self.db.create_scan("xss_scanner", url, "vulnerability")
        self.logger.scan_start("xss_scanner", url)
        
        try:
            # Parse URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                print_warning("No parameters found in URL")
                print_info("Testing reflected XSS on URL path...")
                self._test_path_xss(url)
            else:
                print_info(f"Found {len(params)} parameters to test")
                for param in params:
                    print_info(f"Testing parameter: {param}")
                    self._test_parameter(url, param, params[param][0])
            
            # Save to database
            for vuln in self.vulnerable_params:
                self.db.add_vulnerability(
                    scan_id, url, 'XSS', 'HIGH',
                    f"Cross-Site Scripting in {vuln['parameter']}",
                    f"Parameter {vuln['parameter']} is vulnerable to XSS",
                    f"Payload: {vuln['payload']}",
                    "Implement input validation and output encoding"
                )
            
            self.db.update_scan(scan_id, "completed", len(self.vulnerable_params))
            self.logger.scan_complete("xss_scanner", url, len(self.vulnerable_params))
            
            self._display_results()
            
            if output:
                self._save_results(url, output)
            
            return self.vulnerable_params
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("xss_scanner", url, str(e))
            print_error(f"Scan failed: {e}")
            return []
    
    def _test_parameter(self, url, param_name, original_value):
        """Test single parameter for XSS"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload in XSS_PAYLOADS:
            try:
                # Replace parameter value with payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                # Build test URL
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                
                # Send request
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Check if payload is reflected
                if self._check_xss_response(response, payload):
                    self.vulnerable_params.append({
                        'parameter': param_name,
                        'payload': payload,
                        'response_code': response.status_code,
                        'evidence': self._extract_evidence(response.text, payload)
                    })
                    print_success(f"Vulnerable! Parameter: {param_name}")
                    print_info(f"  Payload: {payload}")
                    break
            
            except requests.RequestException:
                continue
    
    def _test_path_xss(self, url):
        """Test path-based XSS"""
        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'-alert('XSS')-'"
        ]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}/{payload}"
                response = requests.get(test_url, timeout=10, verify=False)
                
                if self._check_xss_response(response, payload):
                    print_success(f"Path-based XSS found with payload: {payload}")
            except:
                pass
    
    def _check_xss_response(self, response, payload):
        """Check if response contains reflected XSS"""
        text = response.text
        
        # Check if payload is reflected in response
        if payload in text:
            return True
        
        # Check for partial reflection
        # Remove common encoding
        decoded_payload = payload.replace('&lt;', '<').replace('&gt;', '>')
        decoded_payload = decoded_payload.replace('&#60;', '<').replace('&#62;', '>')
        
        if decoded_payload in text:
            return True
        
        # Check for script tag reflection
        if '<script>' in payload.lower() and '<script>' in text.lower():
            return True
        
        # Check for event handler reflection
        if 'onerror=' in payload.lower() and 'onerror=' in text.lower():
            return True
        
        # Check for javascript: protocol
        if 'javascript:' in payload.lower() and 'javascript:' in text.lower():
            return True
        
        return False
    
    def _extract_evidence(self, html, payload):
        """Extract evidence from response"""
        # Find payload in response
        idx = html.find(payload)
        if idx != -1:
            start = max(0, idx - 50)
            end = min(len(html), idx + len(payload) + 50)
            return html[start:end]
        
        return "XSS payload reflected in response"
    
    def _display_results(self):
        """Display scan results"""
        print_section("XSS Results")
        
        if not self.vulnerable_params:
            print_success("No XSS vulnerabilities found")
            return
        
        print_error(f"Found {len(self.vulnerable_params)} vulnerable parameters:")
        print()
        
        for vuln in self.vulnerable_params:
            cprint(f"    Parameter: {vuln['parameter']}", Colors.BRED)
            cprint(f"    Payload: {vuln['payload'][:50]}...", Colors.BYELLOW)
            cprint(f"    Response Code: {vuln['response_code']}", Colors.BWHITE)
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
