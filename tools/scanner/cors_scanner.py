"""
BYMA TOOLS - Advanced CORS Scanner
Professional Cross-Origin Resource Sharing vulnerability detection
"""
import requests
import json
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons, print_vuln_found
)
from core.logger import get_database, get_logger


class CORSScanner:
    """Professional CORS vulnerability scanner"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.vulnerabilities = []
        self.start_time = None
        self.target_url = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    # Test origins for CORS
    TEST_ORIGINS = [
        'https://evil.com',
        'https://attacker.com',
        'http://evil.com',
        'null',
        'https://{target}',
        'https://subdomain.{target}',
        'https://{target}.evil.com',
        'https://evil.{target}',
        'https://eviltarget.com',
    ]
    
    def scan(self, url, output=None):
        """Main CORS scan function"""
        self.start_time = datetime.now()
        self.target_url = url
        
        print_section("CORS SCANNER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("cors_scan", url, "vulnerability")
        self.logger.scan_start("cors_scan", url)
        
        try:
            # Parse target
            parsed = urlparse(url)
            target_domain = parsed.netloc
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {url}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Domain:{Colors.BWHITE}       {target_domain}")
            print_separator("-", 50)
            print()
            
            # Check initial response
            print_subsection("Initial CORS Check")
            initial_headers = self._get_cors_headers(url)
            
            if not initial_headers:
                print_warning("No CORS headers found in initial request")
                print_info("Testing with different origins...")
            else:
                self._display_cors_headers(initial_headers)
            
            # Test various origins
            print_subsection("Origin Reflection Tests")
            self._test_origin_reflection(url, target_domain)
            
            # Test null origin
            print_subsection("Null Origin Tests")
            self._test_null_origin(url)
            
            # Test wildcard
            print_subsection("Wildcard Origin Tests")
            self._test_wildcard(url)
            
            # Test credentials
            print_subsection("Credentials Policy Tests")
            self._test_credentials(url, target_domain)
            
            # Test preflight
            print_subsection("Preflight Request Tests")
            self._test_preflight(url, target_domain)
            
            # Test subdomain
            print_subsection("Subdomain Tests")
            self._test_subdomain(url, target_domain)
            
            # Test third-party
            print_subsection("Third-party Origin Tests")
            self._test_third_party(url, target_domain)
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.vulnerabilities))
            self.logger.scan_complete("cors_scan", url, len(self.vulnerabilities))
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.vulnerabilities
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("cors_scan", url, str(e))
            print_error(f"Scan failed: {e}")
            return []
    
    def _get_cors_headers(self, url, origin=None):
        """Get CORS headers from response"""
        try:
            headers = {}
            if origin:
                headers['Origin'] = origin
            
            response = self.session.get(url, headers=headers, timeout=10, verify=False)
            
            cors_headers = {}
            for header in response.headers:
                header_lower = header.lower()
                if any(cors in header_lower for cors in ['access-control', 'cors']):
                    cors_headers[header] = response.headers[header]
            
            return cors_headers
        
        except Exception as e:
            return {}
    
    def _display_cors_headers(self, headers):
        """Display CORS headers"""
        for header, value in headers.items():
            print(f"  {Colors.BCYAN}{header}:{Colors.BWHITE} {value}")
        print()
    
    def _test_origin_reflection(self, url, target_domain):
        """Test if origin is reflected"""
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'http://evil.com',
            f'https://evil.{target_domain}',
            f'https://{target_domain}.evil.com',
            f'https://sub.{target_domain}',
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(url, headers=headers, timeout=10, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao:
                    if acao == '*':
                        print_warning(f"  {origin} -> {acao} (WILDCARD)")
                    elif acao == origin:
                        if acac.lower() == 'true':
                            print_vuln_found("Origin Reflection with Credentials", "HIGH", origin)
                            self.vulnerabilities.append({
                                'type': 'Origin Reflection',
                                'severity': 'HIGH',
                                'origin': origin,
                                'acao': acao,
                                'acac': acac,
                                'detail': 'Origin reflected with credentials enabled',
                            })
                        else:
                            print_warning(f"  {origin} -> {acao} (Reflected)")
                            self.vulnerabilities.append({
                                'type': 'Origin Reflection',
                                'severity': 'MEDIUM',
                                'origin': origin,
                                'acao': acao,
                                'acac': acac,
                                'detail': 'Origin reflected without credentials',
                            })
                    else:
                        print_success(f"  {origin} -> {acao} (Different)")
                else:
                    print_success(f"  {origin} -> No ACAO header")
            
            except Exception as e:
                print_error(f"  {origin} -> Error: {e}")
        
        print()
    
    def _test_null_origin(self, url):
        """Test null origin"""
        try:
            headers = {'Origin': 'null'}
            response = self.session.get(url, headers=headers, timeout=10, verify=False)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == 'null':
                if acac.lower() == 'true':
                    print_vuln_found("Null Origin with Credentials", "CRITICAL", "null")
                    self.vulnerabilities.append({
                        'type': 'Null Origin',
                        'severity': 'CRITICAL',
                        'origin': 'null',
                        'acao': acao,
                        'acac': acac,
                        'detail': 'Null origin allowed with credentials (sandboxed iframe attack)',
                    })
                else:
                    print_warning("Null origin allowed (without credentials)")
                    self.vulnerabilities.append({
                        'type': 'Null Origin',
                        'severity': 'MEDIUM',
                        'origin': 'null',
                        'acao': acao,
                        'acac': acac,
                        'detail': 'Null origin allowed without credentials',
                    })
            else:
                print_success("Null origin not allowed")
        
        except Exception as e:
            print_error(f"Null origin test failed: {e}")
        
        print()
    
    def _test_wildcard(self, url):
        """Test wildcard origin"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*':
                if acac.lower() == 'true':
                    print_vuln_found("Wildcard with Credentials", "CRITICAL", "*")
                    self.vulnerabilities.append({
                        'type': 'Wildcard with Credentials',
                        'severity': 'CRITICAL',
                        'origin': '*',
                        'acao': acao,
                        'acac': acac,
                        'detail': 'Wildcard origin with credentials (invalid config)',
                    })
                else:
                    print_warning("Wildcard origin (without credentials)")
                    self.vulnerabilities.append({
                        'type': 'Wildcard Origin',
                        'severity': 'LOW',
                        'origin': '*',
                        'acao': acao,
                        'acac': acac,
                        'detail': 'Wildcard origin allows any domain',
                    })
            else:
                print_success("No wildcard origin")
        
        except Exception as e:
            print_error(f"Wildcard test failed: {e}")
        
        print()
    
    def _test_credentials(self, url, target_domain):
        """Test credentials policy"""
        test_origins = [
            f'https://evil.{target_domain}',
            f'https://{target_domain}.evil.com',
            'https://evil.com',
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(url, headers=headers, timeout=10, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acac.lower() == 'true':
                    if acao == origin:
                        print_vuln_found("Credentials with Reflection", "HIGH", origin)
                        self.vulnerabilities.append({
                            'type': 'Credentials Reflection',
                            'severity': 'HIGH',
                            'origin': origin,
                            'acao': acao,
                            'acac': acac,
                            'detail': 'Credentials allowed with reflected origin',
                        })
                    elif acao == '*':
                        print_warning(f"  {origin} -> Credentials with wildcard")
                    else:
                        print_success(f"  {origin} -> Credentials with different origin")
                else:
                    print_success(f"  {origin} -> No credentials")
            
            except Exception as e:
                print_error(f"  {origin} -> Error: {e}")
        
        print()
    
    def _test_preflight(self, url, target_domain):
        """Test preflight requests"""
        test_origins = [
            'https://evil.com',
            f'https://evil.{target_domain}',
            'null',
        ]
        
        for origin in test_origins:
            try:
                headers = {
                    'Origin': origin,
                    'Access-Control-Request-Method': 'PUT',
                    'Access-Control-Request-Headers': 'X-Custom-Header',
                }
                
                response = self.session.options(url, headers=headers, timeout=10, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acam = response.headers.get('Access-Control-Allow-Methods', '')
                acah = response.headers.get('Access-Control-Allow-Headers', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao:
                    if acao == origin or acao == '*':
                        if acac.lower() == 'true':
                            print_vuln_found("Preflight with Credentials", "HIGH", origin)
                            self.vulnerabilities.append({
                                'type': 'Preflight Vulnerability',
                                'severity': 'HIGH',
                                'origin': origin,
                                'acao': acao,
                                'acam': acam,
                                'acah': acah,
                                'detail': 'Preflight allows credentials with arbitrary origin',
                            })
                        else:
                            print_warning(f"  {origin} -> Preflight allowed")
                    else:
                        print_success(f"  {origin} -> Different origin")
                else:
                    print_success(f"  {origin} -> No preflight response")
            
            except Exception as e:
                print_error(f"  {origin} -> Error: {e}")
        
        print()
    
    def _test_subdomain(self, url, target_domain):
        """Test subdomain origin"""
        subdomains = [
            f'https://test.{target_domain}',
            f'https://api.{target_domain}',
            f'https://dev.{target_domain}',
            f'https://staging.{target_domain}',
        ]
        
        for origin in subdomains:
            try:
                headers = {'Origin': origin}
                response = self.session.get(url, headers=headers, timeout=10, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao:
                    if acao == origin:
                        if acac.lower() == 'true':
                            print_warning(f"  {origin} -> Allowed with credentials")
                            self.vulnerabilities.append({
                                'type': 'Subdomain Trust',
                                'severity': 'MEDIUM',
                                'origin': origin,
                                'acao': acao,
                                'acac': acac,
                                'detail': 'Subdomain trusted with credentials',
                            })
                        else:
                            print_success(f"  {origin} -> Allowed without credentials")
                    elif acao == '*':
                        print_warning(f"  {origin} -> Wildcard")
                    else:
                        print_success(f"  {origin} -> Different origin")
                else:
                    print_success(f"  {origin} -> Not allowed")
            
            except Exception as e:
                print_error(f"  {origin} -> Error: {e}")
        
        print()
    
    def _test_third_party(self, url, target_domain):
        """Test third-party origins"""
        third_party_origins = [
            'https://evil.com',
            'https://attacker.com',
            'https://malicious-site.com',
            'https://phishing.com',
        ]
        
        for origin in third_party_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(url, headers=headers, timeout=10, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin:
                    if acac.lower() == 'true':
                        print_vuln_found("Third-party with Credentials", "CRITICAL", origin)
                        self.vulnerabilities.append({
                            'type': 'Third-party Trust',
                            'severity': 'CRITICAL',
                            'origin': origin,
                            'acao': acao,
                            'acac': acac,
                            'detail': 'Third-party origin trusted with credentials',
                        })
                    else:
                        print_warning(f"  {origin} -> Allowed without credentials")
                        self.vulnerabilities.append({
                            'type': 'Third-party Trust',
                            'severity': 'MEDIUM',
                            'origin': origin,
                            'acao': acao,
                            'acac': acac,
                            'detail': 'Third-party origin allowed',
                        })
                else:
                    print_success(f"  {origin} -> Not allowed")
            
            except Exception as e:
                print_error(f"  {origin} -> Error: {e}")
        
        print()
    
    def _display_results(self):
        """Display scan results"""
        print_section("CORS SCAN RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}SCAN SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Target:{Colors.BWHITE}         {self.target_url}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Vulnerabilities:{Colors.BWHITE} {len(self.vulnerabilities)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}            {elapsed:.1f}s")
        
        print_separator("-", 50)
        print()
        
        # Display vulnerabilities
        if self.vulnerabilities:
            print(f"\n  {Icons.WARNING} {Colors.BRED}VULNERABILITIES FOUND{Colors.RESET}")
            print_separator("-", 50)
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_colors = {
                    'CRITICAL': Colors.BRED,
                    'HIGH': Colors.RED,
                    'MEDIUM': Colors.BYELLOW,
                    'LOW': Colors.BCYAN,
                }
                severity_color = severity_colors.get(vuln['severity'], Colors.BWHITE)
                
                print_subsection(f"Vulnerability #{i}")
                print(f"  {Colors.BCYAN}Type:{Colors.BWHITE}       {vuln['type']}")
                print(f"  {Colors.BCYAN}Severity:{Colors.BWHITE}    {severity_color}{vuln['severity']}")
                print(f"  {Colors.BCYAN}Origin:{Colors.BWHITE}      {vuln['origin']}")
                print(f"  {Colors.BCYAN}ACAO:{Colors.BWHITE}        {vuln.get('acao', 'N/A')}")
                print(f"  {Colors.BCYAN}ACAC:{Colors.BWHITE}        {vuln.get('acac', 'N/A')}")
                print(f"  {Colors.BCYAN}Detail:{Colors.BWHITE}      {vuln['detail']}")
                print()
        else:
            print_success("No CORS vulnerabilities found")
        
        # Recommendations
        print_subsection("Recommendations")
        
        if any(v['type'] == 'Origin Reflection' for v in self.vulnerabilities):
            print_info("- Do not reflect arbitrary origins")
            print_info("- Validate origins against a whitelist")
        
        if any(v['type'] == 'Null Origin' for v in self.vulnerabilities):
            print_info("- Do not trust null origins")
            print_info("- Use proper origin validation")
        
        if any(v['type'] == 'Wildcard with Credentials' for v in self.vulnerabilities):
            print_info("- Remove wildcard or disable credentials")
            print_info("- Use specific origin whitelist")
        
        if any(v['type'] == 'Third-party Trust' for v in self.vulnerabilities):
            print_info("- Do not trust third-party origins")
            print_info("- Implement strict origin validation")
        
        print()
    
    def _save_to_database(self, scan_id):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                for vuln in self.vulnerabilities:
                    cursor.execute("""
                        INSERT INTO vulnerabilities 
                        (scan_id, vuln_type, severity, location, evidence, payload)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        vuln['type'],
                        vuln['severity'],
                        self.target_url,
                        vuln['detail'],
                        vuln['origin']
                    ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'target': self.target_url,
                'scan_time': self.start_time.isoformat(),
                'vulnerabilities': self.vulnerabilities,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
