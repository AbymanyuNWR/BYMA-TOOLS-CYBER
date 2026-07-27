"""
BYMA TOOLS - Advanced HTTP Header Analyzer
Professional security header analysis
"""
import requests
import json
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons, print_vuln_found
)
from core.logger import get_database, get_logger


class HeaderAnalyzer:
    """Professional HTTP header security analyzer"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.start_time = None
        self.vulnerabilities = []
        self.headers_info = {}
    
    # Security headers with recommendations
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'HTTP Strict Transport Security (HSTS)',
            'severity': 'MEDIUM',
            'recommendation': 'max-age=31536000; includeSubDomains; preload',
            'check': '_check_hsts',
        },
        'Content-Security-Policy': {
            'description': 'Content Security Policy',
            'severity': 'MEDIUM',
            'recommendation': "default-src 'self'; script-src 'self'",
            'check': '_check_csp',
        },
        'X-Frame-Options': {
            'description': 'Clickjacking protection',
            'severity': 'MEDIUM',
            'recommendation': 'DENY or SAMEORIGIN',
            'check': '_check_xframe',
        },
        'X-Content-Type-Options': {
            'description': 'MIME type sniffing protection',
            'severity': 'LOW',
            'recommendation': 'nosniff',
            'check': '_check_content_type',
        },
        'X-XSS-Protection': {
            'description': 'XSS filter (deprecated)',
            'severity': 'LOW',
            'recommendation': '1; mode=block',
            'check': '_check_xss_protection',
        },
        'Referrer-Policy': {
            'description': 'Referrer information policy',
            'severity': 'LOW',
            'recommendation': 'strict-origin-when-cross-origin',
            'check': '_check_referrer',
        },
        'Permissions-Policy': {
            'description': 'Feature policy',
            'severity': 'LOW',
            'recommendation': 'geolocation=(), microphone=()',
            'check': '_check_permissions',
        },
        'X-Permitted-Cross-Domain-Policies': {
            'description': 'Cross-domain policy',
            'severity': 'LOW',
            'recommendation': 'none',
            'check': '_check_cross_domain',
        },
        'Cross-Origin-Opener-Policy': {
            'description': 'Cross-origin opener policy',
            'severity': 'LOW',
            'recommendation': 'same-origin',
            'check': '_check_coop',
        },
        'Cross-Origin-Resource-Policy': {
            'description': 'Cross-origin resource policy',
            'severity': 'LOW',
            'recommendation': 'same-origin',
            'check': '_check_corp',
        },
        'Cross-Origin-Embedder-Policy': {
            'description': 'Cross-origin embedder policy',
            'severity': 'LOW',
            'recommendation': 'require-corp',
            'check': '_check_coep',
        },
    }
    
    # Headers that should not be exposed
    DANGEROUS_HEADERS = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Generator',
    ]
    
    def analyze(self, url, output=None):
        """Main header analysis function"""
        self.start_time = datetime.now()
        
        print_section("HTTP HEADER ANALYZER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("header_analysis", url, "security")
        self.logger.scan_start("header_analysis", url)
        
        try:
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {url}")
            print_separator("-", 50)
            print()
            
            # Get response
            print_subsection("Fetching Headers")
            
            response = self._get_response(url)
            
            if not response:
                print_error("Could not reach target")
                self.db.update_scan(scan_id, "failed")
                return None
            
            print_success(f"Connected (Status: {response.status_code})")
            print()
            
            # Store all headers
            self.headers_info = {
                'url': url,
                'status': response.status_code,
                'headers': dict(response.headers),
                'cookies': dict(response.cookies),
            }
            
            # Display all headers
            print_subsection("All Headers")
            self._display_all_headers(response.headers)
            
            # Check security headers
            print_subsection("Security Headers Analysis")
            self._check_security_headers(response.headers)
            
            # Check for information disclosure
            print_subsection("Information Disclosure")
            self._check_information_disclosure(response.headers)
            
            # Check cookies
            print_subsection("Cookie Analysis")
            self._analyze_cookies(response.cookies)
            
            # Check redirect security
            print_subsection("Redirect Analysis")
            self._analyze_redirects(response)
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.vulnerabilities))
            self.logger.scan_complete("header_analysis", url, len(self.vulnerabilities))
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.headers_info
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("header_analysis", url, str(e))
            print_error(f"Analysis failed: {e}")
            return None
    
    def _get_response(self, url):
        """Get HTTP response"""
        try:
            response = requests.get(
                url,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            return response
        except Exception as e:
            return None
    
    def _display_all_headers(self, headers):
        """Display all headers"""
        table_data = [["Header", "Value"]]
        
        for header, value in headers.items():
            table_data.append([header, value[:60]])
        
        print_table(table_data)
        print()
    
    def _check_security_headers(self, headers):
        """Check for security headers"""
        for header_name, header_info in self.SECURITY_HEADERS.items():
            value = headers.get(header_name)
            
            if value:
                # Header exists - check value
                check_method = getattr(self, header_info['check'], None)
                if check_method:
                    check_method(value)
                else:
                    print_success(f"{header_name}: {value[:50]}")
            else:
                # Header missing
                severity = header_info['severity']
                print_vuln_found(f"Missing {header_name}", severity, header_info['description'])
                self.vulnerabilities.append({
                    'type': f'Missing {header_name}',
                    'severity': severity,
                    'detail': header_info['description'],
                    'recommendation': header_info['recommendation'],
                })
        
        print()
    
    def _check_hsts(self, value):
        """Check HSTS header"""
        print_info(f"HSTS: {value}")
        
        # Check max-age
        import re
        max_age_match = re.search(r'max-age=(\d+)', value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                print_warning(f"  max-age too short: {max_age}")
                self.vulnerabilities.append({
                    'type': 'Weak HSTS',
                    'severity': 'LOW',
                    'detail': f'max-age={max_age}',
                    'recommendation': 'max-age=31536000',
                })
            else:
                print_success(f"  max-age: {max_age} (OK)")
        
        # Check includeSubDomains
        if 'includeSubDomains' in value:
            print_success("  includeSubDomains: Present")
        else:
            print_warning("  includeSubDomains: Missing")
        
        # Check preload
        if 'preload' in value:
            print_success("  preload: Present")
        else:
            print_info("  preload: Not present")
    
    def _check_csp(self, value):
        """Check Content Security Policy"""
        print_info(f"CSP: {value[:80]}...")
        
        # Check for unsafe directives
        unsafe_patterns = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-redirect'"]
        for pattern in unsafe_patterns:
            if pattern in value:
                print_warning(f"  Unsafe directive: {pattern}")
                self.vulnerabilities.append({
                    'type': f'Weak CSP: {pattern}',
                    'severity': 'MEDIUM',
                    'detail': f'CSP contains {pattern}',
                    'recommendation': 'Remove unsafe directives',
                })
        
        # Check for wildcards
        if "'*'" in value or "*" in value:
            print_warning("  Wildcard detected")
            self.vulnerabilities.append({
                'type': 'Weak CSP: Wildcard',
                'severity': 'MEDIUM',
                'detail': 'CSP contains wildcard',
                'recommendation': 'Use specific sources',
            })
    
    def _check_xframe(self, value):
        """Check X-Frame-Options"""
        print_info(f"X-Frame-Options: {value}")
        
        valid_values = ['DENY', 'SAMEORIGIN']
        if value.upper() in valid_values:
            print_success(f"  Value: {value} (OK)")
        else:
            print_warning(f"  Invalid value: {value}")
            self.vulnerabilities.append({
                'type': 'Invalid X-Frame-Options',
                'severity': 'LOW',
                'detail': f'Value: {value}',
                'recommendation': 'DENY or SAMEORIGIN',
            })
    
    def _check_content_type(self, value):
        """Check X-Content-Type-Options"""
        print_info(f"X-Content-Type-Options: {value}")
        
        if value.lower() == 'nosniff':
            print_success("  Value: nosniff (OK)")
        else:
            print_warning(f"  Invalid value: {value}")
    
    def _check_xss_protection(self, value):
        """Check X-XSS-Protection"""
        print_info(f"X-XSS-Protection: {value}")
        
        if value == '0':
            print_info("  XSS protection disabled (modern approach)")
        elif '1' in value:
            print_success("  XSS protection enabled")
    
    def _check_referrer(self, value):
        """Check Referrer-Policy"""
        print_info(f"Referrer-Policy: {value}")
        
        good_policies = [
            'no-referrer', 'no-referrer-when-downgrade',
            'origin', 'origin-when-cross-origin',
            'same-origin', 'strict-origin', 'strict-origin-when-cross-origin',
        ]
        
        if value in good_policies:
            print_success(f"  Policy: {value} (OK)")
        else:
            print_warning(f"  Policy could be improved: {value}")
    
    def _check_permissions(self, value):
        """Check Permissions-Policy"""
        print_info(f"Permissions-Policy: {value[:60]}...")
        print_success("  Permissions policy present")
    
    def _check_cross_domain(self, value):
        """Check X-Permitted-Cross-Domain-Policies"""
        print_info(f"X-Permitted-Cross-Domain-Policies: {value}")
        
        if value == 'none':
            print_success("  Cross-domain policies: none (OK)")
        else:
            print_warning("  Cross-domain policies allowed")
    
    def _check_coop(self, value):
        """Check Cross-Origin-Opener-Policy"""
        print_info(f"COOP: {value}")
    
    def _check_corp(self, value):
        """Check Cross-Origin-Resource-Policy"""
        print_info(f"CORP: {value}")
    
    def _check_coep(self, value):
        """Check Cross-Origin-Embedder-Policy"""
        print_info(f"COEP: {value}")
    
    def _check_information_disclosure(self, headers):
        """Check for information disclosure"""
        for header in self.DANGEROUS_HEADERS:
            value = headers.get(header)
            if value:
                print_warning(f"{header}: {value}")
                self.vulnerabilities.append({
                    'type': f'Information Disclosure: {header}',
                    'severity': 'LOW',
                    'detail': f'{header}: {value}',
                    'recommendation': f'Remove {header} header',
                })
        
        # Check for exposed internal headers
        internal_headers = [h for h in headers.keys() if 'internal' in h.lower() or 'debug' in h.lower()]
        for header in internal_headers:
            print_warning(f"Internal header exposed: {header}")
            self.vulnerabilities.append({
                'type': f'Internal Header Exposed: {header}',
                'severity': 'MEDIUM',
                'detail': f'{header}: {headers[header]}',
                'recommendation': f'Remove {header} header',
            })
        
        if not any(h in headers for h in self.DANGEROUS_HEADERS):
            print_success("No dangerous headers found")
        
        print()
    
    def _analyze_cookies(self, cookies):
        """Analyze cookies"""
        if not cookies:
            print_info("No cookies found")
            print()
            return
        
        for cookie in cookies:
            print_info(f"Cookie: {cookie.name}")
            
            # Check security flags
            if cookie.secure:
                print_success("  Secure: Yes")
            else:
                print_warning("  Secure: No")
                self.vulnerabilities.append({
                    'type': f'Insecure Cookie: {cookie.name}',
                    'severity': 'MEDIUM',
                    'detail': 'Cookie not marked as Secure',
                    'recommendation': 'Add Secure flag',
                })
            
            if 'httponly' in str(cookie).lower():
                print_success("  HttpOnly: Yes")
            else:
                print_warning("  HttpOnly: Not set")
            
            if 'samesite' in str(cookie).lower():
                print_success("  SameSite: Present")
            else:
                print_info("  SameSite: Not set")
        
        print()
    
    def _analyze_redirects(self, response):
        """Analyze redirects"""
        if len(response.history) == 0:
            print_info("No redirects")
            print()
            return
        
        print_info(f"Redirect chain ({len(response.history)} redirects):")
        
        for i, resp in enumerate(response.history):
            redirect_url = resp.headers.get('Location', 'N/A')
            print(f"  {i+1}. [{resp.status_code}] {resp.url[:60]}")
            print(f"     -> {redirect_url[:60]}")
        
        # Check for open redirect
        final_url = response.url
        if final_url and not final_url.startswith(response.history[0].url.split('/')[0] + '//'):
            print_warning("Possible open redirect detected")
            self.vulnerabilities.append({
                'type': 'Open Redirect',
                'severity': 'MEDIUM',
                'detail': f'Redirect to external domain: {final_url}',
                'recommendation': 'Validate redirect targets',
            })
        
        print()
    
    def _display_results(self):
        """Display analysis results"""
        print_section("HEADER ANALYSIS RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}ANALYSIS SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Total Headers:{Colors.BWHITE}    {len(self.headers_info.get('headers', {}))}")
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
                
                print(f"  {Colors.BCYAN}#{i}:{Colors.BWHITE} {vuln['type']}")
                print(f"     {Colors.BCYAN}Severity:{Colors.BWHITE} {severity_color}{vuln['severity']}")
                print(f"     {Colors.BCYAN}Detail:{Colors.BWHITE}   {vuln['detail']}")
                print(f"     {Colors.BCYAN}Fix:{Colors.BWHITE}       {vuln['recommendation']}")
                print()
        else:
            print_success("No vulnerabilities found")
        
        # Recommendations
        print_subsection("Summary of Recommendations")
        
        missing_headers = [v for v in self.vulnerabilities if v['type'].startswith('Missing')]
        weak_headers = [v for v in self.vulnerabilities if v['type'].startswith('Weak')]
        info_disclosure = [v for v in self.vulnerabilities if 'Information Disclosure' in v['type']]
        
        if missing_headers:
            print_info(f"- Add {len(missing_headers)} missing security headers")
        
        if weak_headers:
            print_info(f"- Strengthen {len(weak_headers)} weak headers")
        
        if info_disclosure:
            print_info(f"- Remove {len(info_disclosure)} information disclosure headers")
        
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
                        self.headers_info.get('url', ''),
                        vuln['detail'],
                        vuln['recommendation']
                    ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'scan_time': self.start_time.isoformat(),
                'headers': self.headers_info,
                'vulnerabilities': self.vulnerabilities,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
