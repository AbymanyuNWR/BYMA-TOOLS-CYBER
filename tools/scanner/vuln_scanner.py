"""
BYMA TOOLS - Advanced Vulnerability Scanner
Professional comprehensive vulnerability scanner with 50+ checks
"""
import requests
import re
import json
import ssl
import socket
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons, print_vuln_found
)
from core.logger import get_logger
from core.database import get_database


class VulnScanner:
    """Professional comprehensive vulnerability scanner"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.vulnerabilities = []
        self.warnings = []
        self.info_findings = []
        self.start_time = None
        self.target = None
    
    # Dangerous files that shouldn't be accessible
    DANGEROUS_FILES = [
        '/.env', '/config.php', '/wp-config.php', '/configuration.php',
        '/config/database.yml', '/config.json', '/settings.php',
        '/backup.sql', '/dump.sql', '/database.sql', '/db.sql',
        '/.git/HEAD', '/.git/config', '/.svn/entries', '/.hg/',
        '/.htaccess', '/.htpasswd', '/web.config', '/crossdomain.xml',
        '/server-status', '/server-info', '/phpinfo.php', '/info.php',
        '/test.php', '/debug.php', '/administrator/', '/phpmyadmin/',
        '/adminer.php', '/cpanel', '/webmail/', '/.DS_Store',
        '/Thumbs.db', '/.bash_history', '/.ssh/authorized_keys',
        '/proc/self/environ', '/etc/passwd', '/etc/shadow',
    ]
    
    # Common misconfigurations
    MISCONFIG_CHECKS = {
        'directory_listing': {
            'paths': ['/images/', '/uploads/', '/files/', '/assets/', '/static/',
                     '/css/', '/js/', '/includes/', '/lib/', '/tmp/'],
            'severity': 'MEDIUM',
            'title': 'Directory Listing Enabled',
            'description': 'Directory listing exposes file structure',
        },
        'debug_mode': {
            'indicators': ['debug=true', 'debug=1', 'DEBUG=True', 'APP_DEBUG=true'],
            'severity': 'MEDIUM',
            'title': 'Debug Mode Enabled',
            'description': 'Debug mode may expose sensitive information',
        },
        'default_pages': {
            'paths': ['/default.asp', '/default.aspx', '/index.php', '/test/',
                     '/welcome/', '/sample/', '/example/'],
            'severity': 'LOW',
            'title': 'Default Page Found',
            'description': 'Default installation pages may reveal technology info',
        },
    }
    
    # Technology-specific vulnerabilities
    TECH_VULNS = {
        'WordPress': {
            'paths': ['/wp-login.php', '/wp-admin/', '/xmlrpc.php', '/wp-json/'],
            'severity': 'INFO',
            'title': 'WordPress Installation Detected',
        },
        'PHP': {
            'headers': ['X-Powered-By: PHP'],
            'severity': 'LOW',
            'title': 'PHP Version Disclosure',
        },
        'Apache': {
            'headers': ['Server: Apache'],
            'severity': 'LOW',
            'title': 'Apache Server Disclosure',
        },
        'Nginx': {
            'headers': ['Server: nginx'],
            'severity': 'LOW',
            'title': 'Nginx Server Disclosure',
        },
        'IIS': {
            'headers': ['Server: Microsoft-IIS'],
            'severity': 'LOW',
            'title': 'IIS Server Disclosure',
        },
    }
    
    # SSL/TLS vulnerabilities
    SSL_CHECKS = {
        'ssl2': {'name': 'SSLv2', 'severity': 'CRITICAL'},
        'ssl3': {'name': 'SSLv3', 'severity': 'HIGH'},
        'tls1': {'name': 'TLSv1', 'severity': 'MEDIUM'},
        'tls11': {'name': 'TLSv1.1', 'severity': 'MEDIUM'},
    }
    
    def scan(self, target, output=None, depth='comprehensive'):
        """Main scan function with comprehensive checks"""
        self.start_time = datetime.now()
        self.target = target
        
        print_section(f"COMPREHENSIVE VULNERABILITY SCAN")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("vuln_scanner", target, "vulnerability")
        self.logger.scan_start("vuln_scanner", target)
        
        try:
            # Normalize target
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
                self.target = target
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {target}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Depth:{Colors.BWHITE}        {depth.upper()}")
            print_separator("-", 50)
            print()
            
            # Phase 1: Basic connectivity and response analysis
            print_subsection("Phase 1: Target Analysis")
            response = self._analyze_target(target)
            
            if not response:
                print_error("Could not connect to target")
                self.db.update_scan(scan_id, "failed")
                return []
            
            # Phase 2: Security header analysis
            print_subsection("Phase 2: Security Headers")
            self._check_security_headers(target, response)
            
            # Phase 3: Information disclosure
            print_subsection("Phase 3: Information Disclosure")
            self._check_info_disclosure(target, response)
            
            # Phase 4: Dangerous file exposure
            print_subsection("Phase 4: Dangerous File Exposure")
            self._check_dangerous_files(target)
            
            # Phase 5: Directory listing
            print_subsection("Phase 5: Directory Listing")
            self._check_directory_listing(target)
            
            # Phase 6: Common misconfigurations
            print_subsection("Phase 6: Misconfigurations")
            self._check_misconfigurations(target, response)
            
            # Phase 7: Technology detection and tech-specific vulns
            print_subsection("Phase 7: Technology Detection")
            self._check_technology_vulns(target, response)
            
            # Phase 8: SSL/TLS (if HTTPS)
            if target.startswith('https://'):
                print_subsection("Phase 8: SSL/TLS Analysis")
                self._check_ssl_vulns(target)
            
            # Phase 9: Common web vulnerabilities
            print_subsection("Phase 9: Web Vulnerabilities")
            self._check_web_vulns(target)
            
            # Phase 10: CORS and CSRF
            print_subsection("Phase 10: CORS & CSRF")
            self._check_cors_csrf(target)
            
            # Phase 11: Cookie security
            print_subsection("Phase 11: Cookie Security")
            self._check_cookie_security(response)
            
            # Phase 12: Error handling
            print_subsection("Phase 12: Error Handling")
            self._check_error_handling(target)
            
            # Phase 13: Backup files
            if depth == 'comprehensive':
                print_subsection("Phase 13: Backup File Detection")
                self._check_backup_files(target)
            
            # Phase 14: Sensitive data exposure
            print_subsection("Phase 14: Sensitive Data Exposure")
            self._check_sensitive_data(response)
            
            # Phase 15: HTTP methods
            print_subsection("Phase 15: HTTP Methods")
            self._check_http_methods(target)
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.vulnerabilities))
            self.logger.scan_complete("vuln_scanner", target, len(self.vulnerabilities))
            
            # Display results
            self._display_results()
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.vulnerabilities
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("vuln_scanner", target, str(e))
            print_error(f"Scan failed: {e}")
            return []
    
    def _analyze_target(self, target):
        """Analyze target and get initial response"""
        try:
            response = requests.get(target, timeout=15, verify=False, allow_redirects=True)
            
            # Store response info
            self.target_info = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'length': len(response.text),
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'technologies': [],
            }
            
            # Detect technologies
            self._detect_technologies(response)
            
            print_success(f"Connected: {response.status_code}")
            print_info(f"Server: {self.target_info['server']}")
            print_info(f"Technologies: {', '.join(self.target_info['technologies']) or 'Unknown'}")
            print()
            
            return response
        
        except requests.exceptions.SSLError:
            print_warning("SSL Certificate error - continuing anyway")
            try:
                response = requests.get(target, timeout=15, verify=False)
                return response
            except:
                return None
        except Exception as e:
            print_error(f"Connection failed: {e}")
            return None
    
    def _detect_technologies(self, response):
        """Detect technologies from response"""
        tech_indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress', 'wp-json'],
            'Joomla': ['joomla', '/components/', '/modules/'],
            'Drupal': ['drupal', 'sites/default/files'],
            'Laravel': ['laravel', 'csrf-token', 'laravel_session'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'Flask': ['werkzeug', 'flask'],
            'Spring': ['spring', 'thymeleaf', 'whitelabel'],
            'ASP.NET': ['__viewstate', 'asp.net', '__eventvalidation'],
            'PHP': ['.php', 'php', 'PHP'],
            'Node.js': ['Express', 'X-Powered-By: Express'],
            'Ruby on Rails': ['rails', 'ruby', 'X-Powered-By: Phusion Passenger'],
            'Python': ['python', 'X-Powered-By: Python'],
            'Apache': ['Apache'],
            'Nginx': ['nginx'],
            'IIS': ['Microsoft-IIS'],
            'LiteSpeed': ['LiteSpeed'],
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'Sucuri': ['sucuri'],
            'Akamai': ['akamai'],
        }
        
        headers_str = str(response.headers).lower()
        body_lower = response.text.lower()
        
        for tech, indicators in tech_indicators.items():
            for indicator in indicators:
                if indicator.lower() in headers_str or indicator.lower() in body_lower:
                    if tech not in self.target_info['technologies']:
                        self.target_info['technologies'].append(tech)
                    break
    
    def _check_security_headers(self, target, response):
        """Check for missing security headers"""
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': {
                'severity': 'MEDIUM',
                'title': 'Missing HSTS Header',
                'description': 'HTTP Strict Transport Security not enforced',
                'fix': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            },
            'Content-Security-Policy': {
                'severity': 'MEDIUM',
                'title': 'Missing Content Security Policy',
                'description': 'No CSP header to prevent XSS and injection attacks',
                'fix': "Add Content-Security-Policy header with appropriate directives",
            },
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'title': 'Missing X-Frame-Options Header',
                'description': 'Site may be vulnerable to clickjacking',
                'fix': 'Add X-Frame-Options: DENY or SAMEORIGIN',
            },
            'X-Content-Type-Options': {
                'severity': 'LOW',
                'title': 'Missing X-Content-Type-Options',
                'description': 'MIME type sniffing not prevented',
                'fix': 'Add X-Content-Type-Options: nosniff',
            },
            'X-XSS-Protection': {
                'severity': 'LOW',
                'title': 'Missing X-XSS-Protection',
                'description': 'Browser XSS filter not explicitly configured',
                'fix': 'Add X-XSS-Protection: 1; mode=block',
            },
            'Referrer-Policy': {
                'severity': 'LOW',
                'title': 'Missing Referrer-Policy',
                'description': 'Referrer information may leak to third parties',
                'fix': 'Add Referrer-Policy: strict-origin-when-cross-origin',
            },
            'Permissions-Policy': {
                'severity': 'LOW',
                'title': 'Missing Permissions-Policy',
                'description': 'Browser features not restricted',
                'fix': 'Add Permissions-Policy header',
            },
            'Cross-Origin-Opener-Policy': {
                'severity': 'LOW',
                'title': 'Missing COOP Header',
                'description': 'Cross-origin isolation not enforced',
                'fix': 'Add Cross-Origin-Opener-Policy: same-origin',
            },
            'Cross-Origin-Resource-Policy': {
                'severity': 'LOW',
                'title': 'Missing CORP Header',
                'description': 'Resource access not restricted',
                'fix': 'Add Cross-Origin-Resource-Policy: same-origin',
            },
        }
        
        found = 0
        missing = 0
        
        for header, info in security_headers.items():
            if header.lower() in {k.lower() for k in headers.keys()}:
                found += 1
            else:
                missing += 1
                self.vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'severity': info['severity'],
                    'title': info['title'],
                    'description': info['description'],
                    'evidence': f'Header {header} not found in response',
                    'fix': info['fix'],
                })
                print_warning(f"  Missing: {header}")
        
        print_info(f"  Found: {found} | Missing: {missing}")
        print()
    
    def _check_info_disclosure(self, target, response):
        """Check for information disclosure"""
        disclosures = []
        
        # Server header
        server = response.headers.get('Server', '')
        if server and server != 'Unknown':
            disclosures.append({
                'type': 'Server Disclosure',
                'severity': 'LOW',
                'title': 'Server Version Disclosure',
                'description': f'Server header reveals: {server}',
                'evidence': f'Server: {server}',
                'fix': 'Remove or obfuscate Server header',
            })
            print_warning(f"  Server: {server}")
        
        # X-Powered-By
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            disclosures.append({
                'type': 'Technology Disclosure',
                'severity': 'LOW',
                'title': 'Technology Disclosure',
                'description': f'X-Powered-By reveals: {powered_by}',
                'evidence': f'X-Powered-By: {powered_by}',
                'fix': 'Remove X-Powered-By header',
            })
            print_warning(f"  Powered-By: {powered_by}")
        
        # X-AspNet-Version
        asp_version = response.headers.get('X-AspNet-Version', '')
        if asp_version:
            disclosures.append({
                'type': 'ASP.NET Disclosure',
                'severity': 'LOW',
                'title': 'ASP.NET Version Disclosure',
                'description': f'X-AspNet-Version reveals: {asp_version}',
                'evidence': f'X-AspNet-Version: {asp_version}',
                'fix': 'Remove X-AspNet-Version header',
            })
            print_warning(f"  ASP.NET: {asp_version}")
        
        # Check for sensitive comments in HTML
        sensitive_patterns = [
            (r'<!--.*?TODO.*?-->', 'TODO Comment'),
            (r'<!--.*?FIXME.*?-->', 'FIXME Comment'),
            (r'<!--.*?BUG.*?-->', 'BUG Comment'),
            (r'<!--.*?HACK.*?-->', 'HACK Comment'),
            (r'<!--.*?password.*?-->', 'Password in Comment'),
            (r'<!--.*?secret.*?-->', 'Secret in Comment'),
            (r'<!--.*?api.?key.*?-->', 'API Key in Comment'),
        ]
        
        for pattern, name in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE | re.DOTALL)
            if matches:
                disclosures.append({
                    'type': 'Sensitive Comment',
                    'severity': 'MEDIUM',
                    'title': f'{name} Found',
                    'description': f'Sensitive information in HTML comment',
                    'evidence': matches[0][:100],
                    'fix': 'Remove sensitive comments from production code',
                })
                print_warning(f"  {name} found")
        
        # Check for meta generator tag
        generator = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
        if generator:
            print_info(f"  Generator: {generator.group(1)}")
        
        self.vulnerabilities.extend(disclosures)
        
        if not disclosures:
            print_success("  No information disclosure found")
        
        print()
    
    def _check_dangerous_files(self, target):
        """Check for exposed dangerous files"""
        found_files = []
        
        for file_path in self.DANGEROUS_FILES[:20]:
            try:
                url = urljoin(target, file_path)
                response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    # Verify it's not a custom 404
                    if len(response.text) > 50 and 'not found' not in response.text.lower()[:200]:
                        found_files.append({
                            'type': 'Exposed File',
                            'severity': 'HIGH' if file_path in ['/etc/passwd', '/.env', '/.git/HEAD'] else 'MEDIUM',
                            'title': f'Exposed File: {file_path}',
                            'description': f'File {file_path} is accessible',
                            'evidence': f'URL: {url} returned {response.status_code}',
                            'fix': f'Restrict access to {file_path}',
                        })
                        print_vuln_found(f'Exposed: {file_path}', 'HIGH', url)
            except:
                pass
        
        self.vulnerabilities.extend(found_files)
        
        if not found_files:
            print_success("  No dangerous files exposed")
        
        print()
    
    def _check_directory_listing(self, target):
        """Check for directory listing"""
        listing_paths = ['/images/', '/uploads/', '/files/', '/assets/', '/static/',
                        '/css/', '/js/', '/includes/', '/backup/', '/tmp/']
        
        found_listings = []
        
        for path in listing_paths:
            try:
                url = urljoin(target, path)
                response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    # Check for directory listing indicators
                    listing_indicators = [
                        'Index of', 'Directory listing', '<title>Index of',
                        'Parent Directory', '<pre>', 'Last modified',
                    ]
                    
                    if any(indicator in response.text for indicator in listing_indicators):
                        found_listings.append({
                            'type': 'Directory Listing',
                            'severity': 'MEDIUM',
                            'title': f'Directory Listing: {path}',
                            'description': f'Directory listing enabled at {path}',
                            'evidence': f'URL: {url}',
                            'fix': f'Disable directory listing for {path}',
                        })
                        print_warning(f"  Directory listing: {path}")
            except:
                pass
        
        self.vulnerabilities.extend(found_listings)
        
        if not found_listings:
            print_success("  No directory listing found")
        
        print()
    
    def _check_misconfigurations(self, target, response):
        """Check for common misconfigurations"""
        misconfigs = []
        
        # Check for debug mode
        debug_indicators = ['debug=true', 'debug=1', 'DEBUG=True', 'APP_DEBUG=true']
        for indicator in debug_indicators:
            if indicator.lower() in response.text.lower():
                misconfigs.append({
                    'type': 'Misconfiguration',
                    'severity': 'MEDIUM',
                    'title': 'Debug Mode Enabled',
                    'description': 'Debug mode may expose sensitive information',
                    'evidence': f'Found: {indicator}',
                    'fix': 'Disable debug mode in production',
                })
                print_warning(f"  Debug mode detected")
                break
        
        # Check for exposed admin panels
        admin_paths = ['/admin', '/administrator', '/wp-admin', '/cpanel', '/webmail']
        for path in admin_paths:
            try:
                url = urljoin(target, path)
                response_admin = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response_admin.status_code in [200, 301, 302]:
                    misconfigs.append({
                        'type': 'Exposed Admin',
                        'severity': 'LOW',
                        'title': f'Admin Panel Found: {path}',
                        'description': f'Admin panel accessible at {path}',
                        'evidence': f'URL: {url} returned {response_admin.status_code}',
                        'fix': 'Restrict access to admin panels',
                    })
                    print_warning(f"  Admin panel: {path}")
            except:
                pass
        
        # Check for exposed phpinfo
        phpinfo_paths = ['/phpinfo.php', '/info.php', '/test.php']
        for path in phpinfo_paths:
            try:
                url = urljoin(target, path)
                response_phpinfo = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response_phpinfo.status_code == 200 and 'phpinfo()' in response_phpinfo.text:
                    misconfigs.append({
                        'type': 'phpinfo Exposure',
                        'severity': 'MEDIUM',
                        'title': 'phpinfo() Found',
                        'description': f'phpinfo() exposed at {path}',
                        'evidence': f'URL: {url}',
                        'fix': 'Remove phpinfo() from production',
                    })
                    print_warning(f"  phpinfo: {path}")
            except:
                pass
        
        self.vulnerabilities.extend(misconfigs)
        
        if not misconfigs:
            print_success("  No misconfigurations found")
        
        print()
    
    def _check_technology_vulns(self, target, response):
        """Check for technology-specific vulnerabilities"""
        tech_vulns = []
        
        for tech, info in self.TECH_VULNS.items():
            if tech in self.target_info.get('technologies', []):
                # Check paths
                for path in info.get('paths', []):
                    try:
                        url = urljoin(target, path)
                        resp = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                        
                        if resp.status_code in [200, 301, 302, 401, 403]:
                            tech_vulns.append({
                                'type': 'Technology Detection',
                                'severity': info['severity'],
                                'title': f"{tech} Detected",
                                'description': f'{tech} installation found at {path}',
                                'evidence': f'URL: {url}',
                                'fix': f'Remove or restrict access to {path}',
                            })
                            print_info(f"  {tech}: {path}")
                            break
                    except:
                        pass
        
        self.vulnerabilities.extend(tech_vulns)
        
        if not tech_vulns:
            print_info("  No technology-specific issues found")
        
        print()
    
    def _check_ssl_vulns(self, target):
        """Check for SSL/TLS vulnerabilities"""
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Try to connect with different protocols
            protocols = {
                'SSLv2': ssl.PROTOCOL_SSLv2 if hasattr(ssl, 'PROTOCOL_SSLV2') else None,
                'SSLv3': ssl.PROTOCOL_SSLv23,
                'TLSv1': ssl.PROTOCOL_TLSv1,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            }
            
            for proto_name, proto_const in protocols.items():
                if proto_const is None:
                    continue
                
                try:
                    context = ssl.SSLContext(proto_const)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            self.vulnerabilities.append({
                                'type': 'SSL/TLS Vulnerability',
                                'severity': self.SSL_CHECKS.get(proto_name, {}).get('severity', 'MEDIUM'),
                                'title': f'{proto_name} Supported',
                                'description': f'{proto_name} protocol is supported',
                                'evidence': f'Connected with {proto_name}',
                                'fix': f'Disable {proto_name}',
                            })
                            print_warning(f"  {proto_name}: Supported (VULNERABLE)")
                except:
                    print_success(f"  {proto_name}: Not supported (OK)")
        
        except Exception as e:
            print_warning(f"  SSL check failed: {e}")
        
        print()
    
    def _check_web_vulns(self, target):
        """Check for common web vulnerabilities"""
        web_vulns = []
        
        # Check for open redirect
        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'ref']
        for param in redirect_params:
            try:
                url = f"{target}?{param}=http://evil.com"
                response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location:
                        web_vulns.append({
                            'type': 'Open Redirect',
                            'severity': 'MEDIUM',
                            'title': 'Open Redirect Vulnerability',
                            'description': f'Parameter {param} allows arbitrary redirects',
                            'evidence': f'Location: {location}',
                            'fix': 'Validate redirect targets',
                        })
                        print_warning(f"  Open redirect: {param}")
                        break
            except:
                pass
        
        # Check for host header injection
        try:
            headers = {'Host': 'evil.com'}
            response = requests.get(target, headers=headers, timeout=5, verify=False)
            
            if 'evil.com' in response.text or response.status_code == 200:
                web_vulns.append({
                    'type': 'Host Header Injection',
                    'severity': 'MEDIUM',
                    'title': 'Host Header Injection',
                    'description': 'Application responds to arbitrary Host headers',
                    'evidence': 'Application processed evil.com host header',
                    'fix': 'Validate Host header against whitelist',
                })
                print_warning("  Host header injection possible")
        except:
            pass
        
        self.vulnerabilities.extend(web_vulns)
        
        if not web_vulns:
            print_success("  No web vulnerabilities found")
        
        print()
    
    def _check_cors_csrf(self, target):
        """Check for CORS and CSRF issues"""
        cors_vulns = []
        
        # Check CORS
        try:
            headers = {'Origin': 'http://evil.com'}
            response = requests.get(target, headers=headers, timeout=5, verify=False)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if acao == '*':
                cors_vulns.append({
                    'type': 'CORS Misconfiguration',
                    'severity': 'MEDIUM',
                    'title': 'Wildcard CORS Origin',
                    'description': 'Access-Control-Allow-Origin set to *',
                    'evidence': f'ACAO: {acao}',
                    'fix': 'Use specific origin whitelist',
                })
                print_warning("  CORS: Wildcard origin")
            elif acao == 'http://evil.com':
                cors_vulns.append({
                    'type': 'CORS Misconfiguration',
                    'severity': 'HIGH',
                    'title': 'Origin Reflection',
                    'description': 'CORS reflects arbitrary origins',
                    'evidence': f'ACAO: {acao}',
                    'fix': 'Validate origins against whitelist',
                })
                print_warning("  CORS: Origin reflection")
            else:
                print_success("  CORS: Configured properly")
        except:
            print_info("  CORS: Could not test")
        
        self.vulnerabilities.extend(cors_vulns)
        print()
    
    def _check_cookie_security(self, response):
        """Check cookie security"""
        cookie_vulns = []
        
        for cookie in response.cookies:
            issues = []
            
            if not cookie.secure:
                issues.append('Missing Secure flag')
            
            if 'httponly' not in str(cookie).lower():
                issues.append('Missing HttpOnly flag')
            
            if 'samesite' not in str(cookie).lower():
                issues.append('Missing SameSite attribute')
            
            if issues:
                cookie_vulns.append({
                    'type': 'Insecure Cookie',
                    'severity': 'MEDIUM',
                    'title': f'Insecure Cookie: {cookie.name}',
                    'description': '; '.join(issues),
                    'evidence': f'Cookie: {cookie.name}',
                    'fix': 'Add Secure, HttpOnly, and SameSite flags',
                })
                print_warning(f"  {cookie.name}: {', '.join(issues)}")
        
        self.vulnerabilities.extend(cookie_vulns)
        
        if not cookie_vulns:
            if response.cookies:
                print_success("  All cookies properly configured")
            else:
                print_info("  No cookies found")
        
        print()
    
    def _check_error_handling(self, target):
        """Check error handling"""
        error_vulns = []
        
        # Trigger errors
        error_triggers = [
            ("'", "SQL Error"),
            ("<script>", "XSS Error"),
            ("../../../etc/passwd", "Path Traversal Error"),
            ("%00", "Null Byte Error"),
        ]
        
        for payload, error_type in error_triggers:
            try:
                url = f"{target}?test={payload}"
                response = requests.get(url, timeout=5, verify=False)
                
                # Check for verbose errors
                error_indicators = [
                    'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                    'SQLite', 'Microsoft OLE DB', 'ODBC SQL Server',
                    'Warning:', 'Fatal error:', 'Parse error:',
                    'Stack trace', 'Exception in', 'Traceback',
                    'syntax error', 'unexpected token',
                ]
                
                for indicator in error_indicators:
                    if indicator.lower() in response.text.lower():
                        error_vulns.append({
                            'type': 'Verbose Error',
                            'severity': 'MEDIUM',
                            'title': f'{error_type} Disclosure',
                            'description': f'Verbose error messages exposed',
                            'evidence': f'Error indicator: {indicator}',
                            'fix': 'Implement custom error pages',
                        })
                        print_warning(f"  {error_type}: Verbose errors")
                        break
            except:
                pass
        
        self.vulnerabilities.extend(error_vulns)
        
        if not error_vulns:
            print_success("  Error handling appears secure")
        
        print()
    
    def _check_backup_files(self, target):
        """Check for backup files"""
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.swp',
                           '.tar', '.tar.gz', '.zip', '.sql', '.sql.gz']
        
        common_names = ['config', 'database', 'backup', 'db', 'site', 'www']
        
        found_backups = []
        
        for name in common_names:
            for ext in backup_extensions[:5]:
                try:
                    path = f"/{name}{ext}"
                    url = urljoin(target, path)
                    response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                    
                    if response.status_code == 200 and len(response.content) > 100:
                        found_backups.append({
                            'type': 'Backup File',
                            'severity': 'HIGH',
                            'title': f'Backup File Found: {path}',
                            'description': f'Backup file accessible at {path}',
                            'evidence': f'URL: {url} ({len(response.content)} bytes)',
                            'fix': f'Remove or restrict access to {path}',
                        })
                        print_warning(f"  Backup: {path} ({len(response.content)} bytes)")
                except:
                    pass
        
        self.vulnerabilities.extend(found_backups)
        
        if not found_backups:
            print_success("  No backup files found")
        
        print()
    
    def _check_sensitive_data(self, response):
        """Check for sensitive data exposure"""
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email Address'),
            (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'Phone Number'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN Pattern'),
            (r'(?:password|passwd|pwd)\s*[=:]\s*["\']?[^"\'\s]+', 'Password'),
            (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?[^"\'\s]+', 'API Key'),
            (r'(?:secret|token)\s*[=:]\s*["\']?[^"\'\s]+', 'Secret/Token'),
        ]
        
        found_data = []
        
        for pattern, name in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                found_data.append({
                    'type': 'Sensitive Data',
                    'severity': 'HIGH' if name in ['Password', 'API Key', 'Secret/Token'] else 'MEDIUM',
                    'title': f'{name} Exposed',
                    'description': f'{name} found in response',
                    'evidence': f'Found {len(matches)} instances',
                    'fix': 'Remove sensitive data from public responses',
                })
                print_warning(f"  {name}: {len(matches)} instances")
        
        self.vulnerabilities.extend(found_data)
        
        if not found_data:
            print_success("  No sensitive data exposure found")
        
        print()
    
    def _check_http_methods(self, target):
        """Check HTTP methods"""
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        
        try:
            # OPTIONS request
            response = requests.options(target, timeout=5, verify=False)
            allowed = response.headers.get('Allow', '').upper()
            
            if 'TRACE' in allowed:
                self.vulnerabilities.append({
                    'type': 'Dangerous HTTP Method',
                    'severity': 'MEDIUM',
                    'title': 'TRACE Method Enabled',
                    'description': 'TRACE method can be used for XST attacks',
                    'evidence': f'Allow: {allowed}',
                    'fix': 'Disable TRACE method',
                })
                print_warning("  TRACE method enabled")
            
            # Check for other dangerous methods
            for method in dangerous_methods:
                if method in allowed:
                    print_info(f"  {method}: Allowed")
            
            if 'TRACE' not in allowed:
                print_success("  TRACE method disabled")
        
        except:
            print_info("  Could not test HTTP methods")
        
        print()
    
    def _save_to_database(self, scan_id):
        """Save vulnerabilities to database"""
        try:
            with self.db._cursor() as cursor:
                for vuln in self.vulnerabilities:
                    cursor.execute("""
                        INSERT INTO vulnerabilities 
                        (scan_id, vuln_type, severity, location, evidence, payload)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        vuln.get('type', 'Unknown'),
                        vuln.get('severity', 'UNKNOWN'),
                        self.target,
                        vuln.get('description', ''),
                        vuln.get('evidence', ''),
                    ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _display_results(self):
        """Display scan results"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        print_section("VULNERABILITY SCAN RESULTS")
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}SCAN SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {self.target}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Duration:{Colors.BWHITE}      {elapsed:.1f}s")
        print(f"  {Icons.INFO} {Colors.BCYAN}Technologies:{Colors.BWHITE}  {', '.join(self.target_info.get('technologies', []))}")
        
        # Vulnerability counts
        severity_counts = {}
        for vuln in self.vulnerabilities:
            sev = vuln.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print(f"  {Icons.WARNING} {Colors.BCYAN}Vulnerabilities:{Colors.BWHITE} {len(self.vulnerabilities)}")
        
        if severity_counts:
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in severity_counts:
                    color = Colors.BRED if sev == 'CRITICAL' else Colors.RED if sev == 'HIGH' else Colors.BYELLOW if sev == 'MEDIUM' else Colors.BCYAN
                    print(f"       {color}{sev}: {severity_counts[sev]}{Colors.RESET}")
        
        print_separator("-", 50)
        print()
        
        # Display vulnerabilities by severity
        if self.vulnerabilities:
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                vulns = [v for v in self.vulnerabilities if v.get('severity') == sev]
                if vulns:
                    print_subsection(f"{sev} Vulnerabilities")
                    
                    table_data = [["#", "Title", "Evidence"]]
                    for i, vuln in enumerate(vulns[:10], 1):
                        table_data.append([
                            str(i),
                            vuln.get('title', 'Unknown')[:40],
                            vuln.get('evidence', '')[:30],
                        ])
                    
                    print_table(table_data)
                    print()
        else:
            print_success("No vulnerabilities found!")
        
        print()
    
    def _save_results(self, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'target': self.target,
                'scan_time': self.start_time.isoformat(),
                'technologies': self.target_info.get('technologies', []),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
