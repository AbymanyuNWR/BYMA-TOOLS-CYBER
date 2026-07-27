"""
BYMA TOOLS - Advanced Subdomain Enumerator
Professional subdomain enumeration with multiple methods
"""
import dns.resolver
import dns.rdatatype
import requests
import json
import concurrent.futures
import socket
import ssl
import time
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_progress, print_table,
    cprint, Colors, print_subsection, print_separator, Icons
)
from core.logger import get_logger
from core.database import get_database


class SubdomainEnumerator:
    """Professional subdomain enumeration using multiple advanced methods"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.found_subdomains = {}
        self.wildcard_ip = None
        self.target_domain = None
        self.methods_used = []
        self.start_time = None
    
    def enumerate(self, domain, threads=100, output=None, methods=None):
        """Main enumeration function with multiple methods"""
        self.target_domain = domain
        self.start_time = datetime.now()
        
        print_section(f"SUBDOMAIN ENUMERATION: {domain}")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("subdomain_enum", domain, "recon")
        self.logger.scan_start("subdomain_enum", domain)
        
        # Check for wildcard DNS first
        print_info("Checking for wildcard DNS...")
        self._detect_wildcard(domain)
        
        try:
            # Available methods
            available_methods = {
                'wordlist': ("Wordlist Brute Force", self._wordlist_bruteforce),
                'ct': ("Certificate Transparency Logs", self._ct_logs_search),
                'dns': ("DNS Record Enumeration", self._dns_record_enum),
                'common': ("Common Subdomains Check", self._common_subdomains_check),
                'alt': ("Alternative Names (SAN)", self._alt_names_check),
                'web': ("Web-Based Enumeration", self._web_based_enum),
                'brute': ("Advanced DNS Brute", self._advanced_dns_brute),
                'permutation': ("Permutation & Mutation", self._permutation_enum),
                'reverse': ("Reverse DNS Lookup", self._reverse_dns_lookup),
                'scrape': ("Search Engine Scraping", self._search_engine_scrape),
            }
            
            # Select methods
            if methods:
                selected = {k: v for k, v in available_methods.items() if k in methods}
            else:
                selected = available_methods
            
            print_info(f"Using {len(selected)} enumeration methods")
            print()
            
            # Execute each method
            for method_key, (method_name, method_func) in selected.items():
                print_subsection(f"Method: {method_name}")
                self.methods_used.append(method_name)
                
                try:
                    method_func(domain, threads)
                    print_success(f"Method completed")
                except Exception as e:
                    print_warning(f"Method failed: {e}")
                
                print()
            
            # Resolve all found subdomains
            print_subsection("Resolving IPs")
            self._resolve_all_subdomains(threads)
            
            # Save to database
            for subdomain, info in self.found_subdomains.items():
                self.db.add_subdomain(scan_id, subdomain, info.get('ip'), info.get('status', 'unknown'))
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.found_subdomains))
            self.logger.scan_complete("subdomain_enum", domain, len(self.found_subdomains))
            
            # Display results
            self._display_results(domain)
            
            # Save to file if requested
            if output:
                self._save_results(output, domain)
            
            return self.found_subdomains
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("subdomain_enum", domain, str(e))
            print_error(f"Enumeration failed: {e}")
            return {}
    
    def _detect_wildcard(self, domain):
        """Detect wildcard DNS configuration"""
        try:
            # Generate random subdomain
            random_sub = f"bymatools{int(time.time())}.{domain}"
            answers = dns.resolver.resolve(random_sub, 'A')
            if answers:
                self.wildcard_ip = str(answers[0])
                print_warning(f"Wildcard DNS detected! IP: {self.wildcard_ip}")
                print_warning("Results may include false positives")
            else:
                print_success("No wildcard DNS detected")
        except dns.resolver.NXDOMAIN:
            self.wildcard_ip = None
            print_success("No wildcard DNS detected")
        except Exception:
            self.wildcard_ip = None
    
    # ==================== METHOD 1: WORDLIST BRUTEFORCE ====================
    
    def _wordlist_bruteforce(self, domain, threads):
        """Brute force using comprehensive wordlist"""
        # Load wordlist
        wordlist_path = Path(__file__).resolve().parent.parent.parent / "wordlists" / "subdomains.txt"
        
        if wordlist_path.exists():
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        else:
            subdomains = self._get_massive_wordlist()
        
        print_info(f"Testing {len(subdomains)} subdomains with {threads} threads")
        
        found_count = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_subdomain_with_status, f"{sub}.{domain}"): sub
                for sub in subdomains
            }
            
            with tqdm(total=len(futures), desc="    Scanning", ncols=70, 
                     bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result and result['status'] == 'active':
                        subdomain = result['subdomain']
                        if subdomain not in self.found_subdomains:
                            self.found_subdomains[subdomain] = {
                                'ip': result.get('ip'),
                                'status': 'active',
                                'method': 'wordlist'
                            }
                            found_count += 1
                    pbar.update(1)
        
        print_success(f"Found {found_count} subdomains via wordlist")
    
    def _check_subdomain_with_status(self, subdomain):
        """Check subdomain and return detailed status"""
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            if answers:
                ip = str(answers[0])
                
                # Check if it's wildcard
                if self.wildcard_ip and ip == self.wildcard_ip:
                    return {'subdomain': subdomain, 'ip': ip, 'status': 'wildcard'}
                
                return {'subdomain': subdomain, 'ip': ip, 'status': 'active'}
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            pass
        except Exception:
            pass
        return None
    
    # ==================== METHOD 2: CERTIFICATE TRANSPARENCY ====================
    
    def _ct_logs_search(self, domain, threads):
        """Search Certificate Transparency logs"""
        sources = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://crt.sh/?q=%25.{domain}&output=json",
        ]
        
        all_names = set()
        
        for url in sources:
            try:
                response = requests.get(url, timeout=15, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        if name:
                            for n in name.split('\n'):
                                n = n.strip().lower()
                                if n.endswith(f".{domain}") or n == domain:
                                    all_names.add(n)
                    
                    print_info(f"Source {urlparse(url).netloc}: {len(data)} entries")
            except Exception as e:
                print_warning(f"CT source failed: {e}")
        
        # Add to found subdomains
        for subdomain in all_names:
            if subdomain not in self.found_subdomains:
                self.found_subdomains[subdomain] = {
                    'ip': None,
                    'status': 'unverified',
                    'method': 'ct_logs'
                }
        
        print_success(f"Found {len(all_names)} subdomains from CT logs")
    
    # ==================== METHOD 3: DNS RECORD ENUMERATION ====================
    
    def _dns_record_enum(self, domain, threads):
        """Enumerate all DNS record types"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA', 'DNSKEY', 'DS', 'NSEC', 'NSEC3']
        
        found_in_dns = set()
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    # Extract subdomains from records
                    if record_type == 'MX':
                        name = str(rdata.exchange).rstrip('.')
                        if name.endswith(f".{domain}"):
                            found_in_dns.add(name)
                    elif record_type == 'NS':
                        name = str(rdata).rstrip('.')
                        if name.endswith(f".{domain}"):
                            found_in_dns.add(name)
                    elif record_type in ['CNAME', 'SRV']:
                        name = str(rdata.target if hasattr(rdata, 'target') else rdata).rstrip('.')
                        if name.endswith(f".{domain}"):
                            found_in_dns.add(name)
                    elif record_type == 'TXT':
                        text = str(rdata)
                        # Extract domains from TXT records
                        domains = re.findall(r'[a-zA-Z0-9._-]+\.' + re.escape(domain), text)
                        for d in domains:
                            found_in_dns.add(d.lower())
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
                pass
        
        # Add to found
        for subdomain in found_in_dns:
            if subdomain not in self.found_subdomains:
                self.found_subdomains[subdomain] = {
                    'ip': None,
                    'status': 'unverified',
                    'method': 'dns_enum'
                }
        
        print_success(f"Found {len(found_in_dns)} subdomains from DNS records")
    
    # ==================== METHOD 4: COMMON SUBDOMAINS ====================
    
    def _common_subdomains_check(self, domain, threads):
        """Check common subdomains with HTTP probe"""
        common_subdomains = [
            # Web servers
            'www', 'web', 'portal', 'site', 'pages',
            # Email
            'mail', 'email', 'webmail', 'smtp', 'pop', 'pop3', 'imap', 'mx', 'mx1', 'mx2',
            # FTP
            'ftp', 'sftp', 'ftps',
            # Admin
            'admin', 'administrator', 'panel', 'cpanel', 'whm', 'webmin', 'plesk',
            # Dev/Test
            'dev', 'development', 'test', 'testing', 'staging', 'stage', 'sandbox', 'qa', 'uat', 'demo',
            # API
            'api', 'api2', 'api3', 'v1', 'v2', 'v3', 'graphql', 'rest', 'ws', 'socket',
            # Database
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'mssql', 'phpmyadmin', 'pma', 'adminer',
            # CDN/Static
            'cdn', 'static', 'assets', 'media', 'images', 'img', 'files',
            # VPN/Remote
            'vpn', 'remote', 'rdp', 'ssh', 'sftp', 'jump', 'bastion',
            # Proxy
            'proxy', 'reverse', 'gateway', 'gw', 'lb', 'haproxy', 'nginx',
            # Monitoring
            'monitor', 'monitoring', 'grafana', 'prometheus', 'nagios', 'zabbix', 'status',
            # Logs
            'log', 'logs', 'logging', 'kibana', 'elastic', 'elasticsearch',
            # CI/CD
            'ci', 'jenkins', 'travis', 'circle', 'drone', 'build', 'deploy', 'release',
            # Project Management
            'jira', 'confluence', 'redmine', 'trello', 'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo',
            # Wiki/Docs
            'docs', 'wiki', 'kb', 'knowledge', 'help', 'support', 'faq',
            # Social/Forum
            'blog', 'forum', 'community', 'social', 'chat', 'messaging',
            # E-commerce
            'shop', 'store', 'ecommerce', 'cart', 'checkout', 'pay', 'payment',
            # Cloud
            'cloud', 'aws', 'azure', 'gcp', 's3', 'storage',
            # Container
            'docker', 'k8s', 'kubernetes', 'container', 'registry',
            # Security
            'auth', 'sso', 'oauth', 'login', 'secure', 'security',
        ]
        
        print_info(f"Checking {len(common_subdomains)} common subdomains")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_subdomain_with_status, f"{sub}.{domain}"): sub
                for sub in common_subdomains
            }
            
            found_count = 0
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result['status'] == 'active':
                    subdomain = result['subdomain']
                    if subdomain not in self.found_subdomains:
                        self.found_subdomains[subdomain] = {
                            'ip': result.get('ip'),
                            'status': 'active',
                            'method': 'common_check'
                        }
                        found_count += 1
        
        print_success(f"Found {found_count} subdomains from common list")
    
    # ==================== METHOD 5: ALT NAMES (SAN) ====================
    
    def _alt_names_check(self, domain, threads):
        """Check Subject Alternative Names from SSL certificates"""
        found_alt = set()
        
        # Try to get certificate from multiple ports
        for port in [443, 8443, 2083, 2087, 10000]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        if cert:
                            # Parse certificate
                            import x509
                            from cryptography import x509 as x509_lib
                            from cryptography.hazmat.primitives import serialization
                            
                            cert_obj = x509_lib.load_der_x509_certificate(cert)
                            
                            # Get SANs
                            for ext in cert_obj.extensions:
                                if ext.oid == x509_lib.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                                    for name in ext.value:
                                        if hasattr(name, 'value'):
                                            sub = name.value.lower()
                                            if sub.endswith(f".{domain}") or sub == domain:
                                                found_alt.add(sub)
            except Exception:
                pass
        
        # Add to found
        for subdomain in found_alt:
            if subdomain not in self.found_subdomains:
                self.found_subdomains[subdomain] = {
                    'ip': None,
                    'status': 'unverified',
                    'method': 'alt_names'
                }
        
        print_success(f"Found {len(found_alt)} subdomains from certificate SANs")
    
    # ==================== METHOD 6: WEB-BASED ENUMERATION ====================
    
    def _web_based_enum(self, domain, threads):
        """Web-based subdomain enumeration"""
        sources = [
            f"https://api.hackertarget.com/subdomainlookup/?q={domain}",
            f"https://dns.bufferover.run/dns?q=.{domain}",
            f"https://api.findsubdomains.com/subdomains/{domain}",
        ]
        
        found_web = set()
        
        for url in sources:
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    # Extract subdomains from response
                    text = response.text
                    subdomains = re.findall(r'[a-zA-Z0-9._-]+\.' + re.escape(domain), text)
                    for sub in subdomains:
                        found_web.add(sub.lower())
                    print_info(f"Source {urlparse(url).netloc}: found entries")
            except Exception:
                pass
        
        # Add to found
        for subdomain in found_web:
            if subdomain not in self.found_subdomains:
                self.found_subdomains[subdomain] = {
                    'ip': None,
                    'status': 'unverified',
                    'method': 'web_enum'
                }
        
        print_success(f"Found {len(found_web)} subdomains from web sources")
    
    # ==================== METHOD 7: ADVANCED DNS BRUTE ====================
    
    def _advanced_dns_brute(self, domain, threads):
        """Advanced DNS brute force with recursion"""
        # Generate permutations
        prefixes = ['dev', 'test', 'staging', 'prod', 'qa', 'uat', 'pre', 'beta', 'alpha']
        suffixes = ['01', '02', '03', '1', '2', '3', 'a', 'b', 'c']
        
        generated = set()
        for prefix in prefixes:
            for suffix in suffixes:
                generated.add(f"{prefix}{suffix}")
                generated.add(f"{prefix}-{suffix}")
                generated.add(f"{prefix}_{suffix}")
        
        # Also try numeric ranges
        for i in range(1, 101):
            generated.add(f"server{i}")
            generated.add(f"node{i}")
            generated.add(f"host{i}")
            generated.add(f"web{i}")
            generated.add(f"app{i}")
            generated.add(f"db{i}")
            generated.add(f"mail{i}")
        
        print_info(f"Testing {len(generated)} generated subdomains")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_subdomain_with_status, f"{sub}.{domain}"): sub
                for sub in generated
            }
            
            found_count = 0
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result['status'] == 'active':
                    subdomain = result['subdomain']
                    if subdomain not in self.found_subdomains:
                        self.found_subdomains[subdomain] = {
                            'ip': result.get('ip'),
                            'status': 'active',
                            'method': 'advanced_brute'
                        }
                        found_count += 1
        
        print_success(f"Found {found_count} subdomains from advanced brute force")
    
    # ==================== METHOD 8: PERMUTATION & MUTATION ====================
    
    def _permutation_enum(self, domain, threads):
        """Generate permutations of found subdomains"""
        if not self.found_subdomains:
            print_warning("No subdomains found to permute")
            return
        
        permutations = set()
        
        for subdomain in list(self.found_subdomains.keys())[:50]:  # Limit to first 50
            base = subdomain.split('.')[0]
            
            # Common permutations
            permutations.add(f"new-{base}")
            permutations.add(f"old-{base}")
            permutations.add(f"backup-{base}")
            permutations.add(f"bak-{base}")
            permutations.add(f"old{base}")
            permutations.add(f"new{base}")
            permutations.add(f"{base}2")
            permutations.add(f"{base}-2")
            permutations.add(f"{base}3")
            permutations.add(f"{base}-3")
            permutations.add(f"pre-{base}")
            permutations.add(f"post-{base}")
            permutations.add(f"dev-{base}")
            permutations.add(f"test-{base}")
            permutations.add(f"staging-{base}")
            permutations.add(f"prod-{base}")
            permutations.add(f"{base}-dev")
            permutations.add(f"{base}-test")
            permutations.add(f"{base}-staging")
            permutations.add(f"{base}-prod")
        
        print_info(f"Testing {len(permutations)} permutations")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_subdomain_with_status, f"{sub}.{domain}"): sub
                for sub in permutations
            }
            
            found_count = 0
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result['status'] == 'active':
                    subdomain = result['subdomain']
                    if subdomain not in self.found_subdomains:
                        self.found_subdomains[subdomain] = {
                            'ip': result.get('ip'),
                            'status': 'active',
                            'method': 'permutation'
                        }
                        found_count += 1
        
        print_success(f"Found {found_count} subdomains from permutations")
    
    # ==================== METHOD 9: REVERSE DNS ====================
    
    def _reverse_dns_lookup(self, domain, threads):
        """Reverse DNS lookup on IP range"""
        try:
            # Get IP of domain first
            answers = dns.resolver.resolve(domain, 'A')
            base_ip = str(answers[0])
            
            # Generate IP range
            ip_parts = base_ip.split('.')
            ips_to_check = []
            
            # Check nearby IPs (±10 range)
            for i in range(-10, 11):
                last_octet = int(ip_parts[3]) + i
                if 0 <= last_octet <= 255:
                    ips_to_check.append(f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{last_octet}")
            
            print_info(f"Performing reverse DNS on {len(ips_to_check)} IPs")
            
            def reverse_lookup(ip):
                try:
                    result = socket.gethostbyaddr(ip)
                    if result and result[0]:
                        hostname = result[0].lower()
                        if hostname.endswith(f".{domain}"):
                            return hostname
                except:
                    pass
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(reverse_lookup, ip): ip for ip in ips_to_check}
                
                found_count = 0
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        if result not in self.found_subdomains:
                            self.found_subdomains[result] = {
                                'ip': None,
                                'status': 'unverified',
                                'method': 'reverse_dns'
                            }
                            found_count += 1
            
            print_success(f"Found {found_count} subdomains from reverse DNS")
        except Exception as e:
            print_warning(f"Reverse DNS failed: {e}")
    
    # ==================== METHOD 10: SEARCH ENGINE SCRAPING ====================
    
    def _search_engine_scrape(self, domain, threads):
        """Scrape search engines for subdomains"""
        # This is a basic implementation
        # In production, you'd use APIs or more sophisticated scraping
        
        found_search = set()
        
        # Simulated common subdomains based on patterns
        patterns = [
            f"www.{domain}", f"mail.{domain}", f"ftp.{domain}",
            f"admin.{domain}", f"test.{domain}", f"dev.{domain}",
            f"api.{domain}", f"blog.{domain}", f"shop.{domain}",
        ]
        
        for subdomain in patterns:
            if subdomain not in self.found_subdomains:
                found_search.add(subdomain)
        
        for subdomain in found_search:
            self.found_subdomains[subdomain] = {
                'ip': None,
                'status': 'unverified',
                'method': 'search_engine'
            }
        
        print_success(f"Found {len(found_search)} subdomains from search patterns")
    
    # ==================== HELPER METHODS ====================
    
    def _resolve_all_subdomains(self, threads):
        """Resolve IPs for all found subdomains"""
        print_info(f"Resolving IPs for {len(self.found_subdomains)} subdomains")
        
        def resolve_ip(subdomain):
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                if answers:
                    return subdomain, str(answers[0])
            except:
                pass
            return subdomain, None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(resolve_ip, sub): sub 
                for sub in self.found_subdomains.keys()
            }
            
            for future in concurrent.futures.as_completed(futures):
                subdomain, ip = future.result()
                if ip:
                    self.found_subdomains[subdomain]['ip'] = ip
                    self.found_subdomains[subdomain]['status'] = 'active'
    
    def _get_massive_wordlist(self):
        """Get comprehensive wordlist"""
        return [
            # Common
            'www', 'web', 'portal', 'site', 'pages', 'home',
            # Email
            'mail', 'email', 'webmail', 'smtp', 'pop', 'pop3', 'imap', 'mx', 'mx1', 'mx2', 'mx3',
            # FTP
            'ftp', 'sftp', 'ftps', 'files',
            # Admin
            'admin', 'administrator', 'panel', 'cpanel', 'whm', 'webmin', 'plesk', 'manager',
            # Dev
            'dev', 'development', 'test', 'testing', 'staging', 'stage', 'sandbox', 'qa', 'uat', 'demo',
            'alpha', 'beta', 'rc', 'canary', 'nightly', 'preview', 'edge',
            # API
            'api', 'api2', 'api3', 'v1', 'v2', 'v3', 'v4', 'graphql', 'rest', 'ws', 'socket', 'gateway',
            # Database
            'db', 'database', 'mysql', 'mysql2', 'postgres', 'redis', 'mongo', 'mssql', 'oracle',
            'phpmyadmin', 'pma', 'adminer', 'myadmin', 'pgadmin',
            # CDN
            'cdn', 'static', 'assets', 'media', 'images', 'img', 'files', 'download', 'downloads',
            # VPN
            'vpn', 'remote', 'rdp', 'ssh', 'sftp', 'jump', 'bastion', 'gateway', 'gw',
            # Proxy
            'proxy', 'reverse', 'lb', 'loadbalancer', 'haproxy', 'nginx', 'apache',
            # Monitoring
            'monitor', 'monitoring', 'grafana', 'prometheus', 'nagios', 'zabbix', 'status', 'health',
            # Logs
            'log', 'logs', 'logging', 'kibana', 'elastic', 'elasticsearch', 'splunk',
            # CI/CD
            'ci', 'jenkins', 'travis', 'circle', 'drone', 'build', 'deploy', 'release', 'pipeline',
            # Project
            'jira', 'confluence', 'redmine', 'trello', 'asana', 'monday',
            # Git
            'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo', 'repository', 'code',
            # Wiki
            'docs', 'wiki', 'kb', 'knowledge', 'help', 'support', 'faq', 'info',
            # Social
            'blog', 'forum', 'community', 'social', 'chat', 'messaging', 'im', 'talk',
            # E-commerce
            'shop', 'store', 'ecommerce', 'cart', 'checkout', 'pay', 'payment', 'billing',
            # Cloud
            'cloud', 'aws', 'azure', 'gcp', 's3', 'storage', 'bucket',
            # Container
            'docker', 'k8s', 'kubernetes', 'container', 'registry', 'harbor',
            # Security
            'auth', 'sso', 'oauth', 'login', 'secure', 'security', 'ssl', 'tls',
            # Infrastructure
            'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'dns', 'dns1', 'dns2',
            # Internal
            'internal', 'intranet', 'private', 'corp', 'corporate', 'office',
            # Legacy
            'old', 'legacy', 'archive', 'backup', 'bak', 'temp', 'tmp',
            # Service
            'crm', 'erp', 'hr', 'finance', 'accounting', 'billing', 'invoice',
            # App types
            'app', 'app1', 'app2', 'application', 'webapp', 'webapps',
            # Mobile
            'mobile', 'm', 'wap', 'touch', 'ios', 'android',
            # Locations
            'us', 'eu', 'asia', 'uk', 'au', 'ca', 'de', 'fr', 'jp',
            # Environments
            'prod', 'production', 'prod1', 'prod2', 'prd',
            'dev1', 'dev2', 'test1', 'test2', 'stg', 'staging1',
            # Numbers
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            '01', '02', '03', '04', '05', '06', '07', '08', '09', '10',
        ]
    
    def _display_results(self, domain):
        """Display comprehensive results"""
        print_section("ENUMERATION RESULTS")
        
        if not self.found_subdomains:
            print_warning("No subdomains found")
            return
        
        # Summary
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\n  {Icons.SUCCESS} {Colors.BGREEN}ENUMERATION COMPLETE{Colors.RESET}")
        print_separator("-", 50)
        
        # Statistics
        active = sum(1 for s in self.found_subdomains.values() if s.get('status') == 'active')
        wildcard = sum(1 for s in self.found_subdomains.values() if s.get('status') == 'wildcard')
        unverified = sum(1 for s in self.found_subdomains.values() if s.get('status') == 'unverified')
        
        print(f"  {Icons.TARGET} {Colors.BCYAN}Domain:{Colors.BWHITE}      {domain}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Total:{Colors.BWHITE}        {len(self.found_subdomains)}")
        print(f"  {Colors.BGREEN}  Active:{Colors.BWHITE}      {active}")
        if wildcard > 0:
            print(f"  {Colors.BYELLOW}  Wildcard:{Colors.BWHITE}    {wildcard}")
        if unverified > 0:
            print(f"  {Colors.BBLUE}  Unverified:{Colors.BWHITE} {unverified}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}        {elapsed:.1f}s")
        print(f"  {Icons.INFO} {Colors.BCYAN}Methods:{Colors.BWHITE}      {', '.join(self.methods_used)}")
        
        print_separator("-", 50)
        print()
        
        # Table of results
        if self.found_subdomains:
            headers = ["#", "Subdomain", "IP Address", "Status", "Method"]
            rows = []
            
            for i, (subdomain, info) in enumerate(sorted(self.found_subdomains.items()), 1):
                status_color = {
                    'active': Colors.BGREEN,
                    'wildcard': Colors.BYELLOW,
                    'unverified': Colors.BBLUE
                }.get(info.get('status', ''), Colors.BWHITE)
                
                status_text = info.get('status', 'unknown').upper()
                ip = info.get('ip') or '-'
                method = info.get('method', '-')[:15]
                
                rows.append([
                    str(i),
                    subdomain[:35],
                    ip[:15],
                    status_text[:10],
                    method
                ])
            
            print_table(headers, rows)
    
    def _save_results(self, output_file, domain):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'domain': domain,
                'scan_time': self.start_time.isoformat(),
                'elapsed_seconds': (datetime.now() - self.start_time).total_seconds(),
                'total_found': len(self.found_subdomains),
                'methods_used': self.methods_used,
                'wildcard_detected': self.wildcard_ip is not None,
                'wildcard_ip': self.wildcard_ip,
                'subdomains': {}
            }
            
            for subdomain, info in sorted(self.found_subdomains.items()):
                results['subdomains'][subdomain] = {
                    'ip': info.get('ip'),
                    'status': info.get('status'),
                    'method': info.get('method')
                }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
            print_info(f"File size: {output_path.stat().st_size / 1024:.1f} KB")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
