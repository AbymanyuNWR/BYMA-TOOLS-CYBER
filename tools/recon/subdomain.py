"""
BYMA TOOLS - Subdomain Enumerator
Tools untuk enumerasi subdomain menggunakan berbagai metode
"""
import dns.resolver
import requests
import json
import concurrent.futures
from pathlib import Path
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_progress, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class SubdomainEnumerator:
    """Subdomain enumeration using multiple methods"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.found_subdomains = set()
    
    def enumerate(self, domain, threads=50, output=None):
        """Main enumeration function"""
        print_section(f"Subdomain Enumeration: {domain}")
        
        # Create scan record
        scan_id = self.db.create_scan("subdomain_enum", domain, "recon")
        self.logger.scan_start("subdomain_enum", domain)
        
        try:
            # Method 1: DNS Brute Force
            print_info("Method 1: DNS Brute Force")
            self._dns_bruteforce(domain, threads)
            
            # Method 2: Certificate Transparency
            print_info("Method 2: Certificate Transparency Logs")
            self._check_ct_logs(domain)
            
            # Method 3: Common Subdomains Check
            print_info("Method 3: Common Subdomains Check")
            self._check_common_subdomains(domain)
            
            # Method 4: DNS Enumeration
            print_info("Method 4: DNS Record Enumeration")
            self._dns_enumeration(domain)
            
            # Save results to database
            for subdomain in self.found_subdomains:
                try:
                    ip = self._resolve_subdomain(subdomain)
                    self.db.add_subdomain(scan_id, subdomain, ip, "active")
                except:
                    self.db.add_subdomain(scan_id, subdomain, None, "unknown")
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.found_subdomains))
            self.logger.scan_complete("subdomain_enum", domain, len(self.found_subdomains))
            
            # Display results
            self._display_results(domain)
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.found_subdomains
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("subdomain_enum", domain, str(e))
            print_error(f"Enumeration failed: {e}")
            return set()
    
    def _dns_bruteforce(self, domain, threads):
        """DNS brute force using wordlist"""
        # Load wordlist
        wordlist_path = Path(__file__).resolve().parent.parent.parent / "wordlists" / "subdomains.txt"
        
        if wordlist_path.exists():
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        else:
            # Default subdomains
            subdomains = self._get_default_subdomains()
        
        print_info(f"Testing {len(subdomains)} subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_subdomain, f"{sub}.{domain}"): sub
                for sub in subdomains
            }
            
            for future in tqdm(concurrent.futures.as_completed(futures), 
                             total=len(futures), desc="    Progress"):
                result = future.result()
                if result:
                    self.found_subdomains.add(result)
    
    def _check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            if answers:
                return subdomain
        except:
            pass
        return None
    
    def _check_ct_logs(self, domain):
        """Check Certificate Transparency logs"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Handle multiple names
                        for name in name.split('\n'):
                            name = name.strip()
                            if name.endswith(f".{domain}") or name == domain:
                                self.found_subdomains.add(name)
                
                print_success(f"Found {len(data)} entries from CT logs")
        except Exception as e:
            print_warning(f"CT log check failed: {e}")
    
    def _check_common_subdomains(self, domain):
        """Check common subdomains"""
        common = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
                  'api', 'blog', 'shop', 'app', 'portal', 'vpn', 'remote',
                  'webmail', 'smtp', 'ns1', 'ns2', 'dns', 'mx', 'cdn']
        
        for sub in common:
            subdomain = f"{sub}.{domain}"
            if self._check_subdomain(subdomain):
                self.found_subdomains.add(subdomain)
    
    def _dns_enumeration(self, domain):
        """Enumerate DNS records"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    if record_type in ['MX', 'NS']:
                        name = str(rdata.exchange if record_type == 'MX' else rdata).rstrip('.')
                        if name.endswith(f".{domain}"):
                            self.found_subdomains.add(name)
            except:
                pass
    
    def _resolve_subdomain(self, subdomain):
        """Resolve subdomain to IP"""
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            return str(answers[0])
        except:
            return None
    
    def _get_default_subdomains(self):
        """Get default subdomain list"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
            'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'mx',
            'mx1', 'mx2', 'relay', 'panel', 'cpanel', 'whm', 'webdisk',
            'autoconfig', 'autodiscover', 'admin', 'administrator', 'webmin',
            'user', 'users', 'portal', 'dev', 'development', 'test',
            'testing', 'staging', 'stage', 'sandbox', 'qa', 'uat', 'demo',
            'preview', 'beta', 'alpha', 'nightly', 'canary', 'api', 'api2',
            'api3', 'v1', 'v2', 'v3', 'graphql', 'rest', 'ws', 'socket',
            'app', 'app2', 'apps', 'application', 'mobile', 'm', 'wap',
            'web', 'www2', 'www3', 'web2', 'site', 'blog', 'wordpress',
            'wp', 'wp2', 'cms', 'drupal', 'joomla', 'shop', 'store',
            'ecommerce', 'cart', 'checkout', 'pay', 'payment', 'forum',
            'community', 'social', 'chat', 'messaging', 'im', 'support',
            'help', 'helpdesk', 'ticket', 'docs', 'wiki', 'kb', 'knowledge',
            'cdn', 'static', 'assets', 'media', 'images', 'img', 'files',
            'download', 'downloads', 'upload', 'uploads', 'content', 'db',
            'database', 'mysql', 'mysql2', 'sql', 'postgres', 'redis',
            'mongo', 'mssql', 'phpmyadmin', 'pma', 'adminer', 'myadmin',
            'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo',
            'repository', 'code', 'ci', 'jenkins', 'travis', 'circle',
            'drone', 'build', 'deploy', 'release', 'jira', 'confluence',
            'redmine', 'trello', 'asana', 'monitor', 'monitoring', 'grafana',
            'prometheus', 'nagios', 'zabbix', 'status', 'log', 'logs',
            'logging', 'kibana', 'elastic', 'elasticsearch', 'vpn', 'remote',
            'rdp', 'ssh', 'sftp', 'jump', 'bastion', 'proxy', 'reverse',
            'gateway', 'gw', 'lb', 'loadbalancer', 'haproxy', 'nginx'
        ]
    
    def _display_results(self, domain):
        """Display enumeration results"""
        print_section("Enumeration Results")
        
        if not self.found_subdomains:
            print_warning("No subdomains found")
            return
        
        print_success(f"Found {len(self.found_subdomains)} subdomains:")
        print()
        
        for subdomain in sorted(self.found_subdomains):
            ip = self._resolve_subdomain(subdomain)
            if ip:
                cprint(f"    {subdomain:<40} {ip}", Colors.BWHITE)
            else:
                cprint(f"    {subdomain:<40} {'(no IP)':<15}", Colors.BYELLOW)
    
    def _save_results(self, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'domain': output_file.split('_')[0] if '_' in output_file else 'unknown',
                    'subdomains': sorted(list(self.found_subdomains)),
                    'count': len(self.found_subdomains)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
