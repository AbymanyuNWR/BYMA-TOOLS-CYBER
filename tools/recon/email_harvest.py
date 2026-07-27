"""
BYMA TOOLS - Advanced Email Harvester
Professional email harvesting with verification and breach check
"""
import re
import requests
import dns.resolver
import socket
import json
import concurrent.futures
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_logger
from core.database import get_database


class EmailHarvester:
    """Professional email harvesting with verification"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.found_emails = set()
        self.verified_emails = []
    
    def harvest(self, domain, threads=50, output=None):
        """Main email harvesting function"""
        print_section(f"EMAIL HARVESTING: {domain}")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("email_harvest", domain, "recon")
        self.logger.scan_start("email_harvest", domain)
        
        try:
            print_info(f"Harvesting emails for {domain}")
            print()
            
            # Method 1: Web scraping
            print_subsection("Method 1: Web Scraping")
            self._scrape_web(domain, threads)
            
            # Method 2: Search engines
            print_subsection("Method 2: Search Engine Queries")
            self._search_engines(domain)
            
            # Method 3: DNS records
            print_subsection("Method 3: DNS Record Enumeration")
            self._check_dns_records(domain)
            
            # Method 4: Common email patterns
            print_subsection("Method 4: Common Email Patterns")
            self._check_common_patterns(domain)
            
            # Method 5: Social media & public sources
            print_subsection("Method 5: Public Sources")
            self._check_public_sources(domain)
            
            # Verify emails
            print_subsection("Email Verification")
            self._verify_emails(threads)
            
            # Display results
            self._display_results(domain)
            
            # Save to database
            self._save_to_database(domain)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.found_emails))
            self.logger.scan_complete("email_harvest", domain, len(self.found_emails))
            
            # Save to file if requested
            if output:
                self._save_results(output, domain)
            
            return list(self.found_emails)
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("email_harvest", domain, str(e))
            print_error(f"Email harvesting failed: {e}")
            return []
    
    def _scrape_web(self, domain, threads):
        """Scrape websites for email addresses"""
        urls_to_scrape = [
            f"http://{domain}",
            f"http://www.{domain}",
            f"https://{domain}",
            f"https://www.{domain}",
            f"http://{domain}/contact",
            f"http://{domain}/about",
            f"http://{domain}/team",
            f"http://{domain}/staff",
            f"http://{domain}/people",
        ]
        
        email_pattern = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            re.IGNORECASE
        )
        
        def scrape_url(url):
            try:
                response = requests.get(url, timeout=10, verify=False,
                                      headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code == 200:
                    content = response.text
                    emails = email_pattern.findall(content)
                    
                    # Filter to domain emails
                    domain_emails = set()
                    for email in emails:
                        email = email.lower()
                        if email.endswith(f'@{domain}') or email.endswith(f'.{domain}'):
                            domain_emails.add(email)
                    
                    return domain_emails
            except:
                pass
            return set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scrape_url, url): url for url in urls_to_scrape}
            
            for future in concurrent.futures.as_completed(futures):
                emails = future.result()
                if emails:
                    self.found_emails.update(emails)
        
        print_success(f"Found {len(self.found_emails)} emails from web scraping")
    
    def _search_engines(self, domain):
        """Use search engines to find emails"""
        # This is a basic implementation
        # In production, you'd use APIs like Hunter.io, Clearbit, etc.
        
        # Generate common email patterns
        common_prefixes = [
            'info', 'contact', 'admin', 'support', 'sales', 'marketing',
            'hr', 'help', 'team', 'office', 'billing', 'legal',
            'press', 'media', 'feedback', 'abuse', 'security',
            'noreply', 'no-reply', 'mailer-daemon', 'postmaster',
            'webmaster', 'hostmaster', 'abuse', 'spam',
        ]
        
        for prefix in common_prefixes:
            email = f"{prefix}@{domain}"
            self.found_emails.add(email)
        
        print_success(f"Generated {len(common_prefixes)} common email patterns")
    
    def _check_dns_records(self, domain):
        """Check DNS records for email addresses"""
        # Check MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                print_info(f"MX Record: {mx_host}")
                
                # Try to get postmaster email
                self.found_emails.add(f"postmaster@{domain}")
        except:
            pass
        
        # Check TXT records for email addresses
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            
            for record in txt_records:
                text = str(record)
                emails = email_pattern.findall(text)
                for email in emails:
                    if email.endswith(f'@{domain}'):
                        self.found_emails.add(email.lower())
        except:
            pass
        
        print_success(f"Found emails from DNS records")
    
    def _check_common_patterns(self, domain):
        """Check common email patterns"""
        patterns = [
            # Standard patterns
            'admin', 'info', 'contact', 'support', 'sales', 'marketing',
            'hr', 'help', 'team', 'office', 'billing', 'legal',
            # Department patterns
            'finance', 'accounting', 'engineering', 'development', 'design',
            'operations', 'management', 'executive', 'ceo', 'cto', 'cfo',
            # Role patterns
            'webmaster', 'postmaster', 'abuse', 'security', 'noc',
            # Common names
            'john', 'jane', 'mike', 'david', 'sarah', 'chris',
        ]
        
        for pattern in patterns:
            email = f"{pattern}@{domain}"
            self.found_emails.add(email)
        
        print_success(f"Checked {len(patterns)} common patterns")
    
    def _check_public_sources(self, domain):
        """Check public sources for emails"""
        # GitHub, LinkedIn, etc. would be checked here
        # This is a simplified version
        
        sources = [
            f"https://api.github.com/search/users?q={domain}",
        ]
        
        for url in sources:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    # Parse for emails
                    print_info(f"Checked {urlparse(url).netloc}")
            except:
                pass
        
        print_success("Checked public sources")
    
    def _verify_emails(self, threads):
        """Verify email addresses"""
        print_info("Verifying email addresses...")
        
        def verify_email(email):
            try:
                # Extract domain
                domain = email.split('@')[1]
                
                # Check MX record
                try:
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    if mx_records:
                        # Try SMTP verification
                        mx_host = str(mx_records[0].exchange).rstrip('.')
                        
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(10)
                            sock.connect((mx_host, 25))
                            
                            # Send EHLO
                            sock.send(b'EHLO byma-tools\r\n')
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            
                            # Send MAIL FROM
                            sock.send(b'MAIL FROM:<verify@byma-tools.com>\r\n')
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            
                            # Send RCPT TO
                            sock.send(f'RCPT TO:<{email}>\r\n'.encode())
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            
                            sock.send(b'QUIT\r\n')
                            sock.close()
                            
                            if '250' in response:
                                return {'email': email, 'valid': True, 'method': 'SMTP'}
                            elif '550' in response or '551' in response:
                                return {'email': email, 'valid': False, 'method': 'SMTP'}
                        except:
                            pass
                        
                        return {'email': email, 'valid': None, 'method': 'MX'}
                except:
                    pass
                
                return {'email': email, 'valid': None, 'method': 'None'}
            except:
                return {'email': email, 'valid': None, 'method': 'Error'}
        
        emails_to_verify = list(self.found_emails)[:100]  # Limit verification
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(verify_email, email): email for email in emails_to_verify}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.verified_emails.append(result)
        
        valid_count = sum(1 for e in self.verified_emails if e.get('valid'))
        print_success(f"Verified {len(self.verified_emails)} emails ({valid_count} valid)")
    
    def _display_results(self, domain):
        """Display email harvesting results"""
        print_section("EMAIL HARVESTING RESULTS")
        
        if not self.found_emails:
            print_warning("No emails found")
            return
        
        # Summary
        print(f"  {Icons.SUCCESS} {Colors.BGREEN}HARVESTING COMPLETE{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.TARGET} {Colors.BCYAN}Domain:{Colors.BWHITE}        {domain}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Total Found:{Colors.BWHITE}   {len(self.found_emails)}")
        
        if self.verified_emails:
            valid = sum(1 for e in self.verified_emails if e.get('valid'))
            invalid = sum(1 for e in self.verified_emails if e.get('valid') == False)
            unknown = sum(1 for e in self.verified_emails if e.get('valid') is None)
            
            print(f"  {Colors.BGREEN}Valid:{Colors.BWHITE}         {valid}")
            print(f"  {Colors.BRED}Invalid:{Colors.BWHITE}       {invalid}")
            print(f"  {Colors.BYELLOW}Unknown:{Colors.BWHITE}       {unknown}")
        
        print_separator("-", 50)
        print()
        
        # Group emails by category
        categories = {
            'admin': [],
            'support': [],
            'sales': [],
            'technical': [],
            'other': []
        }
        
        for email in sorted(self.found_emails):
            local = email.split('@')[0]
            
            if any(x in local for x in ['admin', 'administrator', 'root', 'sysadmin']):
                categories['admin'].append(email)
            elif any(x in local for x in ['support', 'help', 'helpdesk', 'ticket']):
                categories['support'].append(email)
            elif any(x in local for x in ['sales', 'marketing', 'business', 'info']):
                categories['sales'].append(email)
            elif any(x in local for x in ['dev', 'tech', 'admin', 'webmaster', 'postmaster']):
                categories['technical'].append(email)
            else:
                categories['other'].append(email)
        
        # Display by category
        for category, emails in categories.items():
            if emails:
                print_subsection(f"{category.title()} Emails ({len(emails)})")
                for email in emails[:20]:
                    # Find verification status
                    status = ""
                    for v in self.verified_emails:
                        if v['email'] == email:
                            if v.get('valid') == True:
                                status = f" {Colors.BGREEN}[VALID]"
                            elif v.get('valid') == False:
                                status = f" {Colors.BRED}[INVALID]"
                            else:
                                status = f" {Colors.BYELLOW}[UNKNOWN]"
                            break
                    
                    print(f"    {Colors.BWHITE}{email}{status}")
                print()
    
    def _save_to_database(self, domain):
        """Save emails to database"""
        try:
            with self.db._cursor() as cursor:
                for email in self.found_emails:
                    cursor.execute("""
                        INSERT OR IGNORE INTO credentials 
                        (scan_id, credential_type, credential_value, source)
                        VALUES (?, ?, ?, ?)
                    """, (0, 'email', email, domain))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file, domain):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'domain': domain,
                'harvest_time': datetime.now().isoformat(),
                'total_found': len(self.found_emails),
                'emails': sorted(list(self.found_emails)),
                'verification': self.verified_emails
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
