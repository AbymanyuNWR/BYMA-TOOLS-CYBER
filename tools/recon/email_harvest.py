"""
BYMA TOOLS - Email Harvester
Tools untuk mengumpulkan email addresses dari domain
"""
import re
import requests
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class EmailHarvester:
    """Email harvesting from web sources"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.emails = set()
        self.visited_urls = set()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
    
    def harvest(self, domain, output=None):
        """Main email harvesting function"""
        print_section(f"Email Harvesting: {domain}")
        
        # Create scan record
        scan_id = self.db.create_scan("email_harvest", domain, "recon")
        self.logger.scan_start("email_harvest", domain)
        
        try:
            # Method 1: Search engine scraping
            print_info("Method 1: Web scraping...")
            self._scrape_website(f"http://{domain}")
            self._scrape_website(f"https://{domain}")
            
            # Method 2: Common pages
            print_info("Method 2: Checking common pages...")
            self._check_common_pages(domain)
            
            # Method 3: JavaScript files
            print_info("Method 3: Checking JavaScript files...")
            self._check_js_files(f"http://{domain}")
            
            # Method 4: Contact pages
            print_info("Method 4: Checking contact pages...")
            self._check_contact_pages(domain)
            
            # Filter emails by domain
            domain_emails = [e for e in self.emails if domain in e]
            
            # Display results
            self._display_results(domain, domain_emails)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(domain_emails))
            self.logger.scan_complete("email_harvest", domain, len(domain_emails))
            
            # Save to file if requested
            if output:
                self._save_results(domain, domain_emails, output)
            
            return domain_emails
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("email_harvest", domain, str(e))
            print_error(f"Email harvesting failed: {e}")
            return []
    
    def _scrape_website(self, url):
        """Scrape website for emails"""
        try:
            headers = {'User-Agent': self.user_agents[0]}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                # Extract emails using regex
                email_pattern = re.compile(
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                )
                found_emails = email_pattern.findall(response.text)
                
                for email in found_emails:
                    self.emails.add(email.lower())
                
                # Parse HTML for links
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a', href=True)
                
                for link in links[:50]:  # Limit to 50 links
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Only follow links on same domain
                    if urlparse(full_url).netloc == urlparse(url).netloc:
                        if full_url not in self.visited_urls:
                            self.visited_urls.add(full_url)
                            self._scrape_page(full_url)
        
        except Exception as e:
            pass
    
    def _scrape_page(self, url):
        """Scrape single page for emails"""
        try:
            headers = {'User-Agent': self.user_agents[0]}
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                email_pattern = re.compile(
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                )
                found_emails = email_pattern.findall(response.text)
                
                for email in found_emails:
                    self.emails.add(email.lower())
        
        except:
            pass
    
    def _check_common_pages(self, domain):
        """Check common pages for emails"""
        common_pages = [
            '/contact', '/contact-us', '/contact.html', '/contact.php',
            '/about', '/about-us', '/about.html', '/about.php',
            '/team', '/our-team', '/staff', '/people',
            '/support', '/help', '/faq',
            '/impressum', '/imprint', '/legal',
            '/privacy', '/terms',
            '/robots.txt', '/sitemap.xml'
        ]
        
        for page in common_pages:
            for protocol in ['http', 'https']:
                url = f"{protocol}://{domain}{page}"
                self._scrape_page(url)
    
    def _check_js_files(self, url):
        """Check JavaScript files for emails"""
        try:
            headers = {'User-Agent': self.user_agents[0]}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                scripts = soup.find_all('script', src=True)
                
                for script in scripts[:20]:  # Limit to 20 scripts
                    src = script['src']
                    full_url = urljoin(url, src)
                    
                    try:
                        js_response = requests.get(full_url, headers=headers, timeout=5)
                        if js_response.status_code == 200:
                            email_pattern = re.compile(
                                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                            )
                            found_emails = email_pattern.findall(js_response.text)
                            
                            for email in found_emails:
                                self.emails.add(email.lower())
                    except:
                        pass
        
        except:
            pass
    
    def _check_contact_pages(self, domain):
        """Check contact pages specifically"""
        contact_urls = [
            f"http://{domain}/contact",
            f"https://{domain}/contact",
            f"http://{domain}/contact.html",
            f"https://{domain}/contact.html",
            f"http://{domain}/contact.php",
            f"https://{domain}/contact.php"
        ]
        
        for url in contact_urls:
            try:
                headers = {'User-Agent': self.user_agents[0]}
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                
                if response.status_code == 200:
                    # Look for mailto links
                    soup = BeautifulSoup(response.text, 'html.parser')
                    mailto_links = soup.find_all('a', href=re.compile(r'^mailto:'))
                    
                    for link in mailto_links:
                        email = link['href'].replace('mailto:', '').split('?')[0]
                        if email:
                            self.emails.add(email.lower())
            
            except:
                pass
    
    def _display_results(self, domain, emails):
        """Display harvested emails"""
        print_section("Harvested Emails")
        
        if not emails:
            print_warning(f"No emails found for {domain}")
            return
        
        print_success(f"Found {len(emails)} emails for {domain}:")
        print()
        
        # Group emails by category
        categories = {
            'General': [],
            'Support': [],
            'Admin': [],
            'Marketing': [],
            'Other': []
        }
        
        for email in sorted(emails):
            email_lower = email.lower()
            
            if any(x in email_lower for x in ['support', 'help', 'contact']):
                categories['Support'].append(email)
            elif any(x in email_lower for x in ['admin', 'administrator', 'webmaster']):
                categories['Admin'].append(email)
            elif any(x in email_lower for x in ['marketing', 'promo', 'news']):
                categories['Marketing'].append(email)
            elif any(x in email_lower for x in ['info', 'hello', 'general', 'office']):
                categories['General'].append(email)
            else:
                categories['Other'].append(email)
        
        for category, email_list in categories.items():
            if email_list:
                cprint(f"    {category}:", Colors.BCYAN)
                for email in email_list:
                    cprint(f"      - {email}", Colors.BWHITE)
                print()
    
    def _save_results(self, domain, emails, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'domain': domain,
                    'emails': sorted(list(emails)),
                    'total': len(emails)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
