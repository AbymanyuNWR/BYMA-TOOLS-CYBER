"""
BYMA TOOLS - Web Crawler
Tools untuk crawling website dan mengumpulkan informasi
"""
import requests
import json
import re
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


class WebCrawler:
    """Web crawler for information gathering"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.visited = set()
        self.urls = set()
        self.forms = set()
        self.emails = set()
        self.js_files = set()
        self.images = set()
    
    def crawl(self, url, depth=3, output=None):
        """Main crawl function"""
        print_section(f"Web Crawler: {url}")
        
        scan_id = self.db.create_scan("web_crawler", url, "recon")
        self.logger.scan_start("web_crawler", url)
        
        try:
            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            print_info(f"Crawl depth: {depth}")
            print()
            
            # Start crawling
            self._crawl_url(url, depth, 0)
            
            # Display results
            self._display_results()
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.urls))
            self.logger.scan_complete("web_crawler", url, len(self.urls))
            
            # Save to file if requested
            if output:
                self._save_results(url, output)
            
            return {
                'urls': list(self.urls),
                'forms': list(self.forms),
                'emails': list(self.emails),
                'js_files': list(self.js_files)
            }
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("web_crawler", url, str(e))
            print_error(f"Crawl failed: {e}")
            return {}
    
    def _crawl_url(self, url, max_depth, current_depth):
        """Recursively crawl URLs"""
        if current_depth > max_depth:
            return
        
        if url in self.visited:
            return
        
        self.visited.add(url)
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code != 200:
                return
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links
            links = soup.find_all('a', href=True)
            base_domain = urlparse(url).netloc
            
            for link in links:
                href = link['href']
                full_url = urljoin(url, href)
                
                # Only follow links on same domain
                if urlparse(full_url).netloc == base_domain:
                    self.urls.add(full_url)
                    
                    if current_depth < max_depth:
                        self._crawl_url(full_url, max_depth, current_depth + 1)
            
            # Extract forms
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                inputs = form.find_all('input')
                
                form_data = {
                    'url': url,
                    'action': urljoin(url, action),
                    'method': method,
                    'inputs': [inp.get('name', '') for inp in inputs if inp.get('name')]
                }
                self.forms.add(json.dumps(form_data))
            
            # Extract emails
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            emails = email_pattern.findall(response.text)
            for email in emails:
                self.emails.add(email.lower())
            
            # Extract JavaScript files
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                full_url = urljoin(url, src)
                self.js_files.add(full_url)
            
            # Extract images
            images = soup.find_all('img', src=True)
            for img in images:
                src = img['src']
                full_url = urljoin(url, src)
                self.images.add(full_url)
            
            print_info(f"  Crawled: {url} (depth: {current_depth})")
        
        except Exception as e:
            pass
    
    def _display_results(self):
        """Display crawl results"""
        print_section("Crawl Results")
        
        print_success(f"Found {len(self.urls)} URLs")
        print_success(f"Found {len(self.forms)} forms")
        print_success(f"Found {len(self.emails)} emails")
        print_success(f"Found {len(self.js_files)} JavaScript files")
        print()
        
        # Display URLs
        if self.urls:
            cprint(f"    {'URLs Found:':<25}", Colors.BCYAN)
            for url in sorted(list(self.urls))[:20]:
                cprint(f"      {url}", Colors.BWHITE)
            if len(self.urls) > 20:
                cprint(f"      ... and {len(self.urls) - 20} more", Colors.BBLACK)
        
        # Display forms
        if self.forms:
            print()
            cprint(f"    {'Forms Found:':<25}", Colors.BCYAN)
            for form_json in list(self.forms)[:10]:
                form = json.loads(form_json)
                cprint(f"      {form['method']} {form['action']}", Colors.BWHITE)
        
        # Display emails
        if self.emails:
            print()
            cprint(f"    {'Emails Found:':<25}", Colors.BCYAN)
            for email in list(self.emails)[:10]:
                cprint(f"      {email}", Colors.BWHITE)
    
    def _save_results(self, url, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'target': url,
                    'urls': list(self.urls),
                    'forms': [json.loads(f) for f in self.forms],
                    'emails': list(self.emails),
                    'js_files': list(self.js_files),
                    'images': list(self.images)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
