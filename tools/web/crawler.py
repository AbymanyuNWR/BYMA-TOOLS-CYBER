"""
BYMA TOOLS - Advanced Web Crawler
Professional web crawler with link discovery and content analysis
"""
import requests
import re
import json
import time
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class WebCrawler:
    """Professional web crawler with comprehensive discovery"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.visited = set()
        self.discovered_urls = []
        self.forms = []
        self.emails = set()
        self.phone_numbers = set()
        self.external_links = set()
        self.start_time = None
    
    # Common file extensions to discover
    INTERESTING_EXTENSIONS = [
        '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl',
        '.html', '.htm', '.txt', '.xml', '.json',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.zip', '.tar', '.gz', '.rar',
        '.sql', '.bak', '.old', '.tmp',
        '.conf', '.config', '.ini', '.env',
    ]
    
    # Interesting paths
    INTERESTING_PATHS = [
        '/admin', '/login', '/register', '/dashboard',
        '/api', '/api/v1', '/api/v2', '/graphql',
        '/robots.txt', '/sitemap.xml', '/.env',
        '/config', '/backup', '/test', '/debug',
        '/uploads', '/images', '/files', '/documents',
        '/wp-admin', '/wp-content', '/wp-login.php',
        '/phpmyadmin', '/adminer.php',
        '/server-status', '/server-info',
        '/.git', '/.svn', '/.hg',
    ]
    
    def crawl(self, url, depth=3, max_pages=100, output=None, 
              follow_external=False, extract_emails=True, extract_phones=True):
        """Main crawl function"""
        self.start_time = datetime.now()
        
        print_section("WEB CRAWLER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("web_crawl", url, "recon")
        self.logger.scan_start("web_crawl", url)
        
        try:
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {url}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Max Depth:{Colors.BWHITE}    {depth}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Max Pages:{Colors.BWHITE}    {max_pages}")
            print_separator("-", 50)
            print()
            
            # Initialize session
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            # Start crawling
            print_subsection("Crawling")
            
            queue = deque([(url, 0)])
            
            while queue and len(self.visited) < max_pages:
                current_url, current_depth = queue.popleft()
                
                if current_url in self.visited:
                    continue
                
                if current_depth > depth:
                    continue
                
                try:
                    # Fetch page
                    response = session.get(current_url, timeout=10, verify=False)
                    
                    self.visited.add(current_url)
                    
                    # Display progress
                    status_color = Colors.BGREEN if response.status_code == 200 else Colors.BYELLOW
                    cprint(f"  [{response.status_code}] {current_url}", status_color)
                    
                    # Store URL info
                    url_info = {
                        'url': current_url,
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                        'length': len(response.text),
                        'depth': current_depth,
                    }
                    self.discovered_urls.append(url_info)
                    
                    # Parse HTML if it's a web page
                    if 'text/html' in response.headers.get('Content-Type', ''):
                        # Extract links
                        links = self._extract_links(response.text, current_url)
                        
                        for link in links:
                            if link not in self.visited:
                                # Check if external
                                parsed_link = urlparse(link)
                                parsed_base = urlparse(url)
                                
                                if parsed_link.netloc == parsed_base.netloc:
                                    queue.append((link, current_depth + 1))
                                elif follow_external:
                                    self.external_links.add(link)
                        
                        # Extract forms
                        forms = self._extract_forms(response.text, current_url)
                        self.forms.extend(forms)
                        
                        # Extract emails
                        if extract_emails:
                            emails = self._extract_emails(response.text)
                            self.emails.update(emails)
                        
                        # Extract phone numbers
                        if extract_phones:
                            phones = self._extract_phones(response.text)
                            self.phone_numbers.update(phones)
                
                except Exception as e:
                    if current_url not in self.visited:
                        print_error(f"  Error: {current_url}: {e}")
                
                # Small delay
                time.sleep(0.1)
            
            # Check for interesting paths
            print_subsection("Checking Interesting Paths")
            self._check_interesting_paths(url, session)
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.visited))
            self.logger.scan_complete("web_crawl", url, len(self.visited))
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return {
                'urls': self.discovered_urls,
                'forms': self.forms,
                'emails': list(self.emails),
                'phones': list(self.phone_numbers),
                'external_links': list(self.external_links),
            }
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("web_crawl", url, str(e))
            print_error(f"Crawl failed: {e}")
            return None
    
    def _extract_links(self, html, base_url):
        """Extract links from HTML"""
        links = []
        
        # Find all href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            href = match.group(1)
            
            # Convert to absolute URL
            absolute_url = urljoin(base_url, href)
            
            # Remove fragment
            absolute_url, _ = urldefrag(absolute_url)
            
            # Only include HTTP(S) URLs
            if absolute_url.startswith(('http://', 'https://')):
                links.append(absolute_url)
        
        # Find all src attributes
        src_pattern = r'src=["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, html, re.IGNORECASE):
            src = match.group(1)
            absolute_url = urljoin(base_url, src)
            absolute_url, _ = urldefrag(absolute_url)
            
            if absolute_url.startswith(('http://', 'https://')):
                links.append(absolute_url)
        
        return list(set(links))
    
    def _extract_forms(self, html, base_url):
        """Extract forms from HTML"""
        forms = []
        
        # Find form tags
        form_pattern = r'<form[^>]*>(.*?)</form>'
        for match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = match.group(0)
            
            # Extract form attributes
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else base_url
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # Extract input fields
            inputs = []
            input_pattern = r'<input[^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_html = input_match.group(0)
                
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                
                if name_match:
                    inputs.append({
                        'name': name_match.group(1),
                        'type': type_match.group(1) if type_match else 'text',
                    })
            
            form_info = {
                'action': urljoin(base_url, action),
                'method': method,
                'inputs': inputs,
                'page': base_url,
            }
            forms.append(form_info)
        
        return forms
    
    def _extract_emails(self, text):
        """Extract email addresses"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return set(re.findall(email_pattern, text))
    
    def _extract_phones(self, text):
        """Extract phone numbers"""
        phone_patterns = [
            r'\+?[\d\-\(\)]{10,}',
            r'\+\d{1,3}[\s-]?\d{4,}',
        ]
        
        phones = set()
        for pattern in phone_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                # Basic validation
                digits = re.sub(r'\D', '', match)
                if 10 <= len(digits) <= 15:
                    phones.add(match)
        
        return phones
    
    def _check_interesting_paths(self, base_url, session):
        """Check for interesting paths"""
        found_paths = []
        
        for path in self.INTERESTING_PATHS:
            url = urljoin(base_url, path)
            
            try:
                response = session.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    found_paths.append({
                        'path': path,
                        'url': url,
                        'status': response.status_code,
                    })
                    
                    status_color = Colors.BGREEN if response.status_code == 200 else Colors.BYELLOW
                    cprint(f"  [{response.status_code}] {path}", status_color)
            
            except:
                pass
        
        if not found_paths:
            print_info("  No interesting paths found")
        
        print()
    
    def _display_results(self):
        """Display crawl results"""
        print_section("CRAWL RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}CRAWL SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Pages Visited:{Colors.BWHITE}   {len(self.visited)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}URLs Found:{Colors.BWHITE}     {len(self.discovered_urls)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Forms Found:{Colors.BWHITE}    {len(self.forms)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Emails Found:{Colors.BWHITE}   {len(self.emails)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Phones Found:{Colors.BWHITE}   {len(self.phone_numbers)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}External Links:{Colors.BWHITE} {len(self.external_links)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}           {elapsed:.1f}s")
        
        print_separator("-", 50)
        print()
        
        # Display forms
        if self.forms:
            print_subsection("Forms")
            
            table_data = [["Method", "Action", "Inputs"]]
            for form in self.forms[:20]:
                table_data.append([
                    form['method'],
                    form['action'][:40],
                    str(len(form['inputs'])),
                ])
            
            print_table(table_data)
            print()
        
        # Display emails
        if self.emails:
            print_subsection("Emails")
            for email in list(self.emails)[:20]:
                print(f"  {Colors.BCYAN}{email}{Colors.RESET}")
            print()
        
        # Display external links
        if self.external_links:
            print_subsection("External Links")
            for link in list(self.external_links)[:20]:
                print(f"  {Colors.BCYAN}{link}{Colors.RESET}")
            print()
        
        print()
    
    def _save_to_database(self, scan_id):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                # Save URLs
                for url_info in self.discovered_urls[:100]:
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, result_type, result_data)
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        'url',
                        json.dumps(url_info)
                    ))
                
                # Save forms
                for form in self.forms:
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, result_type, result_data)
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        'form',
                        json.dumps(form)
                    ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'crawl_time': self.start_time.isoformat(),
                'pages_visited': len(self.visited),
                'urls': self.discovered_urls,
                'forms': self.forms,
                'emails': list(self.emails),
                'phones': list(self.phone_numbers),
                'external_links': list(self.external_links),
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
