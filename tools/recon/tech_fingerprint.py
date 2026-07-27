"""
BYMA TOOLS - Advanced Technology Fingerprinting
Professional technology detection with CMS, framework, and WAF detection
"""
import requests
import re
import json
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_logger
from core.database import get_database


class TechFingerprint:
    """Professional technology fingerprinting with comprehensive detection"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.detected_tech = {}
        self.headers = {}
        self.cookies = {}
        self.body = ''
    
    # Technology signatures
    SIGNATURES = {
        # CMS
        'WordPress': {
            'headers': ['x-powered-by: wordpress'],
            'body': ['wp-content', 'wp-includes', 'wordpress'],
            'cookies': ['wordpress_', 'wp-settings-'],
            'meta': ['generator.*wordpress'],
        },
        'Joomla': {
            'headers': [],
            'body': ['joomla', '/media/jui/', 'com_content'],
            'cookies': ['joomla_'],
            'meta': ['generator.*joomla'],
        },
        'Drupal': {
            'headers': ['x-generator: drupal', 'x-drupal-cache'],
            'body': ['drupal', 'sites/default/files'],
            'cookies': ['SESS', 'Drupal.'],
            'meta': ['generator.*drupal'],
        },
        'Magento': {
            'headers': ['x-magento'],
            'body': ['magento', 'Mage.Cookies'],
            'cookies': ['PHPSESSID', 'frontend'],
            'meta': [],
        },
        'Shopify': {
            'headers': ['x-shopify-stage'],
            'body': ['shopify', 'cdn.shopify.com'],
            'cookies': ['_shopify_'],
            'meta': [],
        },
        'Wix': {
            'headers': [],
            'body': ['wix', 'wixstatic.com'],
            'cookies': ['_wix'],
            'meta': [],
        },
        'Squarespace': {
            'headers': [],
            'body': ['squarespace', 'static.squarespace.com'],
            'cookies': [],
            'meta': [],
        },
        
        # Frameworks
        'Laravel': {
            'headers': ['x-powered-by: laravel'],
            'body': ['laravel'],
            'cookies': ['laravel_session'],
            'meta': [],
        },
        'Django': {
            'headers': ['x-frame-options: deny'],
            'body': ['csrfmiddlewaretoken', 'django'],
            'cookies': ['csrftoken', 'sessionid'],
            'meta': [],
        },
        'Flask': {
            'headers': ['server: werkzeug'],
            'body': [],
            'cookies': ['session=ey'],
            'meta': [],
        },
        'Ruby on Rails': {
            'headers': ['x-powered-by: phusion passenger', 'x-runtime'],
            'body': ['csrf-token', 'authenticity_token'],
            'cookies': ['_session_id'],
            'meta': [],
        },
        'Express.js': {
            'headers': ['x-powered-by: express'],
            'body': [],
            'cookies': ['connect.sid'],
            'meta': [],
        },
        'ASP.NET': {
            'headers': ['x-powered-by: asp.net', 'x-aspnet-version'],
            'body': ['__viewstate', '__eventvalidation'],
            'cookies': ['ASP.NET_SessionId', '.ASPXAUTH'],
            'meta': ['generator.*microsoft.*visual studio'],
        },
        
        # Web Servers
        'Apache': {
            'headers': ['server: apache'],
            'body': ['apache'],
            'cookies': [],
            'meta': [],
        },
        'Nginx': {
            'headers': ['server: nginx'],
            'body': [],
            'cookies': [],
            'meta': [],
        },
        'IIS': {
            'headers': ['server: microsoft-iis'],
            'body': [],
            'cookies': [],
            'meta': [],
        },
        'LiteSpeed': {
            'headers': ['server: litespeed'],
            'body': [],
            'cookies': [],
            'meta': [],
        },
        'Caddy': {
            'headers': ['server: caddy'],
            'body': [],
            'cookies': [],
            'meta': [],
        },
        
        # Languages
        'PHP': {
            'headers': ['x-powered-by: php'],
            'body': ['.php'],
            'cookies': ['PHPSESSID'],
            'meta': [],
        },
        'Python': {
            'headers': ['x-powered-by: python', 'server: python'],
            'body': ['python'],
            'cookies': [],
            'meta': [],
        },
        'Ruby': {
            'headers': ['x-powered-by: ruby'],
            'body': [],
            'cookies': [],
            'meta': [],
        },
        'Node.js': {
            'headers': ['x-powered-by: express'],
            'body': [],
            'cookies': [],
            'meta': [],
        },
        'Java': {
            'headers': ['x-powered-by: servlet', 'set-cookie: jsessionid'],
            'body': ['.jsp', '.do', '.action'],
            'cookies': ['JSESSIONID'],
            'meta': [],
        },
        
        # JavaScript Frameworks
        'React': {
            'headers': [],
            'body': ['react', 'reactroot', '_reactRoot'],
            'cookies': [],
            'meta': [],
        },
        'Vue.js': {
            'headers': [],
            'body': ['vue', 'vue-', 'v-cloak'],
            'cookies': [],
            'meta': [],
        },
        'Angular': {
            'headers': [],
            'body': ['ng-version', 'angular', 'ng-app'],
            'cookies': [],
            'meta': [],
        },
        'jQuery': {
            'headers': [],
            'body': ['jquery', 'jquery.min.js'],
            'cookies': [],
            'meta': [],
        },
        'Bootstrap': {
            'headers': [],
            'body': ['bootstrap.min.css', 'bootstrap.min.js'],
            'cookies': [],
            'meta': [],
        },
        
        # Analytics & Marketing
        'Google Analytics': {
            'headers': [],
            'body': ['google-analytics.com', 'gtag', 'ga.js', 'analytics.js'],
            'cookies': ['_ga', '_gid', '_gat'],
            'meta': [],
        },
        'Google Tag Manager': {
            'headers': [],
            'body': ['googletagmanager.com', 'gtm.js'],
            'cookies': ['_gtm'],
            'meta': [],
        },
        'Facebook Pixel': {
            'headers': [],
            'body': ['facebook.net/en_US/fbevents.js', 'fbq('],
            'cookies': ['_fbp'],
            'meta': [],
        },
        'Hotjar': {
            'headers': [],
            'body': ['hotjar.com', 'hj('],
            'cookies': ['_hj'],
            'meta': [],
        },
        'Mixpanel': {
            'headers': [],
            'body': ['mixpanel.com', 'mixpanel.init'],
            'cookies': ['mp_'],
            'meta': [],
        },
        
        # Security
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status'],
            'body': ['cloudflare', 'cf-browser-verification'],
            'cookies': ['__cfduid', 'cf_clearance'],
            'meta': [],
        },
        'Akamai': {
            'headers': ['x-akamai-transformed'],
            'body': ['akamai'],
            'cookies': ['akamai_'],
            'meta': [],
        },
        'Sucuri': {
            'headers': ['x-sucuri-id'],
            'body': ['sucuri'],
            'cookies': ['sucuri_'],
            'meta': [],
        },
        'Wordfence': {
            'headers': [],
            'body': ['wordfence', 'wf_loginscan'],
            'cookies': ['wfwaf', 'wordfence'],
            'meta': [],
        },
        'ModSecurity': {
            'headers': ['server: mod_security'],
            'body': ['mod_security', 'modsecurity'],
            'cookies': [],
            'meta': [],
        },
        
        # Hosting
        'AWS': {
            'headers': ['x-amz-cf-id', 'x-amz-request-id'],
            'body': ['amazonaws.com'],
            'cookies': [],
            'meta': [],
        },
        'Google Cloud': {
            'headers': ['server: gse'],
            'body': ['google cloud', 'googleapis.com'],
            'cookies': [],
            'meta': [],
        },
        'Azure': {
            'headers': ['x-azure-ref'],
            'body': ['azure', 'microsoft.com'],
            'cookies': [],
            'meta': [],
        },
        'Heroku': {
            'headers': ['server: heroku-router'],
            'body': ['heroku'],
            'cookies': [],
            'meta': [],
        },
        'Vercel': {
            'headers': ['x-vercel-id', 'server: vercel'],
            'body': ['vercel', 'zeit.co'],
            'cookies': [],
            'meta': [],
        },
        'Netlify': {
            'headers': ['server: netlify'],
            'body': ['netlify'],
            'cookies': [],
            'meta': [],
        },
    }
    
    def fingerprint(self, url, output=None):
        """Main fingerprinting function"""
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        
        domain = urlparse(url).netloc
        
        print_section(f"TECHNOLOGY FINGERPRINT: {domain}")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("tech_fingerprint", url, "recon")
        self.logger.scan_start("tech_fingerprint", url)
        
        try:
            print_info(f"Fingerprinting {url}")
            print()
            
            # Fetch website
            self._fetch_website(url)
            
            # Analyze headers
            print_subsection("Analyzing Headers")
            self._analyze_headers()
            
            # Analyze cookies
            print_subsection("Analyzing Cookies")
            self._analyze_cookies()
            
            # Analyze body
            print_subsection("Analyzing Body Content")
            self._analyze_body()
            
            # Analyze meta tags
            print_subsection("Analyzing Meta Tags")
            self._analyze_meta_tags()
            
            # Check for technologies
            print_subsection("Technology Detection")
            self._detect_technologies()
            
            # Display results
            self._display_results(domain)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.detected_tech))
            self.logger.scan_complete("tech_fingerprint", url, len(self.detected_tech))
            
            # Save to file if requested
            if output:
                self._save_results(output, domain)
            
            return self.detected_tech
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("tech_fingerprint", url, str(e))
            print_error(f"Fingerprinting failed: {e}")
            return {}
    
    def _fetch_website(self, url):
        """Fetch website content"""
        try:
            response = requests.get(url, timeout=15, verify=False,
                                  headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            
            self.headers = dict(response.headers)
            self.cookies = dict(response.cookies)
            self.body = response.text[:50000]  # Limit body size
            
            print_success(f"Fetched website (Status: {response.status_code})")
            print_info(f"Response size: {len(self.body)} bytes")
        except Exception as e:
            print_error(f"Failed to fetch website: {e}")
            raise
    
    def _analyze_headers(self):
        """Analyze HTTP headers"""
        if not self.headers:
            print_warning("No headers found")
            return
        
        # Display important headers
        important_headers = [
            'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
            'x-generator', 'x-drupal-cache', 'x-magento', 'x-shopify-stage',
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'content-security-policy', 'strict-transport-security',
            'x-sucuri-id', 'cf-ray', 'x-akamai-transformed', 'x-azure-ref',
            'x-vercel-id', 'server', 'x-request-id', 'x-runtime',
        ]
        
        for header in important_headers:
            if header in self.headers:
                print(f"    {Colors.BCYAN}{header}: {Colors.BWHITE}{self.headers[header]}")
        
        print_success(f"Analyzed {len(self.headers)} headers")
    
    def _analyze_cookies(self):
        """Analyze cookies"""
        if not self.cookies:
            print_warning("No cookies found")
            return
        
        for cookie_name, cookie_value in self.cookies.items():
            print(f"    {Colors.BCYAN}{cookie_name}: {Colors.BWHITE}{cookie_value[:50]}...")
        
        print_success(f"Analyzed {len(self.cookies)} cookies")
    
    def _analyze_body(self):
        """Analyze body content"""
        if not self.body:
            print_warning("No body content")
            return
        
        # Count patterns
        patterns = {
            'HTML tags': len(re.findall(r'<[^>]+>', self.body)),
            'JavaScript': len(re.findall(r'<script[^>]*>', self.body)),
            'CSS': len(re.findall(r'<link[^>]*stylesheet', self.body)),
            'Images': len(re.findall(r'<img[^>]+>', self.body)),
            'Links': len(re.findall(r'<a[^>]+href', self.body)),
            'Forms': len(re.findall(r'<form[^>]+>', self.body)),
            'Meta tags': len(re.findall(r'<meta[^>]+>', self.body)),
        }
        
        for pattern, count in patterns.items():
            if count > 0:
                print(f"    {Colors.BCYAN}{pattern}: {Colors.BWHITE}{count}")
        
        print_success(f"Analyzed {len(self.body)} bytes of content")
    
    def _analyze_meta_tags(self):
        """Analyze meta tags"""
        meta_patterns = re.findall(r'<meta[^>]+>', self.body, re.IGNORECASE)
        
        if not meta_patterns:
            print_warning("No meta tags found")
            return
        
        for meta in meta_patterns[:20]:
            print(f"    {Colors.BWHITE}{meta[:100]}")
        
        print_success(f"Found {len(meta_patterns)} meta tags")
    
    def _detect_technologies(self):
        """Detect technologies using signatures"""
        detected = []
        
        for tech_name, signatures in self.SIGNATURES.items():
            score = 0
            
            # Check headers
            for pattern in signatures.get('headers', []):
                header_name, header_value = pattern.split(': ', 1) if ': ' in pattern else (pattern, '')
                
                for h_name, h_value in self.headers.items():
                    if header_name.lower() in h_name.lower():
                        if header_value.lower() in h_value.lower():
                            score += 3
                        else:
                            score += 1
            
            # Check body
            for pattern in signatures.get('body', []):
                if pattern.lower() in self.body.lower():
                    score += 2
            
            # Check cookies
            for cookie_pattern in signatures.get('cookies', []):
                for cookie_name in self.cookies.keys():
                    if cookie_pattern.lower() in cookie_name.lower():
                        score += 2
            
            # Check meta tags
            for pattern in signatures.get('meta', []):
                if re.search(pattern, self.body, re.IGNORECASE):
                    score += 1
            
            # Determine detection
            if score >= 4:
                confidence = min(100, score * 10)
                detected.append({
                    'name': tech_name,
                    'confidence': confidence,
                    'score': score
                })
        
        # Store detected technologies
        self.detected_tech = {}
        for tech in sorted(detected, key=lambda x: x['score'], reverse=True):
            self.detected_tech[tech['name']] = {
                'confidence': tech['confidence'],
                'score': tech['score']
            }
            print_success(f"Detected: {tech['name']} (Confidence: {tech['confidence']}%)")
    
    def _display_results(self, domain):
        """Display fingerprinting results"""
        print_section("TECHNOLOGY FINGERPRINT RESULTS")
        
        if not self.detected_tech:
            print_warning("No technologies detected")
            return
        
        # Summary
        print(f"  {Icons.SUCCESS} {Colors.BGREEN}FINGERPRINTING COMPLETE{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.TARGET} {Colors.BCYAN}Domain:{Colors.BWHITE}        {domain}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Technologies:{Colors.BWHITE}  {len(self.detected_tech)}")
        
        print_separator("-", 50)
        print()
        
        # Group by category
        categories = {
            'CMS': [],
            'Framework': [],
            'Web Server': [],
            'Language': [],
            'JavaScript': [],
            'Analytics': [],
            'Security': [],
            'Hosting': [],
            'Other': []
        }
        
        category_keywords = {
            'CMS': ['WordPress', 'Joomla', 'Drupal', 'Magento', 'Shopify', 'Wix', 'Squarespace'],
            'Framework': ['Laravel', 'Django', 'Flask', 'Ruby on Rails', 'Express.js', 'ASP.NET'],
            'Web Server': ['Apache', 'Nginx', 'IIS', 'LiteSpeed', 'Caddy'],
            'Language': ['PHP', 'Python', 'Ruby', 'Node.js', 'Java'],
            'JavaScript': ['React', 'Vue.js', 'Angular', 'jQuery', 'Bootstrap'],
            'Analytics': ['Google Analytics', 'Google Tag Manager', 'Facebook Pixel', 'Hotjar', 'Mixpanel'],
            'Security': ['Cloudflare', 'Akamai', 'Sucuri', 'Wordfence', 'ModSecurity'],
            'Hosting': ['AWS', 'Google Cloud', 'Azure', 'Heroku', 'Vercel', 'Netlify'],
        }
        
        for tech_name, info in self.detected_tech.items():
            placed = False
            for category, keywords in category_keywords.items():
                if tech_name in keywords:
                    categories[category].append((tech_name, info))
                    placed = True
                    break
            if not placed:
                categories['Other'].append((tech_name, info))
        
        # Display by category
        for category, techs in categories.items():
            if techs:
                print_subsection(f"{category}")
                for tech_name, info in techs:
                    confidence = info['confidence']
                    color = Colors.BGREEN if confidence >= 80 else Colors.BYELLOW if confidence >= 50 else Colors.BCYAN
                    print(f"    {color}{tech_name:<25} {Colors.BWHITE}Confidence: {confidence}%")
                print()
