"""
BYMA TOOLS - Technology Fingerprint
Tools untuk mendeteksi teknologi yang digunakan oleh website
"""
import requests
import json
import re
from pathlib import Path
from bs4 import BeautifulSoup
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class TechFingerprint:
    """Technology detection and fingerprinting"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.technologies = {
            'cms': [],
            'framework': [],
            'server': [],
            'language': [],
            'javascript': [],
            'analytics': [],
            'cdn': [],
            'ssl': [],
            'other': []
        }
    
    def detect(self, url, output=None):
        """Main detection function"""
        print_section(f"Technology Fingerprint: {url}")
        
        # Create scan record
        scan_id = self.db.create_scan("tech_fingerprint", url, "recon")
        self.logger.scan_start("tech_fingerprint", url)
        
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            # Get HTTP headers
            print_info("Analyzing HTTP headers...")
            headers = self._analyze_headers(url)
            
            # Get HTML content
            print_info("Analyzing HTML content...")
            html_content = self._get_html(url)
            
            if html_content:
                # Detect technologies
                self._detect_cms(html_content, headers)
                self._detect_framework(html_content, headers)
                self._detect_server(headers)
                self._detect_language(html_content, headers)
                self._detect_javascript(html_content)
                self._detect_analytics(html_content)
                self._detect_cdn(headers)
                self._detect_ssl(url, headers)
            
            # Display results
            self._display_results(url)
            
            # Update scan status
            total_techs = sum(len(v) for v in self.technologies.values())
            self.db.update_scan(scan_id, "completed", total_techs)
            self.logger.scan_complete("tech_fingerprint", url, total_techs)
            
            # Save to file if requested
            if output:
                self._save_results(url, output)
            
            return self.technologies
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("tech_fingerprint", url, str(e))
            print_error(f"Technology detection failed: {e}")
            return {}
    
    def _analyze_headers(self, url):
        """Analyze HTTP headers"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            return dict(response.headers)
        except:
            return {}
    
    def _get_html(self, url):
        """Get HTML content"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            return response.text
        except:
            return None
    
    def _detect_cms(self, html, headers):
        """Detect CMS"""
        html_lower = html.lower()
        
        # WordPress
        if any(x in html_lower for x in ['wp-content', 'wp-includes', 'wordpress']):
            self.technologies['cms'].append('WordPress')
        elif 'x-powered-by' in headers and 'wordpress' in headers['x-powered-by'].lower():
            self.technologies['cms'].append('WordPress')
        
        # Joomla
        if any(x in html_lower for x in ['/media/jui/', 'joomla', 'com_content']):
            self.technologies['cms'].append('Joomla')
        
        # Drupal
        if any(x in html_lower for x in ['drupal', 'sites/default/files', 'misc/drupal.js']):
            self.technologies['cms'].append('Drupal')
        
        # Magento
        if any(x in html_lower for x in ['magento', 'skin/frontend/', 'js/mage/']):
            self.technologies['cms'].append('Magento')
        
        # Shopify
        if 'cdn.shopify.com' in html_lower or 'shopify' in html_lower:
            self.technologies['cms'].append('Shopify')
        
        # Wix
        if 'wix.com' in html_lower or 'wixstatic.com' in html_lower:
            self.technologies['cms'].append('Wix')
        
        # Squarespace
        if 'squarespace.com' in html_lower or 'sqsp' in html_lower:
            self.technologies['cms'].append('Squarespace')
        
        # Ghost
        if 'ghost' in html_lower and ('ghost.io' in html_lower or 'ghost-' in html_lower):
            self.technologies['cms'].append('Ghost')
        
        # Hugo
        if 'hugo' in html_lower:
            self.technologies['cms'].append('Hugo')
        
        # Jekyll
        if 'jekyll' in html_lower:
            self.technologies['cms'].append('Jekyll')
    
    def _detect_framework(self, html, headers):
        """Detect web framework"""
        html_lower = html.lower()
        
        # Laravel
        if any(x in html_lower for x in ['laravel', 'csrf-token', 'laravel_session']):
            self.technologies['framework'].append('Laravel')
        
        # Django
        if any(x in html_lower for x in ['django', 'csrfmiddlewaretoken']):
            self.technologies['framework'].append('Django')
        
        # Flask
        if 'flask' in html_lower:
            self.technologies['framework'].append('Flask')
        
        # Ruby on Rails
        if any(x in html_lower for x in ['rails', 'ruby', 'csrf-param']):
            self.technologies['framework'].append('Ruby on Rails')
        
        # ASP.NET
        if any(x in html_lower for x in ['asp.net', '__viewstate', '__eventvalidation']):
            self.technologies['framework'].append('ASP.NET')
        
        # Spring
        if 'spring' in html_lower:
            self.technologies['framework'].append('Spring')
        
        # Express.js
        if 'x-powered-by' in headers and 'express' in headers['x-powered-by'].lower():
            self.technologies['framework'].append('Express.js')
        
        # Next.js
        if any(x in html_lower for x in ['next.js', '__next', '_next/static']):
            self.technologies['framework'].append('Next.js')
        
        # Nuxt.js
        if any(x in html_lower for x in ['nuxt.js', '__nuxt', '_nuxt/']):
            self.technologies['framework'].append('Nuxt.js')
        
        # Angular
        if any(x in html_lower for x in ['ng-version', 'angular', 'ng-app']):
            self.technologies['framework'].append('Angular')
        
        # Vue.js
        if any(x in html_lower for x in ['vue.js', 'vuejs', 'v-cloak']):
            self.technologies['framework'].append('Vue.js')
        
        # React
        if any(x in html_lower for x in ['react', 'reactroot', 'data-reactroot']):
            self.technologies['framework'].append('React')
        
        # jQuery
        if 'jquery' in html_lower:
            self.technologies['framework'].append('jQuery')
    
    def _detect_server(self, headers):
        """Detect web server"""
        server = headers.get('server', '').lower()
        x_powered = headers.get('x-powered-by', '').lower()
        
        if 'apache' in server:
            self.technologies['server'].append('Apache')
        elif 'nginx' in server:
            self.technologies['server'].append('Nginx')
        elif 'iis' in server:
            self.technologies['server'].append('IIS')
        elif 'lighttpd' in server:
            self.technologies['server'].append('Lighttpd')
        elif 'caddy' in server:
            self.technologies['server'].append('Caddy')
        elif 'openresty' in server:
            self.technologies['server'].append('OpenResty')
        elif 'litespeed' in server:
            self.technologies['server'].append('LiteSpeed')
        
        # X-Powered-By
        if 'php' in x_powered:
            self.technologies['server'].append('PHP')
        elif 'asp.net' in x_powered:
            self.technologies['server'].append('ASP.NET')
        elif 'express' in x_powered:
            self.technologies['server'].append('Express.js')
    
    def _detect_language(self, html, headers):
        """Detect programming language"""
        html_lower = html.lower()
        x_powered = headers.get('x-powered-by', '').lower()
        
        if 'php' in x_powered or '<?php' in html:
            self.technologies['language'].append('PHP')
        elif 'asp.net' in x_powered or 'aspx' in html:
            self.technologies['language'].append('ASP.NET')
        elif 'python' in x_powered or 'django' in x_powered:
            self.technologies['language'].append('Python')
        elif 'ruby' in x_powered:
            self.technologies['language'].append('Ruby')
        elif 'perl' in x_powered:
            self.technologies['language'].append('Perl')
        elif 'node' in x_powered or 'express' in x_powered:
            self.technologies['language'].append('Node.js')
        elif 'java' in x_powered:
            self.technologies['language'].append('Java')
    
    def _detect_javascript(self, html):
        """Detect JavaScript libraries"""
        html_lower = html.lower()
        
        js_libs = {
            'react': ['react', 'reactdom', 'reactroot'],
            'vue.js': ['vue.js', 'vuejs'],
            'angular': ['angular', 'ng-version'],
            'jquery': ['jquery'],
            'bootstrap': ['bootstrap'],
            'tailwind': ['tailwindcss', 'tailwind'],
            'materialize': ['materialize'],
            'bulma': ['bulma'],
            'foundation': ['foundation'],
            'backbone.js': ['backbone.js', 'backbone'],
            'ember.js': ['ember.js', 'ember'],
            'd3.js': ['d3.js', 'd3.min.js'],
            'three.js': ['three.js', 'three.min.js'],
            'gsap': ['gsap', 'greensock'],
            'moment.js': ['moment.js', 'moment.min.js'],
            'lodash': ['lodash', 'underscore'],
            'axios': ['axios'],
            'd3.js': ['d3.js'],
            'chart.js': ['chart.js', 'chartjs'],
            'highcharts': ['highcharts'],
        }
        
        for lib, patterns in js_libs.items():
            if any(pattern in html_lower for pattern in patterns):
                self.technologies['javascript'].append(lib)
    
    def _detect_analytics(self, html):
        """Detect analytics and tracking"""
        html_lower = html.lower()
        
        analytics = {
            'Google Analytics': ['google-analytics', 'gtag', 'ga.js', 'analytics.js'],
            'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
            'Facebook Pixel': ['facebook.net/en_US/fbevents', 'fbq('],
            'Hotjar': ['hotjar.com', 'hj('],
            'Mixpanel': ['mixpanel.com', 'mixpanel.init'],
            'Amplitude': ['amplitude.com', 'amplitude.getInstance'],
            'Segment': ['segment.com/analytics', 'analytics.load'],
            'Matomo': ['matomo.org', 'piwik.js'],
            'Plausible': ['plausible.io'],
            'Clarity': ['clarity.ms'],
        }
        
        for tool, patterns in analytics.items():
            if any(pattern in html_lower for pattern in patterns):
                self.technologies['analytics'].append(tool)
    
    def _detect_cdn(self, headers):
        """Detect CDN"""
        server = headers.get('server', '').lower()
        via = headers.get('via', '').lower()
        x_cache = headers.get('x-cache', '').lower()
        
        cdn_indicators = {
            'Cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status'],
            'Akamai': ['akamai', 'x-akamai'],
            'AWS CloudFront': ['cloudfront', 'x-amz-cf-id'],
            'Fastly': ['fastly', 'x-served-by'],
            'KeyCDN': ['keycdn', 'x-edge-location'],
            'StackPath': ['stackpath', 'highwinds'],
            'MaxCDN': ['maxcdn', 'netdna'],
            'Incapsula': ['incapsula', 'incap_ses'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
        }
        
        headers_str = f"{server} {via} {x_cache}".lower()
        all_headers = ' '.join(f"{k}: {v}".lower() for k, v in headers.items())
        
        for cdn, patterns in cdn_indicators.items():
            if any(pattern in headers_str or pattern in all_headers for pattern in patterns):
                self.technologies['cdn'].append(cdn)
    
    def _detect_ssl(self, url, headers):
        """Detect SSL/TLS information"""
        if url.startswith('https://'):
            self.technologies['ssl'].append('HTTPS Enabled')
        
        hsts = headers.get('strict-transport-security')
        if hsts:
            self.technologies['ssl'].append('HSTS Enabled')
    
    def _display_results(self, url):
        """Display detection results"""
        print_section("Detected Technologies")
        
        total_techs = sum(len(v) for v in self.technologies.values())
        
        if total_techs == 0:
            print_warning("No technologies detected")
            return
        
        # CMS
        if self.technologies['cms']:
            cprint(f"    {'CMS:':<20} {', '.join(self.technologies['cms'])}", Colors.BGREEN)
        
        # Framework
        if self.technologies['framework']:
            cprint(f"    {'Framework:':<20} {', '.join(self.technologies['framework'])}", Colors.BCYAN)
        
        # Server
        if self.technologies['server']:
            cprint(f"    {'Server:':<20} {', '.join(self.technologies['server'])}", Colors.BWHITE)
        
        # Language
        if self.technologies['language']:
            cprint(f"    {'Language:':<20} {', '.join(self.technologies['language'])}", Colors.BYELLOW)
        
        # JavaScript
        if self.technologies['javascript']:
            cprint(f"    {'JavaScript:':<20} {', '.join(self.technologies['javascript'])}", Colors.BMAGENTA)
        
        # Analytics
        if self.technologies['analytics']:
            cprint(f"    {'Analytics:':<20} {', '.join(self.technologies['analytics'])}", Colors.BBLUE)
        
        # CDN
        if self.technologies['cdn']:
            cprint(f"    {'CDN:':<20} {', '.join(self.technologies['cdn'])}", Colors.BRED)
        
        # SSL
        if self.technologies['ssl']:
            cprint(f"    {'SSL/TLS:':<20} {', '.join(self.technologies['ssl'])}", Colors.BGREEN)
        
        print()
        print_info(f"Total technologies detected: {total_techs}")
    
    def _save_results(self, url, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'url': url,
                    'technologies': self.technologies,
                    'total': sum(len(v) for v in self.technologies.values())
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
