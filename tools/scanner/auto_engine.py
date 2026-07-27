"""
BYMA TOOLS - Advanced Auto Scan Engine
Intelligent auto-scanning with AI-powered decision making
"""
import re
import json
import time
import socket
import requests
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons, print_scan_start, print_scan_complete
)
from core.logger import get_logger
from core.database import get_database


class AutoScanEngine:
    """AI-powered auto scan engine with intelligent decision making"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.scan_plan = []
        self.results = {}
        self.start_time = None
        self.target_info = {}
    
    # Scan profiles
    SCAN_PROFILES = {
        'passive': {
            'name': 'Passive Reconnaissance',
            'description': 'Non-intrusive information gathering',
            'tools': ['whois', 'dns', 'headers', 'ssl'],
            'risk': 'LOW',
        },
        'smart': {
            'name': 'Smart Scan',
            'description': 'Balanced scan with intelligent decisions',
            'tools': ['whois', 'dns', 'headers', 'ssl', 'vuln', 'dir'],
            'risk': 'MEDIUM',
        },
        'aggressive': {
            'name': 'Aggressive Scan',
            'description': 'Comprehensive deep scanning',
            'tools': ['whois', 'dns', 'headers', 'ssl', 'vuln', 'dir', 'sqli', 'xss'],
            'risk': 'HIGH',
        },
        'full': {
            'name': 'Full Security Audit',
            'description': 'Complete security assessment',
            'tools': ['whois', 'dns', 'headers', 'ssl', 'vuln', 'dir', 'sqli', 'xss', 'tech'],
            'risk': 'HIGH',
        },
    }
    
    def auto_scan(self, target, mode='smart', output=None):
        """Main auto scan function"""
        self.start_time = datetime.now()
        
        print_section("AUTO SCAN ENGINE")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("auto_scan", target, "auto")
        self.logger.scan_start("auto_scan", target)
        
        try:
            # Analyze target
            print_subsection("Target Analysis")
            self.target_info = self._analyze_target(target)
            self._display_target_info()
            
            # Create intelligent scan plan
            print_subsection("Creating Scan Plan")
            self.scan_plan = self._create_intelligent_plan(target, mode)
            self._display_plan()
            
            # Execute scan plan
            print_subsection("Executing Scan Plan")
            self._execute_plan(target, scan_id)
            
            # Generate summary
            self._generate_summary()
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.results))
            self.logger.scan_complete("auto_scan", target, len(self.results))
            
            # Save results
            if output:
                self._save_results(target, output)
            
            return self.results
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("auto_scan", target, str(e))
            print_error(f"Auto scan failed: {e}")
            return {}
    
    def _analyze_target(self, target):
        """Analyze target to determine best scanning approach"""
        info = {
            'original': target,
            'type': 'unknown',
            'protocol': None,
            'hostname': None,
            'port': None,
            'path': None,
            'is_web': False,
            'is_ip': False,
            'is_domain': False,
            'is_url': False,
            'open_ports': [],
            'services': [],
            'technologies': [],
            'web_server': None,
            'cms': None,
            'os': None,
            'response_time': 0,
        }
        
        # Detect target type
        if target.startswith(('http://', 'https://')):
            info['is_url'] = True
            info['is_web'] = True
            info['protocol'] = 'https' if target.startswith('https') else 'http'
            
            parsed = urlparse(target)
            info['hostname'] = parsed.hostname
            info['port'] = parsed.port or (443 if info['protocol'] == 'https' else 80)
            info['path'] = parsed.path
            info['type'] = 'url'
        
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            info['is_ip'] = True
            info['type'] = 'ip'
            info['hostname'] = target
        
        elif '/' in target:
            info['type'] = 'cidr'
            info['is_ip'] = True
            info['hostname'] = target
        
        elif re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
            info['is_domain'] = True
            info['type'] = 'domain'
            info['hostname'] = target
            info['is_web'] = True
        
        else:
            info['type'] = 'hostname'
            info['hostname'] = target
            info['is_web'] = True
        
        # Quick port check for web services
        if info['is_web']:
            self._quick_web_check(info)
        
        return info
    
    def _quick_web_check(self, info):
        """Quick check for web services"""
        try:
            start_time = time.time()
            
            # Try HTTPS first, then HTTP
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{info['hostname']}"
                    response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                    
                    info['response_time'] = time.time() - start_time
                    info['status_code'] = response.status_code
                    info['web_server'] = response.headers.get('Server', 'Unknown')
                    
                    # Detect technologies
                    headers_str = str(response.headers).lower()
                    body_lower = response.text.lower()
                    
                    # CMS detection
                    cms_indicators = {
                        'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                        'Joomla': ['joomla', '/components/'],
                        'Drupal': ['drupal', 'sites/default'],
                        'Laravel': ['laravel', 'csrf-token'],
                        'Django': ['csrfmiddlewaretoken'],
                        'ASP.NET': ['__viewstate', 'asp.net'],
                    }
                    
                    for cms, indicators in cms_indicators.items():
                        for indicator in indicators:
                            if indicator.lower() in headers_str or indicator.lower() in body_lower:
                                info['cms'] = cms
                                info['technologies'].append(cms)
                                break
                    
                    # Server detection
                    server = response.headers.get('Server', '')
                    if 'apache' in server.lower():
                        info['web_server'] = 'Apache'
                    elif 'nginx' in server.lower():
                        info['web_server'] = 'Nginx'
                    elif 'iis' in server.lower():
                        info['web_server'] = 'IIS'
                    
                    break
                
                except:
                    continue
        
        except:
            pass
    
    def _create_intelligent_plan(self, target, mode):
        """Create intelligent scan plan based on target analysis"""
        profile = self.SCAN_PROFILES.get(mode, self.SCAN_PROFILES['smart'])
        
        plan = []
        
        # Always start with passive recon
        plan.append({
            'phase': 1,
            'name': 'Passive Reconnaissance',
            'tools': ['whois_lookup', 'dns_lookup'],
            'description': 'Gathering publicly available information',
            'estimated_time': '30s',
        })
        
        # Add web-specific scans if target is web
        if self.target_info.get('is_web'):
            plan.append({
                'phase': 2,
                'name': 'Web Analysis',
                'tools': ['header_analyzer', 'tech_fingerprint'],
                'description': 'Analyzing web application security headers and technology',
                'estimated_time': '20s',
            })
            
            plan.append({
                'phase': 3,
                'name': 'SSL/TLS Analysis',
                'tools': ['ssl_checker'],
                'description': 'Checking SSL/TLS configuration',
                'estimated_time': '15s',
            })
            
            plan.append({
                'phase': 4,
                'name': 'Vulnerability Scanning',
                'tools': ['vuln_scanner'],
                'description': 'Scanning for common vulnerabilities',
                'estimated_time': '60s',
            })
            
            # Add deeper scans based on mode
            if mode in ['aggressive', 'full']:
                plan.append({
                    'phase': 5,
                    'name': 'Directory Discovery',
                    'tools': ['dir_bruteforce'],
                    'description': 'Discovering hidden directories and files',
                    'estimated_time': '120s',
                })
            
            if mode == 'full':
                plan.append({
                    'phase': 6,
                    'name': 'Injection Testing',
                    'tools': ['sql_injection', 'xss_scanner'],
                    'description': 'Testing for injection vulnerabilities',
                    'estimated_time': '180s',
                })
        
        else:
            # Non-web target
            plan.append({
                'phase': 2,
                'name': 'Port Scanning',
                'tools': ['port_scanner'],
                'description': 'Scanning for open ports and services',
                'estimated_time': '60s',
            })
        
        return plan
    
    def _display_target_info(self):
        """Display target information"""
        print(f"  {Colors.BCYAN}Target:{Colors.BWHITE}       {self.target_info['original']}")
        print(f"  {Colors.BCYAN}Type:{Colors.BWHITE}         {self.target_info['type'].upper()}")
        print(f"  {Colors.BCYAN}Hostname:{Colors.BWHITE}     {self.target_info.get('hostname', 'N/A')}")
        
        if self.target_info.get('web_server'):
            print(f"  {Colors.BCYAN}Web Server:{Colors.BWHITE}   {self.target_info['web_server']}")
        
        if self.target_info.get('cms'):
            print(f"  {Colors.BCYAN}CMS:{Colors.BWHITE}          {self.target_info['cms']}")
        
        if self.target_info.get('technologies'):
            print(f"  {Colors.BCYAN}Technologies:{Colors.BWHITE} {', '.join(self.target_info['technologies'])}")
        
        if self.target_info.get('response_time'):
            print(f"  {Colors.BCYAN}Response Time:{Colors.BWHITE} {self.target_info['response_time']:.2f}s")
        
        print()
    
    def _display_plan(self):
        """Display scan plan"""
        print(f"  {Colors.BCYAN}+{'=' * 50}+{Colors.RESET}")
        print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}  SCAN PLAN {' ' * 39}  {Colors.BCYAN}|{Colors.RESET}")
        print(f"  {Colors.BCYAN}+{'-' * 50}+{Colors.RESET}")
        
        for phase in self.scan_plan:
            print(f"  {Colors.BCYAN}|{Colors.BYELLOW}  Phase {phase['phase']}: {phase['name']:<34} {Colors.BCYAN}|{Colors.RESET}")
            print(f"  {Colors.BCYAN}|{Colors.BWHITE}    Tools: {', '.join(phase['tools']):<37} {Colors.BCYAN}|{Colors.RESET}")
            print(f"  {Colors.BCYAN}|{Colors.BBLACK}    ETA: {phase['estimated_time']:<40} {Colors.BCYAN}|{Colors.RESET}")
            print(f"  {Colors.BCYAN}+{'-' * 50}+{Colors.RESET}")
        
        print()
    
    def _execute_plan(self, target, scan_id):
        """Execute the scan plan"""
        total_phases = len(self.scan_plan)
        
        for phase in self.scan_plan:
            print_subsection(f"Phase {phase['phase']}/{total_phases}: {phase['name']}")
            print_info(f"Tools: {', '.join(phase['tools'])}")
            print()
            
            for tool in phase['tools']:
                try:
                    self._execute_tool(tool, target, scan_id)
                except Exception as e:
                    print_warning(f"  Tool {tool} failed: {e}")
            
            print()
    
    def _execute_tool(self, tool, target, scan_id):
        """Execute a specific tool"""
        print_info(f"  Running {tool}...")
        
        try:
            if tool == 'whois_lookup':
                from tools.recon.whois_lookup import WhoisLookup
                scanner = WhoisLookup()
                result = scanner.lookup(target)
                self.results['whois'] = result
            
            elif tool == 'dns_lookup':
                from tools.recon.dns_lookup import DNSLookup
                scanner = DNSLookup()
                result = scanner.lookup(target)
                self.results['dns'] = result
            
            elif tool == 'header_analyzer':
                from tools.web.header_analyzer import HeaderAnalyzer
                analyzer = HeaderAnalyzer()
                result = analyzer.analyze(target)
                self.results['headers'] = result
            
            elif tool == 'tech_fingerprint':
                from tools.recon.tech_fingerprint import TechFingerprint
                fingerprinter = TechFingerprint()
                result = fingerprinter.fingerprint(target)
                self.results['tech'] = result
            
            elif tool == 'ssl_checker':
                from tools.scanner.ssl_checker import SSLChecker
                checker = SSLChecker()
                result = checker.scan(target)
                self.results['ssl'] = result
            
            elif tool == 'vuln_scanner':
                from tools.scanner.vuln_scanner import VulnScanner
                scanner = VulnScanner()
                result = scanner.scan(target)
                self.results['vuln'] = result
            
            elif tool == 'dir_bruteforce':
                from tools.scanner.dir_bruteforce import DirectoryBruteforcer
                scanner = DirectoryBruteforcer()
                result = scanner.scan(target, threads=50)
                self.results['dir'] = result
            
            elif tool == 'sql_injection':
                from tools.scanner.sql_injection import SQLInjectionScanner
                scanner = SQLInjectionScanner()
                result = scanner.scan(target)
                self.results['sqli'] = result
            
            elif tool == 'xss_scanner':
                from tools.scanner.xss_scanner import XSSScanner
                scanner = XSSScanner()
                result = scanner.scan(target)
                self.results['xss'] = result
            
            elif tool == 'port_scanner':
                from tools.recon.port_scanner import PortScanner
                scanner = PortScanner()
                result = scanner.scan(target, ports="1-1024")
                self.results['ports'] = result
            
            print_success(f"  {tool} completed")
        
        except Exception as e:
            print_error(f"  {tool} failed: {e}")
    
    def _generate_summary(self):
        """Generate scan summary"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        print_section("AUTO SCAN SUMMARY")
        
        print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {self.target_info['original']}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Duration:{Colors.BWHITE}      {elapsed:.1f}s")
        print(f"  {Icons.INFO} {Colors.BCYAN}Phases:{Colors.BWHITE}        {len(self.scan_plan)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Results:{Colors.BWHITE}       {len(self.results)}")
        
        # Count vulnerabilities
        total_vulns = 0
        if 'vuln' in self.results and isinstance(self.results['vuln'], list):
            total_vulns = len(self.results['vuln'])
        
        print(f"  {Icons.WARNING} {Colors.BCYAN}Vulnerabilities:{Colors.BWHITE} {total_vulns}")
        
        print_separator("-", 50)
        print()
        
        # Recommendations
        print_subsection("Recommendations")
        
        if self.target_info.get('is_web'):
            print_info("- Run full security audit for comprehensive testing")
            print_info("- Check for SQL injection and XSS vulnerabilities")
            print_info("- Verify all security headers are properly configured")
        
        print_info("- Keep all software up to date")
        print_info("- Implement security best practices")
        print_info("- Regular security assessments recommended")
        print()
    
    def _save_results(self, target, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'target': target,
                'scan_time': self.start_time.isoformat(),
                'target_info': self.target_info,
                'scan_plan': self.scan_plan,
                'results': self.results,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
