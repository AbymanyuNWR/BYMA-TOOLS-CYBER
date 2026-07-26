"""
BYMA TOOLS - Auto Scan Engine
Intelligent auto-scanning yang otomatis mendeteksi target dan menjalankan scan terbaik
"""
import re
import json
import time
from pathlib import Path
from urllib.parse import urlparse
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class AutoScanEngine:
    """AI-powered auto scan engine"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.scan_plan = []
        self.results = {}
    
    def auto_scan(self, target, mode='smart', output=None):
        """Main auto scan function"""
        print_section(f"Auto Scan Engine - Mode: {mode.upper()}")
        
        # Analyze target
        print_info("Analyzing target...")
        target_info = self._analyze_target(target)
        
        # Create scan plan
        print_info("Creating intelligent scan plan...")
        self.scan_plan = self._create_scan_plan(target_info, mode)
        
        # Display plan
        self._display_plan()
        
        # Execute scan plan
        print_info("Executing scan plan...")
        self._execute_plan(target, target_info)
        
        # Generate summary
        self._generate_summary()
        
        # Save results
        if output:
            self._save_results(target, output)
        
        return self.results
    
    def _analyze_target(self, target):
        """Analyze target to determine best scanning approach"""
        info = {
            'original': target,
            'type': None,
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
            'technologies': []
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
        
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            info['is_ip'] = True
            info['type'] = 'ip'
            info['hostname'] = target
        
        elif '/' in target:
            info['type'] = 'cidr'
            info['is_ip'] = True
            info['hostname'] = target
        
        else:
            info['is_domain'] = True
            info['type'] = 'domain'
            info['hostname'] = target
            info['is_web'] = True
        
        return info
    
    def _create_scan_plan(self, target_info, mode):
        """Create intelligent scan plan based on target"""
        plan = []
        
        # Phase 1: Reconnaissance
        recon_steps = []
        
        if target_info['is_domain'] or target_info['is_url']:
            recon_steps.append({
                'tool': 'subdomain',
                'name': 'Subdomain Enumeration',
                'priority': 'high',
                'description': 'Discover all subdomains'
            })
            recon_steps.append({
                'tool': 'dns',
                'name': 'DNS Enumeration',
                'priority': 'high',
                'description': 'Query all DNS records'
            })
            recon_steps.append({
                'tool': 'whois',
                'name': 'WHOIS Lookup',
                'priority': 'medium',
                'description': 'Get domain registration info'
            })
        
        if target_info['is_ip'] or target_info['is_url']:
            recon_steps.append({
                'tool': 'port',
                'name': 'Port Scanning',
                'priority': 'high',
                'description': 'Scan open ports and services'
            })
            recon_steps.append({
                'tool': 'ip',
                'name': 'IP Geolocation',
                'priority': 'low',
                'description': 'Get IP location info'
            })
        
        if target_info['is_web']:
            recon_steps.append({
                'tool': 'tech',
                'name': 'Technology Detection',
                'priority': 'high',
                'description': 'Identify web technologies'
            })
            recon_steps.append({
                'tool': 'email',
                'name': 'Email Harvesting',
                'priority': 'medium',
                'description': 'Find email addresses'
            })
        
        plan.append({
            'phase': 'Reconnaissance',
            'steps': recon_steps
        })
        
        # Phase 2: Vulnerability Scanning
        vuln_steps = []
        
        if target_info['is_web']:
            vuln_steps.append({
                'tool': 'vuln',
                'name': 'Vulnerability Scan',
                'priority': 'high',
                'description': 'Scan for common vulnerabilities'
            })
            vuln_steps.append({
                'tool': 'sqli',
                'name': 'SQL Injection Test',
                'priority': 'high',
                'description': 'Test for SQL injection'
            })
            vuln_steps.append({
                'tool': 'xss',
                'name': 'XSS Test',
                'priority': 'high',
                'description': 'Test for Cross-Site Scripting'
            })
            vuln_steps.append({
                'tool': 'headers',
                'name': 'Security Headers Check',
                'priority': 'medium',
                'description': 'Analyze security headers'
            })
            vuln_steps.append({
                'tool': 'ssl',
                'name': 'SSL/TLS Check',
                'priority': 'medium',
                'description': 'Check SSL/TLS configuration'
            })
            vuln_steps.append({
                'tool': 'dir',
                'name': 'Directory Bruteforce',
                'priority': 'medium',
                'description': 'Find hidden directories'
            })
        
        plan.append({
            'phase': 'Vulnerability Scanning',
            'steps': vuln_steps
        })
        
        # Phase 3: Exploitation (only in aggressive mode)
        if mode == 'aggressive':
            exploit_steps = []
            
            if target_info['is_web']:
                exploit_steps.append({
                    'tool': 'waf',
                    'name': 'WAF Detection',
                    'priority': 'high',
                    'description': 'Detect WAF and attempt bypass'
                })
                exploit_steps.append({
                    'tool': 'credential',
                    'name': 'Credential Harvesting',
                    'priority': 'high',
                    'description': 'Attempt to find credentials'
                })
            
            plan.append({
                'phase': 'Exploitation',
                'steps': exploit_steps
            })
        
        return plan
    
    def _display_plan(self):
        """Display scan plan"""
        print_section("Scan Plan")
        
        for i, phase in enumerate(self.scan_plan, 1):
            cprint(f"    Phase {i}: {phase['phase']}", Colors.BCYAN)
            for step in phase['steps']:
                priority_color = {
                    'high': Colors.BRED,
                    'medium': Colors.BYELLOW,
                    'low': Colors.BGREEN
                }.get(step['priority'], Colors.BWHITE)
                
                cprint(f"      [{step['priority'].upper():<8}] {step['name']}", priority_color)
                cprint(f"              {step['description']}", Colors.BBLACK)
            print()
    
    def _execute_plan(self, target, target_info):
        """Execute scan plan"""
        total_phases = len(self.scan_plan)
        
        for phase_idx, phase in enumerate(self.scan_plan, 1):
            print_section(f"Phase {phase_idx}/{total_phases}: {phase['phase']}")
            
            for step in phase['steps']:
                self._execute_step(target, target_info, step)
    
    def _execute_step(self, target, target_info, step):
        """Execute single scan step"""
        tool = step['tool']
        print_info(f"Running: {step['name']}...")
        
        try:
            if tool == 'subdomain':
                from tools.recon.subdomain import SubdomainEnumerator
                scanner = SubdomainEnumerator()
                result = scanner.enumerate(target_info['hostname'])
                self.results['subdomains'] = list(result) if result else []
            
            elif tool == 'dns':
                from tools.recon.dns_lookup import DNSLookup
                scanner = DNSLookup()
                result = scanner.lookup(target_info['hostname'])
                self.results['dns'] = result
            
            elif tool == 'whois':
                from tools.recon.whois_lookup import WhoisLookup
                scanner = WhoisLookup()
                result = scanner.lookup(target_info['hostname'])
                self.results['whois'] = result
            
            elif tool == 'port':
                from tools.recon.port_scanner import PortScanner
                scanner = PortScanner()
                result = scanner.scan(target_info['hostname'])
                self.results['ports'] = result
                target_info['open_ports'] = [p['port'] for p in result] if result else []
            
            elif tool == 'ip':
                from tools.recon.ip_lookup import IPLookup
                scanner = IPLookup()
                result = scanner.lookup(target_info['hostname'])
                self.results['ip_info'] = result
            
            elif tool == 'tech':
                from tools.recon.tech_fingerprint import TechFingerprint
                scanner = TechFingerprint()
                result = scanner.detect(target)
                self.results['technologies'] = result
            
            elif tool == 'email':
                from tools.recon.email_harvest import EmailHarvester
                scanner = EmailHarvester()
                result = scanner.harvest(target_info['hostname'])
                self.results['emails'] = list(result) if result else []
            
            elif tool == 'vuln':
                from tools.scanner.vuln_scanner import VulnScanner
                scanner = VulnScanner()
                result = scanner.scan(target)
                self.results['vulnerabilities'] = result
            
            elif tool == 'sqli':
                from tools.scanner.sql_injection import SQLInjectionScanner
                scanner = SQLInjectionScanner()
                result = scanner.scan(target)
                self.results['sqli'] = result
            
            elif tool == 'xss':
                from tools.scanner.xss_scanner import XSSScanner
                scanner = XSSScanner()
                result = scanner.scan(target)
                self.results['xss'] = result
            
            elif tool == 'headers':
                from tools.web.header_analyzer import HeaderAnalyzer
                scanner = HeaderAnalyzer()
                result = scanner.analyze(target)
                self.results['headers'] = result
            
            elif tool == 'ssl':
                from tools.scanner.ssl_checker import SSLChecker
                scanner = SSLChecker()
                hostname = target_info['hostname']
                result = scanner.check(hostname)
                self.results['ssl'] = result
            
            elif tool == 'dir':
                from tools.scanner.dir_bruteforce import DirBruteforcer
                scanner = DirBruteforcer()
                result = scanner.bruteforce(target)
                self.results['directories'] = result
            
            elif tool == 'waf':
                from tools.scanner.waf_detect import WAFDetector
                scanner = WAFDetector()
                result = scanner.detect(target)
                self.results['waf'] = result
            
            elif tool == 'credential':
                from tools.exploit.credential_harvest import CredentialHarvester
                harvester = CredentialHarvester()
                result = harvester.harvest(target)
                self.results['credentials'] = result
            
            print_success(f"  Completed: {step['name']}")
        
        except Exception as e:
            print_error(f"  Failed: {step['name']} - {e}")
            self.logger.error(f"Scan step failed: {step['name']} - {e}")
    
    def _generate_summary(self):
        """Generate scan summary"""
        print_section("Scan Summary")
        
        # Count findings
        total_findings = 0
        
        if 'vulnerabilities' in self.results:
            vulns = self.results['vulnerabilities']
            total_findings += len(vulns)
            cprint(f"    Vulnerabilities: {len(vulns)}", Colors.BRED)
        
        if 'sqli' in self.results:
            sqli = self.results['sqli']
            total_findings += len(sqli)
            cprint(f"    SQL Injection: {len(sqli)}", Colors.BRED)
        
        if 'xss' in self.results:
            xss = self.results['xss']
            total_findings += len(xss)
            cprint(f"    XSS: {len(xss)}", Colors.BRED)
        
        if 'subdomains' in self.results:
            subs = self.results['subdomains']
            cprint(f"    Subdomains: {len(subs)}", Colors.BCYAN)
        
        if 'ports' in self.results:
            ports = self.results['ports']
            cprint(f"    Open Ports: {len(ports)}", Colors.BCYAN)
        
        if 'emails' in self.results:
            emails = self.results['emails']
            cprint(f"    Emails: {len(emails)}", Colors.BCYAN)
        
        print()
        cprint(f"    Total Findings: {total_findings}", Colors.BGREEN if total_findings == 0 else Colors.BRED)
    
    def _save_results(self, target, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'target': target,
                    'scan_plan': self.scan_plan,
                    'results': self.results
                }, f, indent=2, default=str)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
