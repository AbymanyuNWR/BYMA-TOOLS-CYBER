"""
BYMA TOOLS - CORS Scanner
Tools untuk testing CORS misconfiguration
"""
import requests
import json
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class CORSScanner:
    """CORS misconfiguration scanner"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.vulnerabilities = []
    
    def scan(self, url, output=None):
        """Main scan function"""
        print_section(f"CORS Scan: {url}")
        
        scan_id = self.db.create_scan("cors_scanner", url, "vulnerability")
        self.logger.scan_start("cors_scanner", url)
        
        try:
            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            # Test various origin scenarios
            print_info("Testing CORS configuration...")
            self._test_cors(url)
            
            # Save to database
            for vuln in self.vulnerabilities:
                self.db.add_vulnerability(
                    scan_id, url, 'CORS Misconfiguration', vuln['severity'],
                    vuln['title'], vuln['description'],
                    vuln.get('evidence'), vuln.get('remediation')
                )
            
            self.db.update_scan(scan_id, "completed", len(self.vulnerabilities))
            self.logger.scan_complete("cors_scanner", url, len(self.vulnerabilities))
            
            self._display_results()
            
            if output:
                self._save_results(url, output)
            
            return self.vulnerabilities
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("cors_scanner", url, str(e))
            print_error(f"CORS scan failed: {e}")
            return []
    
    def _test_cors(self, url):
        """Test CORS configuration"""
        # Extract domain from URL
        try:
            domain = url.split('://')[1].split('/')[0]
        except:
            domain = url
        
        test_origins = [
            ('null', 'Null Origin'),
            (f"https://{domain}", 'Same Origin'),
            ('https://evil.com', 'External Origin'),
            ('https://attacker.com', 'Attacker Domain'),
            (f"https://{domain}.evil.com", 'Subdomain of Target'),
            (f"https://sub.{domain}", 'Subdomain'),
            ('http://localhost', 'Localhost'),
            ('http://127.0.0.1', 'Loopback IP'),
        ]
        
        for origin, description in test_origins:
            self._test_origin(url, origin, description)
    
    def _test_origin(self, url, origin, description):
        """Test single origin"""
        try:
            headers = {
                'Origin': origin,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            # Check CORS headers
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')
            
            if acao:
                # Check for wildcard
                if acao == '*':
                    self.vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'title': 'CORS Wildcard Origin',
                        'description': 'Server responds with Access-Control-Allow-Origin: *',
                        'evidence': f'Origin: {origin}, ACAO: {acao}',
                        'remediation': 'Restrict CORS to specific trusted origins'
                    })
                    print_warning(f"Wildcard origin allowed: {origin}")
                
                # Check if origin is reflected
                elif acao == origin and origin not in ['null']:
                    severity = 'HIGH' if acac == 'true' else 'MEDIUM'
                    self.vulnerabilities.append({
                        'severity': severity,
                        'title': f'CORS Origin Reflection ({description})',
                        'description': f'Server reflects origin: {origin}',
                        'evidence': f'Origin: {origin}, ACAO: {acao}, ACAC: {acac}',
                        'remediation': 'Validate and restrict allowed origins'
                    })
                    print_warning(f"Origin reflected: {origin}")
                
                # Check null origin
                elif acao == 'null' and origin == 'null':
                    self.vulnerabilities.append({
                        'severity': 'HIGH',
                        'title': 'CORS Null Origin Allowed',
                        'description': 'Server allows null origin in CORS',
                        'evidence': f'Origin: {origin}, ACAO: {acao}',
                        'remediation': 'Do not allow null origin in CORS policy'
                    })
                    print_warning("Null origin allowed")
        
        except Exception as e:
            pass
    
    def _display_results(self):
        """Display CORS scan results"""
        print_section("CORS Scan Results")
        
        if not self.vulnerabilities:
            print_success("No CORS misconfigurations found")
            return
        
        print_warning(f"Found {len(self.vulnerabilities)} CORS issues:")
        print()
        
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            color = Colors.BRED if severity in ['CRITICAL', 'HIGH'] else Colors.BYELLOW
            
            cprint(f"    [{severity}] {vuln['title']}", color)
            cprint(f"      Description: {vuln['description']}", Colors.BWHITE)
            if vuln.get('evidence'):
                cprint(f"      Evidence: {vuln['evidence']}", Colors.BBLACK)
            print()
    
    def _save_results(self, url, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'url': url,
                    'vulnerabilities': self.vulnerabilities,
                    'total': len(self.vulnerabilities)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
