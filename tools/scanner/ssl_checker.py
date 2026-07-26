"""
BYMA TOOLS - SSL/TLS Checker
Tools untuk checking keamanan SSL/TLS certificate dan konfigurasi
"""
import ssl
import socket
import json
import requests
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class SSLChecker:
    """SSL/TLS certificate and configuration checker"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.vulnerabilities = []
    
    def check(self, hostname, output=None):
        """Main check function"""
        print_section(f"SSL/TLS Check: {hostname}")
        
        scan_id = self.db.create_scan("ssl_checker", hostname, "vulnerability")
        self.logger.scan_start("ssl_checker", hostname)
        
        try:
            # Remove protocol if present
            hostname = hostname.replace('https://', '').replace('http://', '')
            hostname = hostname.split('/')[0]
            
            # Check certificate
            print_info("Checking SSL certificate...")
            cert_info = self._check_certificate(hostname)
            
            # Check TLS versions
            print_info("Checking TLS versions...")
            tls_info = self._check_tls_versions(hostname)
            
            # Check cipher suites
            print_info("Checking cipher suites...")
            cipher_info = self._check_cipher_suites(hostname)
            
            # Check for known vulnerabilities
            print_info("Checking for vulnerabilities...")
            self._check_vulnerabilities(hostname, cert_info, tls_info)
            
            # Display results
            self._display_results(hostname, cert_info, tls_info, cipher_info)
            
            # Save to database
            for vuln in self.vulnerabilities:
                self.db.add_vulnerability(
                    scan_id, hostname, 'SSL/TLS', vuln['severity'],
                    vuln['title'], vuln['description'],
                    vuln.get('evidence'), vuln.get('remediation')
                )
            
            self.db.update_scan(scan_id, "completed", len(self.vulnerabilities))
            self.logger.scan_complete("ssl_checker", hostname, len(self.vulnerabilities))
            
            if output:
                self._save_results(hostname, cert_info, tls_info, cipher_info, output)
            
            return {'certificate': cert_info, 'tls': tls_info, 'ciphers': cipher_info}
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("ssl_checker", hostname, str(e))
            print_error(f"SSL check failed: {e}")
            return {}
    
    def _check_certificate(self, hostname):
        """Check SSL certificate"""
        cert_info = {
            'subject': None,
            'issuer': None,
            'serial_number': None,
            'not_before': None,
            'not_after': None,
            'san': [],
            'version': None,
            'signature_algorithm': None,
            'key_size': None,
            'is_valid': False,
            'days_remaining': None
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate info
                    cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    cert_info['serial_number'] = cert.get('serialNumber')
                    cert_info['not_before'] = cert.get('notBefore')
                    cert_info['not_after'] = cert.get('notAfter')
                    cert_info['version'] = cert.get('version')
                    
                    # Extract SAN
                    san = cert.get('subjectAltName', ())
                    cert_info['san'] = [entry[1] for entry in san]
                    
                    # Check validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    cert_info['days_remaining'] = (not_after - datetime.now()).days
                    cert_info['is_valid'] = cert_info['days_remaining'] > 0
            
            # Get certificate details using OpenSSL
            cert_info.update(self._get_cert_details(hostname))
        
        except ssl.SSLCertVerificationError as e:
            print_error(f"Certificate verification failed: {e}")
            cert_info['is_valid'] = False
        except Exception as e:
            print_warning(f"Certificate check failed: {e}")
        
        return cert_info
    
    def _get_cert_details(self, hostname):
        """Get additional certificate details"""
        details = {}
        
        try:
            import subprocess
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{hostname}:443', '-servername', hostname],
                input=b'',
                capture_output=True,
                timeout=10
            )
            
            output = result.stdout.decode()
            
            # Extract key size
            if 'Public-Key:' in output:
                key_line = [l for l in output.split('\n') if 'Public-Key:' in l]
                if key_line:
                    details['key_size'] = key_line[0].split('(')[1].split(')')[0]
            
            # Extract signature algorithm
            if 'Signature Algorithm:' in output:
                sig_line = [l for l in output.split('\n') if 'Signature Algorithm:' in l]
                if sig_line:
                    details['signature_algorithm'] = sig_line[0].split(':')[1].strip()
        
        except:
            pass
        
        return details
    
    def _check_tls_versions(self, hostname):
        """Check supported TLS versions"""
        tls_versions = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        # Check each TLS version
        for version_name, ssl_constant in [
            ('SSLv3', ssl.PROTOCOL_TLS),  # Will test separately
            ('TLSv1', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
            ('TLSv1.2', ssl.PROTOCOL_TLS),
            ('TLSv1.3', ssl.PROTOCOL_TLS),
        ]:
            if ssl_constant is None:
                continue
            
            try:
                context = ssl.SSLContext(ssl_constant)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        tls_versions[version_name] = True
            except:
                pass
        
        return tls_versions
    
    def _check_cipher_suites(self, hostname):
        """Check supported cipher suites"""
        ciphers = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    ciphers.append({
                        'name': cipher[0],
                        'protocol': cipher[1],
                        'bits': cipher[2]
                    })
        except:
            pass
        
        return ciphers
    
    def _check_vulnerabilities(self, hostname, cert_info, tls_info):
        """Check for known SSL/TLS vulnerabilities"""
        # Check for expired certificate
        if not cert_info.get('is_valid'):
            self.vulnerabilities.append({
                'severity': 'CRITICAL',
                'title': 'Expired SSL Certificate',
                'description': 'The SSL certificate has expired',
                'remediation': 'Renew the SSL certificate'
            })
        
        # Check for certificate expiring soon
        if cert_info.get('days_remaining', 0) < 30:
            self.vulnerabilities.append({
                'severity': 'HIGH',
                'title': 'SSL Certificate Expiring Soon',
                'description': f"Certificate expires in {cert_info.get('days_remaining')} days",
                'remediation': 'Renew the SSL certificate before expiration'
            })
        
        # Check for weak TLS versions
        if tls_info.get('SSLv3'):
            self.vulnerabilities.append({
                'severity': 'CRITICAL',
                'title': 'SSLv3 Supported (POODLE Vulnerability)',
                'description': 'Server supports SSLv3 which is vulnerable to POODLE attack',
                'remediation': 'Disable SSLv3 support'
            })
        
        if tls_info.get('TLSv1'):
            self.vulnerabilities.append({
                'severity': 'HIGH',
                'title': 'TLSv1.0 Supported',
                'description': 'Server supports TLSv1.0 which is deprecated',
                'remediation': 'Disable TLSv1.0 and use TLSv1.2 or higher'
            })
        
        if tls_info.get('TLSv1.1'):
            self.vulnerabilities.append({
                'severity': 'MEDIUM',
                'title': 'TLSv1.1 Supported',
                'description': 'Server supports TLSv1.1 which is deprecated',
                'remediation': 'Disable TLSv1.1 and use TLSv1.2 or higher'
            })
        
        # Check for weak key size
        key_size = cert_info.get('key_size', '')
        if key_size and '1024' in str(key_size):
            self.vulnerabilities.append({
                'severity': 'HIGH',
                'title': 'Weak SSL Key Size',
                'description': 'Certificate uses 1024-bit key which is weak',
                'remediation': 'Use at least 2048-bit key'
            })
    
    def _display_results(self, hostname, cert_info, tls_info, cipher_info):
        """Display SSL check results"""
        print_section("SSL/TLS Results")
        
        # Certificate Info
        cprint(f"    {'Certificate Information:':<30}", Colors.BCYAN)
        cprint(f"      {'Subject:':<28} {cert_info.get('subject', {}).get('commonName', 'N/A')}", Colors.BWHITE)
        cprint(f"      {'Issuer:':<28} {cert_info.get('issuer', {}).get('organizationName', 'N/A')}", Colors.BWHITE)
        cprint(f"      {'Valid From:':<28} {cert_info.get('not_before', 'N/A')}", Colors.BWHITE)
        cprint(f"      {'Valid To:':<28} {cert_info.get('not_after', 'N/A')}", Colors.BWHITE)
        cprint(f"      {'Days Remaining:':<28} {cert_info.get('days_remaining', 'N/A')}", Colors.BGREEN if cert_info.get('days_remaining', 0) > 30 else Colors.BRED)
        cprint(f"      {'Key Size:':<28} {cert_info.get('key_size', 'N/A')}", Colors.BWHITE)
        
        # TLS Versions
        print()
        cprint(f"    {'TLS Versions:':<30}", Colors.BCYAN)
        for version, supported in tls_info.items():
            status = "Supported" if supported else "Not Supported"
            color = Colors.BRED if supported and version in ['SSLv2', 'SSLv3', 'TLSv1'] else Colors.BGREEN
            cprint(f"      {version:<28} {status}", color)
        
        # Cipher Suites
        if cipher_info:
            print()
            cprint(f"    {'Cipher Suite:':<30}", Colors.BCYAN)
            for cipher in cipher_info:
                cprint(f"      {cipher['name']}", Colors.BWHITE)
                cprint(f"        Protocol: {cipher['protocol']}, Bits: {cipher['bits']}", Colors.BBLACK)
        
        # Vulnerabilities
        if self.vulnerabilities:
            print()
            cprint(f"    {'Vulnerabilities Found:':<30}", Colors.BRED)
            for vuln in self.vulnerabilities:
                cprint(f"      [{vuln['severity']}] {vuln['title']}", Colors.BRED)
    
    def _save_results(self, hostname, cert_info, tls_info, cipher_info, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'hostname': hostname,
                    'certificate': cert_info,
                    'tls_versions': tls_info,
                    'cipher_suites': cipher_info,
                    'vulnerabilities': self.vulnerabilities
                }, f, indent=2, default=str)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
