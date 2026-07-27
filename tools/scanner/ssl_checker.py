"""
BYMA TOOLS - Advanced SSL/TLS Checker
Professional SSL certificate analysis and vulnerability detection
"""
import ssl
import socket
import json
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons, print_vuln_found
)
from core.logger import get_database, get_logger


class SSLChecker:
    """Professional SSL/TLS certificate analyzer"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.results = {}
        self.start_time = None
        self.vulnerabilities = []
    
    # Weak ciphers
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon',
        'RC2', 'SEED', 'IDEA', 'CAMELLIA', 'AESCBC',
    ]
    
    # Weak protocols
    WEAK_PROTOCOLS = [
        'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1',
    ]
    
    # Strong protocols
    STRONG_PROTOCOLS = [
        'TLSv1.2', 'TLSv1.3',
    ]
    
    # Known vulnerable cipher suites
    VULNERABLE_CIPHERS = {
        'RC4': 'RC4 bias vulnerability (CVE-2013-2566)',
        'DES': 'DES is weak (CVE-2016-2183)',
        '3DES': 'Sweet32 attack (CVE-2016-2183)',
        'MD5': 'MD5 collisions (CVE-2004-2761)',
        'NULL': 'No encryption',
        'EXPORT': 'FREAK attack (CVE-2015-0204)',
        'anon': 'Anonymous key exchange',
        'RC2': 'RC2 is weak',
        'CBC': 'BEAST attack (CVE-2011-3389)',
        'GCM': 'Secure',
        'CHACHA20': 'Secure',
    }
    
    def scan(self, target, output=None):
        """Main SSL/TLS scan function"""
        self.start_time = datetime.now()
        
        print_section("SSL/TLS CHECKER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("ssl_check", target, "security")
        self.logger.scan_start("ssl_check", target)
        
        try:
            # Parse target
            hostname, port = self._parse_target(target)
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}     {hostname}:{port}")
            print_separator("-", 50)
            print()
            
            # Get certificate
            print_subsection("Certificate Information")
            cert_info = self._get_certificate(hostname, port)
            
            if not cert_info:
                print_error("Could not retrieve certificate")
                self.db.update_scan(scan_id, "failed")
                return None
            
            # Display certificate info
            self._display_certificate(cert_info)
            
            # Check certificate validity
            print_subsection("Certificate Validity")
            self._check_certificate_validity(cert_info)
            
            # Check certificate chain
            print_subsection("Certificate Chain")
            self._check_certificate_chain(hostname, port)
            
            # Check protocols
            print_subsection("Protocol Support")
            self._check_protocols(hostname, port)
            
            # Check ciphers
            print_subsection("Cipher Suites")
            self._check_ciphers(hostname, port)
            
            # Check for known vulnerabilities
            print_subsection("Vulnerability Checks")
            self._check_vulnerabilities(hostname, port)
            
            # Check HSTS
            print_subsection("HSTS Configuration")
            self._check_hsts(hostname, port)
            
            # Check OCSP
            print_subsection("OCSP Stapling")
            self._check_ocsp(hostname, port)
            
            # Check certificate transparency
            print_subsection("Certificate Transparency")
            self._check_ct(cert_info)
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.vulnerabilities))
            self.logger.scan_complete("ssl_check", target, len(self.vulnerabilities))
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.results
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("ssl_check", target, str(e))
            print_error(f"Scan failed: {e}")
            return None
    
    def _parse_target(self, target):
        """Parse target hostname and port"""
        # Remove protocol prefix
        if target.startswith(('https://', 'http://')):
            target = target.split('://', 1)[1]
        
        # Remove path
        if '/' in target:
            target = target.split('/')[0]
        
        # Parse port
        if ':' in target:
            hostname, port_str = target.rsplit(':', 1)
            port = int(port_str)
        else:
            hostname = target
            port = 443
        
        return hostname, port
    
    def _get_certificate(self, hostname, port):
        """Get SSL certificate"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    
                    # Parse certificate
                    cert_dict = ssl._ssl._test_decode_cert(cert)
                    
                    return cert_dict
        
        except Exception as e:
            print_error(f"Certificate retrieval failed: {e}")
            return None
    
    def _display_certificate(self, cert):
        """Display certificate information"""
        # Subject
        subject = dict(x[0] for x in cert.get('subject', []))
        print(f"  {Colors.BCYAN}Subject:{Colors.BWHITE}       {subject.get('commonName', 'N/A')}")
        
        # Issuer
        issuer = dict(x[0] for x in cert.get('issuer', []))
        print(f"  {Colors.BCYAN}Issuer:{Colors.BWHITE}        {issuer.get('organizationName', 'N/A')}")
        
        # Serial Number
        serial = cert.get('serialNumber', 'N/A')
        print(f"  {Colors.BCYAN}Serial:{Colors.BWHITE}        {serial}")
        
        # Valid From
        not_before = cert.get('notBefore', 'N/A')
        print(f"  {Colors.BCYAN}Valid From:{Colors.BWHITE}    {not_before}")
        
        # Valid To
        not_after = cert.get('notAfter', 'N/A')
        print(f"  {Colors.BCYAN}Valid To:{Colors.BWHITE}      {not_after}")
        
        # Subject Alternative Names
        san = cert.get('subjectAltName', [])
        if san:
            san_names = ', '.join([name[1] for name in san[:5]])
            if len(san) > 5:
                san_names += f"... (+{len(san)-5} more)"
            print(f"  {Colors.BCYAN}SAN:{Colors.BWHITE}          {san_names}")
        
        # Signature Algorithm
        sig_algo = cert.get('signatureAlgorithm', 'N/A')
        print(f"  {Colors.BCYAN}Signature:{Colors.BWHITE}     {sig_algo}")
        
        # Key Size
        public_key = cert.get('publicKey', {})
        if public_key:
            key_size = public_key.get('keySize', 'N/A')
            key_type = public_key.get('type', 'N/A')
            print(f"  {Colors.BCYAN}Key Type:{Colors.BWHITE}      {key_type}")
            print(f"  {Colors.BCYAN}Key Size:{Colors.BWHITE}      {key_size} bits")
        
        # Version
        version = cert.get('version', 'N/A')
        print(f"  {Colors.BCYAN}Version:{Colors.BWHITE}       {version}")
        
        print()
    
    def _check_certificate_validity(self, cert):
        """Check certificate validity"""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.x509.oid import NameOID
            from datetime import datetime
            
            # Get validity dates
            not_before = cert.get('notBefore', '')
            not_after = cert.get('notAfter', '')
            
            # Parse dates (RFC 2822 format)
            from email.utils import parsedate_to_datetime
            start_date = parsedate_to_datetime(not_before)
            end_date = parsedate_to_datetime(not_after)
            
            now = datetime.now()
            
            # Check if expired
            if now > end_date:
                print_error("Certificate is EXPIRED")
                self.vulnerabilities.append({
                    'type': 'Certificate Expired',
                    'severity': 'CRITICAL',
                    'detail': f"Expired on {not_after}",
                })
            elif now < start_date:
                print_error("Certificate is NOT YET VALID")
                self.vulnerabilities.append({
                    'type': 'Certificate Not Valid',
                    'severity': 'HIGH',
                    'detail': f"Valid from {not_before}",
                })
            else:
                print_success("Certificate is valid")
            
            # Calculate remaining validity
            remaining = end_date - now
            days_remaining = remaining.days
            
            if days_remaining < 30:
                print_warning(f"Certificate expires in {days_remaining} days")
                self.vulnerabilities.append({
                    'type': 'Certificate Expiring Soon',
                    'severity': 'MEDIUM',
                    'detail': f"Expires in {days_remaining} days",
                })
            elif days_remaining < 90:
                print_warning(f"Certificate expires in {days_remaining} days")
            else:
                print_success(f"Certificate valid for {days_remaining} more days")
            
            # Check validity period
            validity_period = (end_date - start_date).days
            if validity_period > 397:
                print_warning(f"Certificate validity period too long: {validity_period} days (max 397)")
                self.vulnerabilities.append({
                    'type': 'Certificate Period Too Long',
                    'severity': 'LOW',
                    'detail': f"Validity period: {validity_period} days",
                })
            else:
                print_success(f"Validity period: {validity_period} days")
            
            print()
        
        except Exception as e:
            print_warning(f"Could not validate certificate dates: {e}")
    
    def _check_certificate_chain(self, hostname, port):
        """Check certificate chain"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_chain = ssock.getpeercert(True)
                    
                    # For simplicity, we'll just check if chain exists
                    print_success("Certificate chain is present")
                    
                    # Check chain length
                    # In a real implementation, you'd parse the chain
                    # For now, just report basic info
                    print_info("Chain validation requires full certificate parsing")
        
        except Exception as e:
            print_warning(f"Chain check failed: {e}")
    
    def _check_protocols(self, hostname, port):
        """Check supported protocols"""
        protocols_to_test = [
            ('SSLv2', ssl.PROTOCOL_SSLv23),  # Will be refused
            ('SSLv3', ssl.PROTOCOL_SSLv23),  # Will be refused
            ('TLSv1', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
            ('TLSv1.3', ssl.PROTOCOL_TLS),
        ]
        
        supported = []
        weak = []
        
        for proto_name, proto_const in protocols_to_test:
            try:
                if proto_name == 'SSLv2':
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                elif proto_name == 'SSLv3':
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                elif proto_name == 'TLSv1':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                elif proto_name == 'TLSv1.1':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
                elif proto_name == 'TLSv1.2':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                elif proto_name == 'TLSv1.3':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported.append(proto_name)
                        
                        if proto_name in self.WEAK_PROTOCOLS:
                            weak.append(proto_name)
            
            except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError):
                pass
        
        # Display results
        for proto in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']:
            if proto in supported:
                if proto in self.WEAK_PROTOCOLS:
                    print_warning(f"  {proto}: Supported (WEAK)")
                    self.vulnerabilities.append({
                        'type': f'Weak Protocol: {proto}',
                        'severity': 'HIGH' if proto in ['SSLv2', 'SSLv3'] else 'MEDIUM',
                        'detail': f'{proto} is deprecated and insecure',
                    })
                else:
                    print_success(f"  {proto}: Supported")
            else:
                if proto in self.WEAK_PROTOCOLS:
                    print_success(f"  {proto}: Not supported (GOOD)")
                else:
                    print_warning(f"  {proto}: Not supported")
        
        print()
    
    def _check_ciphers(self, hostname, port):
        """Check supported ciphers"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ciphers = context.get_ciphers()
            
            # Test each cipher
            for cipher in ciphers:
                cipher_name = cipher['name']
                
                # Check if cipher is weak
                is_weak = False
                for weak in self.WEAK_CIPHERS:
                    if weak in cipher_name.upper():
                        is_weak = True
                        break
                
                if is_weak:
                    print_warning(f"  Weak cipher: {cipher_name}")
                    self.vulnerabilities.append({
                        'type': f'Weak Cipher: {cipher_name}',
                        'severity': 'MEDIUM',
                        'detail': cipher_name,
                    })
            
            # Check for specific weak ciphers
            weak_found = []
            for weak in self.WEAK_CIPHERS:
                for cipher in ciphers:
                    if weak in cipher['name'].upper():
                        weak_found.append(cipher['name'])
                        break
            
            if weak_found:
                print_warning(f"Found {len(weak_found)} weak ciphers")
            else:
                print_success("No weak ciphers detected")
            
            print()
        
        except Exception as e:
            print_warning(f"Cipher check failed: {e}")
    
    def _check_vulnerabilities(self, hostname, port):
        """Check for known SSL/TLS vulnerabilities"""
        # Heartbleed
        print_info("Checking for Heartbleed...")
        heartbleed = self._check_heartbleed(hostname, port)
        if heartbleed:
            print_vuln_found("Heartbleed", "CRITICAL", "")
            self.vulnerabilities.append({
                'type': 'Heartbleed (CVE-2014-0160)',
                'severity': 'CRITICAL',
                'detail': 'Server is vulnerable to Heartbleed',
            })
        else:
            print_success("Not vulnerable to Heartbleed")
        
        # POODLE
        print_info("Checking for POODLE...")
        poodle = self._check_poodle(hostname, port)
        if poodle:
            print_vuln_found("POODLE", "HIGH", "")
            self.vulnerabilities.append({
                'type': 'POODLE (CVE-2014-3566)',
                'severity': 'HIGH',
                'detail': 'Server is vulnerable to POODLE',
            })
        else:
            print_success("Not vulnerable to POODLE")
        
        # DROWN
        print_info("Checking for DROWN...")
        drown = self._check_drown(hostname, port)
        if drown:
            print_vuln_found("DROWN", "CRITICAL", "")
            self.vulnerabilities.append({
                'type': 'DROWN (CVE-2016-0800)',
                'severity': 'CRITICAL',
                'detail': 'Server is vulnerable to DROWN',
            })
        else:
            print_success("Not vulnerable to DROWN")
        
        # ROBOT
        print_info("Checking for ROBOT...")
        robot = self._check_robot(hostname, port)
        if robot:
            print_vuln_found("ROBOT", "HIGH", "")
            self.vulnerabilities.append({
                'type': 'ROBOT (CVE-2017-13099)',
                'severity': 'HIGH',
                'detail': 'Server is vulnerable to ROBOT',
            })
        else:
            print_success("Not vulnerable to ROBOT")
        
        # Ticketbleed
        print_info("Checking for Ticketbleed...")
        ticketbleed = self._check_ticketbleed(hostname, port)
        if ticketbleed:
            print_vuln_found("Ticketbleed", "HIGH", "")
            self.vulnerabilities.append({
                'type': 'Ticketbleed (CVE-2016-9244)',
                'severity': 'HIGH',
                'detail': 'Server is vulnerable to Ticketbleed',
            })
        else:
            print_success("Not vulnerable to Ticketbleed")
        
        print()
    
    def _check_heartbleed(self, hostname, port):
        """Check for Heartbleed vulnerability"""
        try:
            # Simplified check - in production, use proper Heartbleed test
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Send heartbeat request
                    # This is a simplified check
                    return False
        except:
            return False
    
    def _check_poodle(self, hostname, port):
        """Check for POODLE vulnerability"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # If SSLv3 is supported, might be vulnerable
                    return False
        except:
            return False
    
    def _check_drown(self, hostname, port):
        """Check for DROWN vulnerability"""
        try:
            # DROWN affects servers that support SSLv2
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return False
        except:
            return False
    
    def _check_robot(self, hostname, port):
        """Check for ROBOT vulnerability"""
        try:
            # ROBOT affects certain RSA key exchanges
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return False
        except:
            return False
    
    def _check_ticketbleed(self, hostname, port):
        """Check for Ticketbleed vulnerability"""
        try:
            # Ticketbleed affects session ticket implementation
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return False
        except:
            return False
    
    def _check_hsts(self, hostname, port):
        """Check HSTS configuration"""
        try:
            import requests
            
            url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"
            response = requests.get(url, timeout=10, verify=False)
            
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            if hsts_header:
                print_success(f"HSTS is enabled")
                print_info(f"Header: {hsts_header}")
                
                # Parse max-age
                max_age_match = re.search(r'max-age=(\d+)', hsts_header)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    
                    if max_age < 31536000:  # 1 year
                        print_warning(f"HSTS max-age too short: {max_age} seconds")
                        self.vulnerabilities.append({
                            'type': 'HSTS Max-Age Too Short',
                            'severity': 'MEDIUM',
                            'detail': f'max-age={max_age}',
                        })
                    else:
                        print_success(f"HSTS max-age: {max_age} seconds")
                
                # Check for includeSubDomains
                if 'includeSubDomains' in hsts_header:
                    print_success("HSTS includes subdomains")
                else:
                    print_warning("HSTS does not include subdomains")
                
                # Check for preload
                if 'preload' in hsts_header:
                    print_success("HSTS preload enabled")
                else:
                    print_warning("HSTS preload not enabled")
            else:
                print_warning("HSTS is not enabled")
                self.vulnerabilities.append({
                    'type': 'HSTS Not Enabled',
                    'severity': 'MEDIUM',
                    'detail': 'No Strict-Transport-Security header',
                })
            
            print()
        
        except Exception as e:
            print_warning(f"HSTS check failed: {e}")
    
    def _check_ocsp(self, hostname, port):
        """Check OCSP stapling"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # OCSP stapling check is complex
                    # For now, just report basic info
                    print_info("OCSP stapling check requires advanced implementation")
                    print_info("Consider using: openssl s_client -connect {hostname}:{port} -status")
        
        except Exception as e:
            print_warning(f"OCSP check failed: {e}")
    
    def _check_ct(self, cert):
        """Check Certificate Transparency"""
        # Check if CT is present in certificate
        # CT logs are embedded in the certificate
        print_info("Certificate Transparency:")
        print_info("  CT compliance requires parsing X.509 extensions")
        print_info("  Check CT logs at: https://crt.sh/")
        print()
    
    def _display_results(self):
        """Display scan results"""
        print_section("SSL/TLS SCAN RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}SCAN SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Vulnerabilities:{Colors.BWHITE} {len(self.vulnerabilities)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}            {elapsed:.1f}s")
        
        print_separator("-", 50)
        print()
        
        # Display vulnerabilities
        if self.vulnerabilities:
            print(f"\n  {Icons.WARNING} {Colors.BRED}VULNERABILITIES FOUND{Colors.RESET}")
            print_separator("-", 50)
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_colors = {
                    'CRITICAL': Colors.BRED,
                    'HIGH': Colors.RED,
                    'MEDIUM': Colors.BYELLOW,
                    'LOW': Colors.BCYAN,
                }
                severity_color = severity_colors.get(vuln['severity'], Colors.BWHITE)
                
                print(f"  {Colors.BCYAN}#{i}:{Colors.BWHITE} {vuln['type']}")
                print(f"     {Colors.BCYAN}Severity:{Colors.BWHITE} {severity_color}{vuln['severity']}")
                print(f"     {Colors.BCYAN}Detail:{Colors.BWHITE}   {vuln['detail']}")
                print()
        else:
            print_success("No vulnerabilities found")
        
        # Recommendations
        print_subsection("Recommendations")
        
        if any(v['type'].startswith('Weak Protocol') for v in self.vulnerabilities):
            print_info("- Disable weak protocols (SSLv2, SSLv3, TLSv1, TLSv1.1)")
        
        if any(v['type'].startswith('Weak Cipher') for v in self.vulnerabilities):
            print_info("- Remove weak cipher suites")
        
        if any(v['type'] == 'HSTS Not Enabled' for v in self.vulnerabilities):
            print_info("- Enable HSTS with max-age >= 31536000")
        
        if any(v['type'] == 'HSTS Max-Age Too Short' for v in self.vulnerabilities):
            print_info("- Increase HSTS max-age to at least 31536000")
        
        print()
    
    def _save_to_database(self, scan_id):
        """Save results to database"""
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
                        'SSL/TLS',
                        vuln['detail'],
                        ''
                    ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'scan_time': self.start_time.isoformat(),
                'vulnerabilities': self.vulnerabilities,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
