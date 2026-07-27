"""
BYMA TOOLS - Advanced Port Scanner
Professional port scanner with multiple scan types and service detection
"""
import socket
import ssl
import struct
import concurrent.futures
import json
import time
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_logger
from core.database import get_database


class PortScanner:
    """Professional port scanner with service detection and banner grabbing"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.open_ports = {}
        self.target = None
        self.start_time = None
    
    # Common ports with services
    COMMON_PORTS = {
        21: ('FTP', 'File Transfer Protocol'),
        22: ('SSH', 'Secure Shell'),
        23: ('Telnet', 'Telnet Protocol'),
        25: ('SMTP', 'Simple Mail Transfer Protocol'),
        53: ('DNS', 'Domain Name System'),
        80: ('HTTP', 'Hypertext Transfer Protocol'),
        110: ('POP3', 'Post Office Protocol v3'),
        111: ('RPCBind', 'RPC Portmapper'),
        135: ('MSRPC', 'Microsoft RPC'),
        139: ('NetBIOS', 'NetBIOS Session Service'),
        143: ('IMAP', 'Internet Message Access Protocol'),
        443: ('HTTPS', 'HTTP Secure'),
        445: ('SMB', 'Server Message Block'),
        993: ('IMAPS', 'IMAP over SSL'),
        995: ('POP3S', 'POP3 over SSL'),
        1433: ('MSSQL', 'Microsoft SQL Server'),
        1434: ('MSSQL-UDP', 'Microsoft SQL Monitor'),
        1521: ('Oracle', 'Oracle Database'),
        1723: ('PPTP', 'Point-to-Point Tunneling Protocol'),
        2049: ('NFS', 'Network File System'),
        3306: ('MySQL', 'MySQL Database'),
        3389: ('RDP', 'Remote Desktop Protocol'),
        5432: ('PostgreSQL', 'PostgreSQL Database'),
        5900: ('VNC', 'Virtual Network Computing'),
        6379: ('Redis', 'Redis Database'),
        8080: ('HTTP-Proxy', 'HTTP Proxy/Alt HTTP'),
        8443: ('HTTPS-Alt', 'HTTPS Alternative'),
        27017: ('MongoDB', 'MongoDB Database'),
        50000: ('SAP', 'SAP Application Server'),
    }
    
    # Top 1000 common ports
    TOP_1000 = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
        113, 119, 135, 139, 143, 144, 179, 199, 254, 255, 280, 311, 389, 427,
        443, 444, 445, 464, 465, 500, 512, 513, 514, 515, 524, 541, 548, 554,
        563, 587, 625, 631, 636, 646, 787, 808, 873, 902, 990, 993, 995, 1000,
        1022, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1080, 1099, 1110, 1433,
        1434, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2100, 2103, 2121,
        2199, 2717, 2869, 2967, 3000, 3001, 3128, 3268, 3306, 3389, 3986, 4000,
        4001, 4443, 4444, 4899, 5000, 5001, 5003, 5009, 5050, 5051, 5060, 5101,
        5120, 5190, 5357, 5432, 5555, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
        7070, 7100, 7443, 7938, 8000, 8001, 8008, 8009, 8010, 8080, 8081, 8082,
        8083, 8084, 8085, 8088, 8090, 8443, 8888, 9000, 9001, 9090, 9099, 9100,
        9200, 9443, 9999, 10000, 10443, 27017, 27018, 28017, 32768, 32769, 32770,
        49152, 49153, 49154, 49155, 49156, 49157
    ]
    
    def scan(self, target, ports=None, scan_type='connect', threads=100, 
             timeout=1, output=None, grab_banner=True, detect_service=True):
        """Main scan function"""
        self.target = target
        self.start_time = datetime.now()
        
        # Determine ports to scan
        if ports:
            port_list = self._parse_ports(ports)
        else:
            port_list = self.TOP_1000
        
        print_section(f"PORT SCANNING: {target}")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("port_scan", target, "recon")
        self.logger.scan_start("port_scan", target)
        
        # Display scan info
        print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {target}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Ports:{Colors.BWHITE}        {len(port_list)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Scan Type:{Colors.BWHITE}    {scan_type.upper()}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Threads:{Colors.BWHITE}      {threads}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Timeout:{Colors.BWHITE}      {timeout}s")
        print_separator("-", 50)
        print()
        
        try:
            # Resolve target IP
            target_ip = self._resolve_target(target)
            print_info(f"Resolved to: {target_ip}")
            print()
            
            # Perform scan based on type
            if scan_type == 'connect':
                self._connect_scan(target, port_list, threads, timeout)
            elif scan_type == 'quick':
                self._quick_scan(target, port_list, threads, timeout)
            elif scan_type == 'full':
                self._full_scan(target, port_list, threads, timeout)
            else:
                self._connect_scan(target, port_list, threads, timeout)
            
            # Grab banners for open ports
            if grab_banner and self.open_ports:
                print_subsection("Banner Grabbing")
                self._grab_banners(target, threads)
            
            # Detect services
            if detect_service and self.open_ports:
                print_subsection("Service Detection")
                self._detect_services(target)
            
            # Save to database
            for port, info in self.open_ports.items():
                self.db.add_port(scan_id, target, port, 'open', 
                               info.get('service', 'unknown'), 
                               info.get('version', ''),
                               info.get('banner', ''))
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.open_ports))
            self.logger.scan_complete("port_scan", target, len(self.open_ports))
            
            # Display results
            self._display_results(target)
            
            # Save to file if requested
            if output:
                self._save_results(output, target)
            
            return self.open_ports
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("port_scan", target, str(e))
            print_error(f"Scan failed: {e}")
            return {}
    
    def _parse_ports(self, port_string):
        """Parse port string into list of ports"""
        ports = set()
        
        for part in str(port_string).split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-', 1)
                start, end = int(start), int(end)
                ports.update(range(start, end + 1))
            elif part.isdigit():
                ports.add(int(part))
        
        return sorted(list(ports))
    
    def _resolve_target(self, target):
        """Resolve target to IP"""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Could not resolve target: {target}")
    
    def _connect_scan(self, target, ports, threads, timeout):
        """TCP Connect scan"""
        print_info(f"Starting TCP Connect scan on {len(ports)} ports")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    return port, True
            except:
                pass
            return port, False
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            with tqdm(total=len(futures), desc="    Scanning", ncols=70,
                     bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:
                for future in concurrent.futures.as_completed(futures):
                    port, is_open = future.result()
                    if is_open:
                        self.open_ports[port] = {
                            'state': 'open',
                            'service': self.COMMON_PORTS.get(port, ('unknown', ''))[0],
                            'banner': '',
                            'version': ''
                        }
                    pbar.update(1)
        
        print_success(f"Found {len(self.open_ports)} open ports")
    
    def _quick_scan(self, target, ports, threads, timeout):
        """Quick scan of common ports"""
        # Filter to only common ports
        common_ports = [p for p in ports if p in self.COMMON_PORTS or p <= 1024]
        
        print_info(f"Quick scan on {len(common_ports)} common ports")
        
        self._connect_scan(target, common_ports, threads, timeout)
    
    def _full_scan(self, target, ports, threads, timeout):
        """Full scan with additional checks"""
        print_info(f"Full scan on {len(ports)} ports")
        
        # First pass: quick connect scan
        self._connect_scan(target, ports, min(threads, 50), timeout)
        
        # Second pass: detailed check on open ports
        if self.open_ports:
            print_info("Performing detailed scan on open ports...")
            
            def detailed_scan(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout * 2)
                    
                    # Try to connect
                    if sock.connect_ex((target, port)) == 0:
                        # Try to get banner
                        banner = ''
                        try:
                            sock.settimeout(1)
                            sock.send(b'HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n' % target.encode())
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        except:
                            pass
                        
                        sock.close()
                        return port, True, banner
                except:
                    pass
                return port, False, ''
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(detailed_scan, port): port for port in list(self.open_ports.keys())}
                
                for future in concurrent.futures.as_completed(futures):
                    port, is_open, banner = future.result()
                    if is_open and banner:
                        self.open_ports[port]['banner'] = banner
    
    def _grab_banners(self, target, threads):
        """Grab banners from open ports"""
        print_info("Grabbing banners from open ports")
        
        def grab_banner(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, port))
                
                banner = ''
                
                # Try to receive banner
                try:
                    # Send probe based on port
                    if port == 80 or port == 8080:
                        sock.send(b'HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n' % target.encode())
                    elif port == 443 or port == 8443:
                        # HTTPS - just grab certificate info
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            cert = ssock.getpeercert()
                            if cert:
                                banner = f"SSL Certificate: {cert.get('subject', ((('', ''),),))[0][0][1]}"
                    elif port == 21:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    elif port == 22:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    elif port == 25:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    elif port == 110:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    else:
                        # Generic banner grab
                        sock.send(b'\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                sock.close()
                return port, banner
            except:
                return port, ''
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(grab_banner, port): port for port in self.open_ports.keys()}
            
            for future in concurrent.futures.as_completed(futures):
                port, banner = future.result()
                if banner:
                    self.open_ports[port]['banner'] = banner[:200]  # Limit banner length
        
        print_success("Banner grabbing completed")
    
    def _detect_services(self, target):
        """Detect services running on open ports"""
        print_info("Detecting services on open ports")
        
        for port in list(self.open_ports.keys()):
            info = self.open_ports[port]
            
            # Get service info from database
            if port in self.COMMON_PORTS:
                info['service'] = self.COMMON_PORTS[port][0]
                info['description'] = self.COMMON_PORTS[port][1]
            
            # Try to get version from banner
            banner = info.get('banner', '')
            if banner:
                # Extract version information
                import re
                version_patterns = [
                    r'Apache/(\d+\.\d+\.\d+)',
                    r'nginx/(\d+\.\d+\.\d+)',
                    r'OpenSSH[_ ](\d+\.\d+)',
                    r'ProFTPD (\d+\.\d+)',
                    r'vsFTPd (\d+\.\d+)',
                    r'Microsoft FTP Service',
                    r'Microsoft-IIS/(\d+\.\d+)',
                    r'Server: ([^\r\n]+)',
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        info['version'] = match.group(1) if match.lastindex else match.group(0)
                        break
        
        print_success("Service detection completed")
    
    def _display_results(self, target):
        """Display comprehensive results"""
        print_section("SCAN RESULTS")
        
        if not self.open_ports:
            print_warning("No open ports found")
            return
        
        # Summary
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\n  {Icons.SUCCESS} {Colors.BGREEN}SCAN COMPLETE{Colors.RESET}")
        print_separator("-", 50)
        
        # Statistics
        print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {target}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Open Ports:{Colors.BWHITE}   {len(self.open_ports)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}         {elapsed:.1f}s")
        
        # Service breakdown
        services = {}
        for port, info in self.open_ports.items():
            service = info.get('service', 'unknown')
            services[service] = services.get(service, 0) + 1
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Services:{Colors.BWHITE}")
        for service, count in sorted(services.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"      {Colors.BYELLOW}{service}: {Colors.BWHITE}{count}")
        
        print_separator("-", 50)
        print()
        
        # Table of results
        headers = ["Port", "State", "Service", "Version", "Banner"]
        rows = []
        
        for port in sorted(self.open_ports.keys()):
            info = self.open_ports[port]
            rows.append([
                str(port),
                info.get('state', 'open'),
                info.get('service', '-')[:15],
                info.get('version', '-')[:15],
                info.get('banner', '-')[:30]
            ])
        
        print_table(headers, rows)
        
        # Vulnerability warnings
        vuln_ports = self._check_vulnerabilities()
        if vuln_ports:
            print()
            print_subsection("Security Warnings")
            for port, warning in vuln_ports:
                cprint(f"  {Colors.BRED}[!] Port {port}: {warning}", Colors.BRED)
    
    def _check_vulnerabilities(self):
        """Check for known vulnerable services"""
        warnings = []
        
        vulnerable_services = {
            21: ("FTP", "FTP may transmit credentials in cleartext"),
            23: ("Telnet", "Telnet transmits all data in cleartext"),
            25: ("SMTP", "SMTP may be used for email spoofing"),
            135: ("MSRPC", "Microsoft RPC - often targeted by malware"),
            139: ("NetBIOS", "NetBIOS - potential information disclosure"),
            445: ("SMB", "SMB - vulnerable to EternalBlue and other attacks"),
            1433: ("MSSQL", "MSSQL - often targeted for database attacks"),
            3306: ("MySQL", "MySQL - ensure strong authentication"),
            3389: ("RDP", "RDP - vulnerable to brute force and BlueKeep"),
            5900: ("VNC", "VNC - ensure encrypted connection"),
            6379: ("Redis", "Redis - often unauthenticated by default"),
            27017: ("MongoDB", "MongoDB - often unauthenticated by default"),
        }
        
        for port in self.open_ports.keys():
            if port in vulnerable_services:
                service, warning = vulnerable_services[port]
                warnings.append((port, f"{service} - {warning}"))
        
        return warnings
    
    def _save_results(self, output_file, target):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            elapsed = (datetime.now() - self.start_time).total_seconds()
            
            results = {
                'target': target,
                'scan_time': self.start_time.isoformat(),
                'elapsed_seconds': elapsed,
                'total_open': len(self.open_ports),
                'ports': {}
            }
            
            for port, info in sorted(self.open_ports.items()):
                results['ports'][str(port)] = {
                    'state': info.get('state'),
                    'service': info.get('service'),
                    'version': info.get('version'),
                    'banner': info.get('banner'),
                    'description': info.get('description', '')
                }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
    
    def scan_ports(self, target, ports="1-1024", output=None):
        """Compatibility method for interactive mode"""
        return self.scan(target, ports=ports, output=output)
