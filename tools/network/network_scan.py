"""
BYMA TOOLS - Advanced Network Scanner
Professional network discovery and port scanning
"""
import socket
import struct
import json
import time
import concurrent.futures
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkScanner:
    """Professional network scanner with multiple techniques"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.discovered_hosts = []
        self.start_time = None
    
    # Common ports
    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MSSQL', 1434: 'MSSQL Browser', 1521: 'Oracle', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9090: 'HTTP-Alt',
        27017: 'MongoDB', 27018: 'MongoDB', 50000: 'SAP',
    }
    
    # Service banners
    SERVICE_BANNERS = {
        'SSH': ['SSH-', 'OpenSSH'],
        'FTP': ['220', 'FTP', 'vsftpd', 'ProFTPD', 'FileZilla'],
        'HTTP': ['HTTP/', 'Apache', 'nginx', 'IIS', 'Server'],
        'SMTP': ['220', 'SMTP', 'ESMTP'],
        'POP3': ['+OK', 'POP3'],
        'IMAP': ['* OK', 'IMAP'],
        'MySQL': ['5.', '8.', 'MySQL'],
        'PostgreSQL': ['PostgreSQL'],
        'Redis': ['REDIS'],
        'SMB': ['SMB', 'NetBIOS'],
        'RDP': ['RDP'],
        'VNC': ['RFB'],
    }
    
    def scan_network(self, target, ports=None, threads=100, timeout=1, output=None, scan_type='quick'):
        """Main network scan function"""
        self.start_time = datetime.now()
        
        print_section("NETWORK SCANNER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("network_scan", target, "recon")
        self.logger.scan_start("network_scan", target)
        
        try:
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {target}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Scan Type:{Colors.BWHITE}    {scan_type.upper()}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Threads:{Colors.BWHITE}      {threads}")
            print_separator("-", 50)
            print()
            
            # Determine scan method
            if scan_type == 'arp' and SCAPY_AVAILABLE:
                print_subsection("ARP Scan")
                self._arp_scan(target)
            elif scan_type == 'discovery':
                print_subsection("Host Discovery")
                self._ping_sweep(target, threads, timeout)
            else:
                # Port scan
                print_subsection("Port Scanning")
                self._port_scan(target, ports, threads, timeout)
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.discovered_hosts))
            self.logger.scan_complete("network_scan", target, len(self.discovered_hosts))
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.discovered_hosts
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("network_scan", target, str(e))
            print_error(f"Scan failed: {e}")
            return []
    
    def _arp_scan(self, network):
        """ARP scan for local network"""
        if not SCAPY_AVAILABLE:
            print_error("Scapy not available for ARP scan")
            return
        
        print_info(f"Sending ARP requests to {network}...")
        
        try:
            # Create ARP request
            arp_request = scapy.ARP(pdst=network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send and receive
            answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            for element in answered_list:
                host = {
                    'ip': element[1].psrc,
                    'mac': element[1].hwsrc,
                    'status': 'up',
                    'ports': [],
                }
                self.discovered_hosts.append(host)
                print_success(f"Found: {host['ip']} ({host['mac']})")
        
        except Exception as e:
            print_error(f"ARP scan failed: {e}")
    
    def _ping_sweep(self, network, threads, timeout):
        """Ping sweep to discover hosts"""
        # Parse network
        if '/' in network:
            base_ip, cidr = network.split('/')
            cidr = int(cidr)
        else:
            base_ip = network
            cidr = 24
        
        # Generate IP range
        import ipaddress
        try:
            network_obj = ipaddress.ip_network(f"{base_ip}/{cidr}", strict=False)
            ips = [str(ip) for ip in network_obj.hosts()]
        except:
            # Fallback: generate IPs manually
            parts = base_ip.split('.')
            ips = [f"{parts[0]}.{parts[1]}.{parts[2]}.{i}" for i in range(1, 255)]
        
        print_info(f"Scanning {len(ips)} hosts...")
        
        def ping_host(ip):
            try:
                # Try to connect to common ports
                for port in [80, 443, 22, 445, 139]:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        host = {
                            'ip': ip,
                            'mac': 'N/A',
                            'status': 'up',
                            'open_ports': [port],
                        }
                        self.discovered_hosts.append(host)
                        print_success(f"Host up: {ip} (port {port} open)")
                        return
            except:
                pass
        
        # Run with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in ips}
            concurrent.futures.wait(futures)
    
    def _port_scan(self, target, ports, threads, timeout):
        """Scan ports on target"""
        # Default to common ports
        if not ports:
            ports = list(self.COMMON_PORTS.keys())
        
        print_info(f"Scanning {len(ports)} ports on {target}...")
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    # Port is open
                    service = self.COMMON_PORTS.get(port, 'Unknown')
                    
                    # Grab banner
                    banner = self._grab_banner(sock)
                    
                    port_info = {
                        'port': port,
                        'state': 'open',
                        'service': service,
                        'banner': banner,
                    }
                    open_ports.append(port_info)
                    
                    print_success(f"Port {port}: OPEN ({service})")
                
                sock.close()
            
            except:
                pass
        
        # Run with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            concurrent.futures.wait(futures)
        
        # Store results
        if open_ports:
            host = {
                'ip': target,
                'mac': 'N/A',
                'status': 'up',
                'open_ports': open_ports,
            }
            self.discovered_hosts.append(host)
        
        print()
        print_info(f"Found {len(open_ports)} open ports")
    
    def _grab_banner(self, sock):
        """Grab service banner"""
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else ''
        except:
            return ''
    
    def _display_results(self):
        """Display scan results"""
        print_section("NETWORK SCAN RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}SCAN SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Hosts Found:{Colors.BWHITE}    {len(self.discovered_hosts)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}            {elapsed:.1f}s")
        
        print_separator("-", 50)
        print()
        
        # Display hosts
        if self.discovered_hosts:
            for i, host in enumerate(self.discovered_hosts, 1):
                print_subsection(f"Host #{i}")
                print(f"  {Colors.BCYAN}IP:{Colors.BWHITE}       {host['ip']}")
                print(f"  {Colors.BCYAN}MAC:{Colors.BWHITE}      {host['mac']}")
                print(f"  {Colors.BCYAN}Status:{Colors.BWHITE}    {host['status']}")
                
                # Display open ports
                open_ports = host.get('open_ports', [])
                if open_ports:
                    print(f"  {Colors.BCYAN}Open Ports:{Colors.BWHITE}")
                    
                    table_data = [["Port", "State", "Service", "Banner"]]
                    for port_info in open_ports:
                        if isinstance(port_info, dict):
                            table_data.append([
                                str(port_info.get('port', '')),
                                port_info.get('state', ''),
                                port_info.get('service', ''),
                                port_info.get('banner', '')[:40],
                            ])
                        else:
                            table_data.append([
                                str(port_info),
                                'open',
                                self.COMMON_PORTS.get(port_info, 'Unknown'),
                                '',
                            ])
                    
                    print_table(table_data)
                print()
        else:
            print_warning("No hosts found")
        
        print()
    
    def _save_to_database(self, scan_id):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                for host in self.discovered_hosts:
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, result_type, result_data)
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        'host',
                        json.dumps(host)
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
                'hosts': self.discovered_hosts,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
