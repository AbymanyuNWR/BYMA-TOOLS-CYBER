"""
BYMA TOOLS - Network Scanner
Tools untuk scanning jaringan dan menemukan host aktif
"""
import socket
import concurrent.futures
from pathlib import Path
import json
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_table, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database
from config.settings import COMMON_PORTS


class NetworkScanner:
    """Network discovery and scanning"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.live_hosts = []
    
    def scan(self, cidr, output=None):
        """Main scan function"""
        print_section(f"Network Scan: {cidr}")
        
        scan_id = self.db.create_scan("network_scan", cidr, "network")
        self.logger.scan_start("network_scan", cidr)
        
        try:
            # Generate IP range from CIDR
            ip_list = self._generate_ip_range(cidr)
            print_info(f"Scanning {len(ip_list)} hosts...")
            
            # Scan for live hosts
            self._scan_hosts(ip_list)
            
            # Scan common ports on live hosts
            print_info("Scanning common ports on live hosts...")
            self._scan_ports()
            
            # Save to database
            for host in self.live_hosts:
                self.db.add_network_host(
                    scan_id, host['ip'], host.get('mac'),
                    host.get('hostname'), host.get('vendor')
                )
            
            self.db.update_scan(scan_id, "completed", len(self.live_hosts))
            self.logger.scan_complete("network_scan", cidr, len(self.live_hosts))
            
            self._display_results()
            
            if output:
                self._save_results(cidr, output)
            
            return self.live_hosts
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("network_scan", cidr, str(e))
            print_error(f"Network scan failed: {e}")
            return []
    
    def _generate_ip_range(self, cidr):
        """Generate IP range from CIDR notation"""
        if '/' in cidr:
            ip, mask = cidr.split('/')
            mask = int(mask)
            
            # Calculate number of hosts
            num_hosts = 2 ** (32 - mask) - 2
            
            # Convert IP to integer
            ip_int = self._ip_to_int(ip)
            
            # Generate IP range
            ip_list = []
            for i in range(1, min(num_hosts + 1, 256)):  # Limit to 256 for /24
                ip_list.append(self._int_to_ip(ip_int + i))
            
            return ip_list
        else:
            # Single IP
            return [cidr]
    
    def _ip_to_int(self, ip):
        """Convert IP address to integer"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    def _int_to_ip(self, ip_int):
        """Convert integer to IP address"""
        return f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"
    
    def _scan_hosts(self, ip_list):
        """Scan for live hosts using TCP connect"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {
                executor.submit(self._check_host, ip): ip
                for ip in ip_list
            }
            
            with tqdm(total=len(futures), desc="    Scanning",
                     bar_format='    {l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]') as pbar:
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.live_hosts.append(result)
                    pbar.update(1)
    
    def _check_host(self, ip):
        """Check if host is alive"""
        try:
            # Try common ports
            for port in [80, 443, 22, 21, 25, 53, 110, 139, 445, 3389]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    # Get hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = None
                    
                    return {
                        'ip': ip,
                        'hostname': hostname,
                        'mac': None,
                        'vendor': None,
                        'open_ports': [port]
                    }
        except:
            pass
        
        return None
    
    def _scan_ports(self):
        """Scan common ports on live hosts"""
        for host in self.live_hosts:
            open_ports = []
            
            for port in COMMON_PORTS.keys():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host['ip'], port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append(port)
                except:
                    pass
            
            host['open_ports'] = open_ports
    
    def _display_results(self):
        """Display scan results"""
        print_section("Network Scan Results")
        
        if not self.live_hosts:
            print_warning("No live hosts found")
            return
        
        print_success(f"Found {len(self.live_hosts)} live hosts:")
        print()
        
        headers = ["IP Address", "Hostname", "Open Ports"]
        rows = []
        
        for host in self.live_hosts:
            ports = ', '.join(str(p) for p in host.get('open_ports', [])[:5])
            if len(host.get('open_ports', [])) > 5:
                ports += '...'
            
            rows.append([
                host['ip'],
                host.get('hostname', '-') or '-',
                ports or '-'
            ])
        
        print_table(headers, rows)
    
    def _save_results(self, cidr, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'network': cidr,
                    'live_hosts': self.live_hosts,
                    'total': len(self.live_hosts)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
