"""
BYMA TOOLS - Port Scanner
Tools untuk scanning port pada target
"""
import socket
import concurrent.futures
from datetime import datetime
from pathlib import Path
import json
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_table, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database
from config.settings import COMMON_PORTS, DEFAULT_THREADS, TOP_PORTS_100


class PortScanner:
    """Port scanning using TCP connect"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.open_ports = []
        self.target = None
    
    def scan(self, target, ports="1-1024", threads=50, output=None):
        """Main scan function"""
        print_section(f"Port Scan: {target}")
        
        self.target = target
        start_time = datetime.now()
        
        # Create scan record
        scan_id = self.db.create_scan("port_scan", target, "network")
        self.logger.scan_start("port_scan", target)
        
        try:
            # Parse port range
            port_list = self._parse_ports(ports)
            print_info(f"Scanning {len(port_list)} ports on {target}")
            print_info(f"Threads: {threads}")
            print()
            
            # Scan ports
            self._scan_ports(target, port_list, threads)
            
            # Sort results
            self.open_ports.sort(key=lambda x: x['port'])
            
            # Calculate elapsed time
            elapsed = (datetime.now() - start_time).total_seconds()
            
            # Save to database
            for port_info in self.open_ports:
                self.db.add_port(
                    scan_id, target, port_info['port'],
                    'open', port_info.get('service'),
                    port_info.get('version'), port_info.get('banner')
                )
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.open_ports))
            self.logger.scan_complete("port_scan", target, len(self.open_ports))
            
            # Display results
            self._display_results(elapsed)
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.open_ports
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("port_scan", target, str(e))
            print_error(f"Scan failed: {e}")
            return []
    
    def _parse_ports(self, ports_str):
        """Parse port string into list of ports"""
        port_list = []
        
        for part in ports_str.split(','):
            part = part.strip()
            
            if '-' in part:
                start, end = part.split('-')
                start, end = int(start), int(end)
                port_list.extend(range(start, end + 1))
            elif part.isdigit():
                port_list.append(int(part))
            elif part == 'top100':
                port_list.extend(TOP_PORTS_100)
            elif part == 'common':
                port_list.extend(COMMON_PORTS.keys())
        
        return sorted(set(port_list))
    
    def _scan_ports(self, target, port_list, threads):
        """Scan ports using thread pool"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_port, target, port): port
                for port in port_list
            }
            
            with tqdm(total=len(futures), desc="    Scanning", 
                     bar_format='    {l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]') as pbar:
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.open_ports.append(result)
                    pbar.update(1)
    
    def _check_port(self, target, port):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Port is open
                service = self._get_service_name(port)
                banner = self._grab_banner(sock, target, port)
                version = self._detect_version(banner)
                
                sock.close()
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'version': version,
                    'banner': banner
                }
            
            sock.close()
        except:
            pass
        
        return None
    
    def _grab_banner(self, sock, target, port):
        """Grab service banner"""
        try:
            # Send probe
            if port == 80 or port == 443:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                sock.send(b"EHLO test\r\n")
            elif port == 110:
                pass  # POP3 sends banner automatically
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:500] if banner else None
        except:
            return None
    
    def _detect_version(self, banner):
        """Detect service version from banner"""
        if not banner:
            return None
        
        banner_lower = banner.lower()
        
        # Common version detection
        if 'apache' in banner_lower:
            parts = banner.split('/')
            if len(parts) > 1:
                return parts[1].split()[0] if parts[1] else None
        elif 'nginx' in banner_lower:
            return banner.split('/')[-1].split()[0] if '/' in banner else None
        elif 'openssh' in banner_lower:
            return banner.split()[2] if len(banner.split()) > 2 else None
        elif 'proftpd' in banner_lower or 'vsftpd' in banner_lower:
            return banner.split()[1] if len(banner.split()) > 1 else None
        
        return banner[:50]
    
    def _get_service_name(self, port):
        """Get service name for port"""
        return COMMON_PORTS.get(port, 'Unknown')
    
    def _display_results(self, elapsed):
        """Display scan results"""
        print_section("Scan Results")
        
        if not self.open_ports:
            print_warning("No open ports found")
            return
        
        print_success(f"Found {len(self.open_ports)} open ports on {self.target}")
        print()
        
        headers = ["Port", "State", "Service", "Version"]
        rows = []
        
        for port_info in self.open_ports:
            rows.append([
                f"{port_info['port']}/tcp",
                "open",
                port_info.get('service', 'Unknown'),
                port_info.get('version', '-') or '-'
            ])
        
        print_table(headers, rows)
        
        print()
        print_info(f"Scan completed in {elapsed:.2f} seconds")
        
        # Show banners if available
        banners = [p for p in self.open_ports if p.get('banner')]
        if banners:
            print_section("Service Banners")
            for port_info in banners:
                cprint(f"    {port_info['port']}/{port_info.get('service', '?')}:",
                       Colors.BCYAN)
                cprint(f"    {port_info['banner'][:100]}", Colors.BWHITE)
    
    def _save_results(self, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'target': self.target,
                    'open_ports': self.open_ports,
                    'total': len(self.open_ports)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")


class QuickScan:
    """Quick port scan for common ports"""
    
    def __init__(self):
        self.scanner = PortScanner()
    
    def scan(self, target, output=None):
        """Quick scan of common ports"""
        print_info(f"Quick scanning {target}...")
        return self.scanner.scan(target, ports="21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017", threads=20, output=output)


class FullScan:
    """Full port scan 1-65535"""
    
    def __init__(self):
        self.scanner = PortScanner()
    
    def scan(self, target, output=None):
        """Full scan of all ports"""
        print_warning(f"Full scanning {target} (1-65535) - This may take a while!")
        return self.scanner.scan(target, ports="1-65535", threads=200, output=output)
