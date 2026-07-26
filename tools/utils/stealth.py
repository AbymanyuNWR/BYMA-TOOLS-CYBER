"""
BYMA TOOLS - Stealth Mode
Tools untuk scan dan attack dengan mode stealth/anti-detection
"""
import random
import time
import socket
import json
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_section, cprint, Colors
)
from core.logger import get_logger


class StealthMode:
    """Stealth scanning and attack mode"""
    
    def __init__(self):
        self.logger = get_logger()
        self.user_agents = self._load_user_agents()
    
    def _load_user_agents(self):
        """Load random user agents"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36'
        ]
    
    def get_random_headers(self):
        """Get random HTTP headers"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        # Randomly add some headers
        if random.random() > 0.5:
            headers['Referer'] = f"https://www.google.com/search?q={random.randint(1, 1000)}"
        
        if random.random() > 0.7:
            headers['X-Forwarded-For'] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        return headers
    
    def stealth_scan(self, target, ports='1-1024', delay=1, jitter=0.5):
        """Perform stealth port scan"""
        print_section(f"Stealth Port Scan: {target}")
        
        print_info(f"Target: {target}")
        print_info(f"Ports: {ports}")
        print_info(f"Delay: {delay}s +/- {jitter}s jitter")
        print()
        
        open_ports = []
        port_list = self._parse_ports(ports)
        
        print_info("Starting stealth scan...")
        
        for port in port_list:
            try:
                # Add random delay with jitter
                actual_delay = delay + random.uniform(-jitter, jitter)
                time.sleep(max(0.1, actual_delay))
                
                # Random SYN scan
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                # Random MSS value
                mss = random.choice([1460, 1360, 1260])
                
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    open_ports.append(port)
                    print_success(f"  Port {port}/tcp - OPEN")
                
                sock.close()
            
            except:
                pass
        
        print()
        print_success(f"Stealth scan completed. Found {len(open_ports)} open ports")
        
        return open_ports
    
    def _parse_ports(self, ports_str):
        """Parse port string"""
        port_list = []
        
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            elif part.isdigit():
                port_list.append(int(part))
        
        # Shuffle ports for stealth
        random.shuffle(port_list)
        
        return port_list
    
    def decoy_scan(self, target, decoys=None, ports='80,443,22'):
        """Perform scan with decoy IPs"""
        print_section(f"Decoy Scan: {target}")
        
        if not decoys:
            decoys = self._generate_decoys(5)
        
        print_info(f"Target: {target}")
        print_info(f"Decoys: {', '.join(decoys)}")
        print()
        
        try:
            from scapy.all import IP, TCP, send
            
            port_list = self._parse_ports(ports)
            
            for port in port_list:
                # Create decoy packets
                for decoy in decoys:
                    packet = IP(src=decoy, dst=target) / TCP(dport=port, flags='S')
                    send(packet, verbose=False)
                
                # Send real packet
                packet = IP(dst=target) / TCP(dport=port, flags='S')
                send(packet, verbose=False)
                
                print_info(f"  Sent packets to port {port} with {len(decoys)} decoys")
        
        except ImportError:
            print_error("Scapy is required for decoy scanning")
        except Exception as e:
            print_error(f"Decoy scan failed: {e}")
    
    def _generate_decoys(self, count):
        """Generate random decoy IPs"""
        decoys = []
        for _ in range(count):
            decoy = f"{random.randint(1, 254)}.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"
            decoys.append(decoy)
        return decoys
    
    def slow_scan(self, target, ports='1-100', min_delay=5, max_delay=30):
        """Perform very slow scan to avoid detection"""
        print_section(f"Slow Scan: {target}")
        
        print_info(f"Target: {target}")
        print_info(f"Ports: {ports}")
        print_info(f"Delay: {min_delay}-{max_delay}s between requests")
        print_warning("This scan will take a long time!")
        print()
        
        open_ports = []
        port_list = self._parse_ports(ports)
        
        for port in port_list:
            try:
                # Random delay
                delay = random.uniform(min_delay, max_delay)
                print_info(f"  Waiting {delay:.1f}s before testing port {port}...")
                time.sleep(delay)
                
                # Test port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    open_ports.append(port)
                    print_success(f"  Port {port}/tcp - OPEN")
                
                sock.close()
            
            except:
                pass
        
        return open_ports
    
    def fragment_packets(self, target, port):
        """Send fragmented packets"""
        print_section(f"Fragmented Packet Scan: {target}:{port}")
        
        try:
            from scapy.all import IP, TCP, send
            
            # Create fragmented packet
            packet = IP(dst=target, flags='MF') / TCP(dport=port, flags='S')
            send(packet, verbose=False)
            
            print_success("Fragmented packet sent")
        
        except ImportError:
            print_error("Scapy is required for packet fragmentation")
        except Exception as e:
            print_error(f"Failed to send fragmented packet: {e}")
    
    def randomize_source_port(self, target, port):
        """Randomize source port"""
        print_section(f"Random Source Port Scan: {target}:{port}")
        
        try:
            from scapy.all import IP, TCP, send
            
            # Random source port
            src_port = random.randint(1024, 65535)
            
            packet = IP(dst=target) / TCP(sport=src_port, dport=port, flags='S')
            send(packet, verbose=False)
            
            print_success(f"Packet sent from source port {src_port}")
        
        except ImportError:
            print_error("Scapy is required for random source port scanning")
        except Exception as e:
            print_error(f"Failed: {e}")
