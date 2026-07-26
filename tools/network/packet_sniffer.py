"""
BYMA TOOLS - Packet Sniffer
Tools untuk sniffing dan analisis paket jaringan
"""
import sys
import json
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger


class PacketSniffer:
    """Network packet sniffer"""
    
    def __init__(self):
        self.logger = get_logger()
        self.packets = []
        self.stats = {
            'total': 0,
            'protocols': {},
            'src_ips': {},
            'dst_ips': {},
            'src_ports': {},
            'dst_ports': {}
        }
    
    def sniff(self, interface=None, count=100, output=None, filter_expr=None):
        """Main sniff function"""
        print_section("Packet Sniffer")
        
        print_warning("This tool requires root/administrator privileges!")
        print_warning("Use with caution and only on networks you own!")
        print()
        
        try:
            # Check if running as root
            if sys.platform != 'win32' and os.geteuid() != 0:
                print_error("This tool requires root privileges. Run with sudo.")
                return
            
            print_info(f"Interface: {interface or 'default'}")
            print_info(f"Packet count: {count}")
            if filter_expr:
                print_info(f"Filter: {filter_expr}")
            print()
            
            # Start sniffing
            print_info("Starting packet capture...")
            print_warning("Press Ctrl+C to stop")
            print()
            
            self._start_sniffing(interface, count, filter_expr)
            
            # Display results
            self._display_results()
            
            # Save to file if requested
            if output:
                self._save_results(output)
        
        except KeyboardInterrupt:
            print()
            print_info("Stopping packet capture...")
            self._display_results()
        
        except Exception as e:
            print_error(f"Packet sniffing failed: {e}")
            self.logger.error(f"Packet sniffing failed: {e}")
    
    def _start_sniffing(self, interface, count, filter_expr):
        """Start packet sniffing using Scapy"""
        try:
            from scapy.all import sniff as scapy_sniff, TCP, UDP, ICMP, IP
            
            def packet_callback(packet):
                self._process_packet(packet)
            
            # Build sniff arguments
            kwargs = {
                'count': count,
                'prn': packet_callback,
                'store': False
            }
            
            if interface:
                kwargs['iface'] = interface
            
            if filter_expr:
                kwargs['filter'] = filter_expr
            
            # Start sniffing
            scapy_sniff(**kwargs)
        
        except ImportError:
            print_error("Scapy is required for packet sniffing")
            print_info("Install with: pip install scapy")
        except Exception as e:
            print_error(f"Sniffing error: {e}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        self.stats['total'] += 1
        
        # Extract IP layer
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            # Update statistics
            self.stats['src_ips'][src_ip] = self.stats['src_ips'].get(src_ip, 0) + 1
            self.stats['dst_ips'][dst_ip] = self.stats['dst_ips'].get(dst_ip, 0) + 1
            
            # Protocol mapping
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, f'Other({proto})')
            self.stats['protocols'][proto_name] = self.stats['protocols'].get(proto_name, 0) + 1
            
            # Extract port information
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                self.stats['src_ports'][src_port] = self.stats['src_ports'].get(src_port, 0) + 1
                self.stats['dst_ports'][dst_port] = self.stats['dst_ports'].get(dst_port, 0) + 1
            
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                self.stats['src_ports'][src_port] = self.stats['src_ports'].get(src_port, 0) + 1
                self.stats['dst_ports'][dst_port] = self.stats['dst_ports'].get(dst_port, 0) + 1
            
            # Store packet info
            packet_info = {
                'time': datetime.now().strftime('%H:%M:%S'),
                'src': src_ip,
                'dst': dst_ip,
                'proto': proto_name,
                'size': len(packet)
            }
            
            if packet.haslayer(TCP):
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)
            
            self.packets.append(packet_info)
            
            # Print packet info
            cprint(f"    {packet_info['time']} {src_ip} -> {dst_ip} {proto_name} "
                   f"Len={len(packet)}", Colors.BWHITE)
    
    def _display_results(self):
        """Display sniffing results"""
        print_section("Packet Capture Results")
        
        if not self.packets:
            print_warning("No packets captured")
            return
        
        print_success(f"Captured {self.stats['total']} packets:")
        print()
        
        # Protocol distribution
        cprint(f"    {'Protocol Distribution:':<25}", Colors.BCYAN)
        for proto, count in sorted(self.stats['protocols'].items(), 
                                   key=lambda x: x[1], reverse=True):
            percent = count / self.stats['total'] * 100
            cprint(f"      {proto:<15} {count:>8} ({percent:.1f}%)", Colors.BWHITE)
        
        print()
        
        # Top source IPs
        cprint(f"    {'Top Source IPs:':<25}", Colors.BCYAN)
        for ip, count in sorted(self.stats['src_ips'].items(), 
                                key=lambda x: x[1], reverse=True)[:10]:
            cprint(f"      {ip:<20} {count:>8}", Colors.BWHITE)
        
        print()
        
        # Top destination IPs
        cprint(f"    {'Top Destination IPs:':<25}", Colors.BCYAN)
        for ip, count in sorted(self.stats['dst_ips'].items(), 
                                key=lambda x: x[1], reverse=True)[:10]:
            cprint(f"      {ip:<20} {count:>8}", Colors.BWHITE)
        
        print()
        
        # Top destination ports
        cprint(f"    {'Top Destination Ports:':<25}", Colors.BCYAN)
        for port, count in sorted(self.stats['dst_ports'].items(), 
                                  key=lambda x: x[1], reverse=True)[:10]:
            from config.settings import COMMON_PORTS
            service = COMMON_PORTS.get(port, 'Unknown')
            cprint(f"      {port}/{service:<15} {count:>8}", Colors.BWHITE)
    
    def _save_results(self, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'stats': self.stats,
                    'packets': self.packets[:1000]  # Limit to 1000 packets
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
