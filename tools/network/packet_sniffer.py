"""
BYMA TOOLS - Advanced Packet Sniffer
Professional network packet capture and analysis
"""
import socket
import struct
import json
import textwrap
import sys
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
    from scapy.layers import http
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketSniffer:
    """Professional packet sniffer with protocol analysis"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.captured_packets = []
        self.start_time = None
        self.packet_count = 0
        self.protocol_stats = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'DNS': 0,
            'ARP': 0,
            'Other': 0,
        }
    
    # Protocol numbers
    PROTOCOLS = {
        1: 'ICMP',
        2: 'IGMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
        89: 'OSPF',
        132: 'SCTP',
    }
    
    # Common ports
    COMMON_PORTS = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 123: 'NTP',
        135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS',
        143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap',
        389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
        514: 'Syslog', 554: 'RTSP', 587: 'SMTP', 636: 'LDAPS',
        993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS',
        1433: 'MSSQL', 1434: 'MSSQL-Browser', 1521: 'Oracle',
        1723: 'PPTP', 1883: 'MQTT', 2049: 'NFS',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        5060: 'SIP', 5061: 'SIPS', 5222: 'XMPP',
        5900: 'VNC', 6379: 'Redis', 6443: 'Kubernetes',
        8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt',
        9090: 'HTTP-Alt', 9200: 'Elasticsearch', 9418: 'Git',
        27017: 'MongoDB', 50000: 'SAP',
    }
    
    def capture(self, interface=None, count=100, timeout=30, output=None, 
                filter_protocol=None, bpf_filter=None):
        """Main packet capture function"""
        self.start_time = datetime.now()
        
        print_section("PACKET SNIFFER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("packet_capture", "network", "recon")
        self.logger.scan_start("packet_capture", "network")
        
        try:
            print(f"  {Icons.INFO} {Colors.BCYAN}Interface:{Colors.BWHITE}    {interface or 'Default'}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Count:{Colors.BWHITE}        {count}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Timeout:{Colors.BWHITE}      {timeout}s")
            print(f"  {Icons.INFO} {Colors.BCYAN}Filter:{Colors.BWHITE}       {filter_protocol or 'None'}")
            if bpf_filter:
                print(f"  {Icons.INFO} {Colors.BCYAN}BPF Filter:{Colors.BWHITE}  {bpf_filter}")
            print_separator("-", 50)
            print()
            
            if SCAPY_AVAILABLE:
                self._scapy_capture(interface, count, timeout, bpf_filter)
            else:
                self._raw_capture(interface, count, timeout)
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", self.packet_count)
            self.logger.scan_complete("packet_capture", "network", self.packet_count)
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.captured_packets
        
        except KeyboardInterrupt:
            print_warning("\nCapture interrupted by user")
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("packet_capture", "network", str(e))
            print_error(f"Capture failed: {e}")
            return []
    
    def _scapy_capture(self, interface, count, timeout, bpf_filter):
        """Capture using scapy"""
        print_info("Starting packet capture with Scapy...")
        print_warning("Press Ctrl+C to stop capture")
        print()
        
        def packet_callback(packet):
            self.packet_count += 1
            packet_info = self._analyze_scapy_packet(packet)
            self.captured_packets.append(packet_info)
            
            # Display real-time
            self._display_packet_realtime(packet_info)
        
        try:
            if interface:
                scapy.sniff(
                    iface=interface,
                    prn=packet_callback,
                    count=count,
                    timeout=timeout,
                    filter=bpf_filter
                )
            else:
                scapy.sniff(
                    prn=packet_callback,
                    count=count,
                    timeout=timeout,
                    filter=bpf_filter
                )
        except Exception as e:
            print_error(f"Scapy capture failed: {e}")
    
    def _raw_capture(self, interface, count, timeout):
        """Raw socket capture (fallback)"""
        print_info("Starting raw socket capture...")
        print_warning("Note: Raw capture has limited protocol parsing")
        print_warning("Install scapy for better results: pip install scapy")
        print()
        
        try:
            # Create raw socket
            if sys.platform == 'win32':
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            else:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            sock.settimeout(timeout)
            
            start_time = datetime.now()
            
            while self.packet_count < count:
                if (datetime.now() - start_time).total_seconds() >= timeout:
                    break
                
                try:
                    data, addr = sock.recvfrom(65535)
                    self.packet_count += 1
                    
                    packet_info = self._analyze_raw_packet(data, addr)
                    self.captured_packets.append(packet_info)
                    
                    self._display_packet_realtime(packet_info)
                
                except socket.timeout:
                    break
        
        except PermissionError:
            print_error("Raw socket requires root/admin privileges")
        except Exception as e:
            print_error(f"Raw capture failed: {e}")
    
    def _analyze_scapy_packet(self, packet):
        """Analyze packet with scapy"""
        packet_info = {
            'number': self.packet_count,
            'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'src': '',
            'dst': '',
            'protocol': 'Other',
            'length': len(packet),
            'info': '',
            'raw': bytes(packet),
        }
        
        # IP layer
        if packet.haslayer(scapy.IP):
            packet_info['src'] = packet[scapy.IP].src
            packet_info['dst'] = packet[scapy.IP].dst
            packet_info['protocol'] = self.PROTOCOLS.get(packet[scapy.IP].proto, 'Other')
        
        # IPv6 layer
        elif packet.haslayer(scapy.IPv6):
            packet_info['src'] = packet[scapy.IPv6].src
            packet_info['dst'] = packet[scapy.IPv6].dst
        
        # TCP layer
        if packet.haslayer(scapy.TCP):
            packet_info['src_port'] = packet[scapy.TCP].sport
            packet_info['dst_port'] = packet[scapy.TCP].dport
            packet_info['protocol'] = 'TCP'
            
            # Identify service
            dst_port = packet[scapy.TCP].dport
            src_port = packet[scapy.TCP].sport
            
            if dst_port in self.COMMON_PORTS:
                packet_info['service'] = self.COMMON_PORTS[dst_port]
            elif src_port in self.COMMON_PORTS:
                packet_info['service'] = self.COMMON_PORTS[src_port]
            
            # TCP flags
            flags = packet[scapy.TCP].flags
            flag_str = []
            if flags & 0x02: flag_str.append('SYN')
            if flags & 0x10: flag_str.append('ACK')
            if flags & 0x01: flag_str.append('FIN')
            if flags & 0x04: flag_str.append('RST')
            if flags & 0x08: flag_str.append('PSH')
            if flags & 0x20: flag_str.append('URG')
            packet_info['flags'] = ','.join(flag_str)
        
        # UDP layer
        elif packet.haslayer(scapy.UDP):
            packet_info['src_port'] = packet[scapy.UDP].sport
            packet_info['dst_port'] = packet[scapy.UDP].dport
            packet_info['protocol'] = 'UDP'
            
            dst_port = packet[scapy.UDP].dport
            if dst_port in self.COMMON_PORTS:
                packet_info['service'] = self.COMMON_PORTS[dst_port]
        
        # DNS layer
        if packet.haslayer(scapy.DNS):
            packet_info['protocol'] = 'DNS'
            packet_info['service'] = 'DNS'
            
            dns = packet[scapy.DNS]
            if dns.qr == 0:  # Query
                packet_info['info'] = f"Query: {dns.qd.qname.decode()}"
            else:  # Response
                packet_info['info'] = f"Response: {dns.qd.qname.decode()}"
        
        # HTTP layer
        if packet.haslayer(http.HTTPRequest):
            packet_info['protocol'] = 'HTTP'
            packet_info['service'] = 'HTTP'
            
            http_layer = packet[http.HTTPRequest]
            packet_info['info'] = f"{http_layer.Method.decode()} {http_layer.Host.decode()}{http_layer.Path.decode()}"
        
        elif packet.haslayer(http.HTTPResponse):
            packet_info['protocol'] = 'HTTP'
            packet_info['service'] = 'HTTP'
            
            http_layer = packet[http.HTTPResponse]
            packet_info['info'] = f"HTTP/{http_layer.Version.decode()} {http_layer.StatusCode.decode()}"
        
        # ICMP layer
        elif packet.haslayer(scapy.ICMP):
            packet_info['protocol'] = 'ICMP'
            packet_info['service'] = 'ICMP'
            
            icmp_type = packet[scapy.ICMP].type
            if icmp_type == 8:
                packet_info['info'] = 'Echo Request'
            elif icmp_type == 0:
                packet_info['info'] = 'Echo Reply'
            else:
                packet_info['info'] = f'Type {icmp_type}'
        
        # ARP layer
        elif packet.haslayer(scapy.ARP):
            packet_info['protocol'] = 'ARP'
            packet_info['service'] = 'ARP'
            
            arp = packet[scapy.ARP]
            if arp.op == 1:
                packet_info['info'] = f"Request: Who has {arp.pdst}? Tell {arp.psrc}"
            else:
                packet_info['info'] = f"Reply: {arp.psrc} is at {arp.hwsrc}"
        
        # Update protocol stats
        proto = packet_info['protocol']
        if proto in self.protocol_stats:
            self.protocol_stats[proto] += 1
        else:
            self.protocol_stats['Other'] += 1
        
        return packet_info
    
    def _analyze_raw_packet(self, data, addr):
        """Analyze raw packet"""
        packet_info = {
            'number': self.packet_count,
            'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'src': addr[0] if addr else 'Unknown',
            'dst': 'Unknown',
            'protocol': 'Other',
            'length': len(data),
            'info': '',
            'raw': data,
        }
        
        try:
            # Parse Ethernet header (Linux)
            if len(data) >= 14:
                eth_header = struct.unpack('!6s6sH', data[:14])
                eth_protocol = socket.ntohs(eth_header[2])
                
                # IP protocol
                if eth_protocol == 8:
                    ip_header = struct.unpack('!BBHHHBBH4s4s', data[14:34])
                    protocol_num = ip_header[6]
                    packet_info['protocol'] = self.PROTOCOLS.get(protocol_num, 'Other')
                    
                    src_ip = socket.inet_ntoa(ip_header[8])
                    dst_ip = socket.inet_ntoa(ip_header[9])
                    packet_info['src'] = src_ip
                    packet_info['dst'] = dst_ip
                    
                    # TCP
                    if protocol_num == 6:
                        tcp_header = struct.unpack('!HHLLBBHHH', data[34:54])
                        src_port = tcp_header[0]
                        dst_port = tcp_header[1]
                        packet_info['src_port'] = src_port
                        packet_info['dst_port'] = dst_port
                        
                        if dst_port in self.COMMON_PORTS:
                            packet_info['service'] = self.COMMON_PORTS[dst_port]
                    
                    # UDP
                    elif protocol_num == 17:
                        udp_header = struct.unpack('!HHHH', data[34:42])
                        src_port = udp_header[0]
                        dst_port = udp_header[1]
                        packet_info['src_port'] = src_port
                        packet_info['dst_port'] = dst_port
                        
                        if dst_port in self.COMMON_PORTS:
                            packet_info['service'] = self.COMMON_PORTS[dst_port]
        
        except:
            pass
        
        # Update protocol stats
        proto = packet_info['protocol']
        if proto in self.protocol_stats:
            self.protocol_stats[proto] += 1
        else:
            self.protocol_stats['Other'] += 1
        
        return packet_info
    
    def _display_packet_realtime(self, packet_info):
        """Display packet in real-time"""
        proto = packet_info['protocol']
        proto_color = {
            'TCP': Colors.BCYAN,
            'UDP': Colors.BYELLOW,
            'HTTP': Colors.BGREEN,
            'DNS': Colors.BMAGENTA,
            'ICMP': Colors.BRED,
            'ARP': Colors.BWHITE,
        }.get(proto, Colors.BWHITE)
        
        src = packet_info.get('src', '?')
        dst = packet_info.get('dst', '?')
        length = packet_info['length']
        info = packet_info.get('info', '')
        service = packet_info.get('service', '')
        
        # Format: [time] proto src > dst length info
        time_str = packet_info['time']
        src_port = packet_info.get('src_port', '')
        dst_port = packet_info.get('dst_port', '')
        
        if src_port:
            src = f"{src}:{src_port}"
        if dst_port:
            dst = f"{dst}:{dst_port}"
        
        info_parts = []
        if service:
            info_parts.append(service)
        if info:
            info_parts.append(info[:50])
        if packet_info.get('flags'):
            info_parts.append(f"[{packet_info['flags']}]")
        
        info_str = ' '.join(info_parts)
        
        cprint(f"  {time_str}  {proto_color}{proto:<6}{Colors.RESET}  {src:<25} -> {dst:<25}  {length:>6}  {info_str}", Colors.BWHITE)
    
    def _display_results(self):
        """Display capture results"""
        print_section("PACKET CAPTURE RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}CAPTURE SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Total Packets:{Colors.BWHITE}    {self.packet_count}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Duration:{Colors.BWHITE}         {elapsed:.1f}s")
        print(f"  {Icons.INFO} {Colors.BCYAN}Packets/sec:{Colors.BWHITE}      {self.packet_count/max(elapsed, 1):.1f}")
        
        print_separator("-", 50)
        print()
        
        # Protocol statistics
        print_subsection("Protocol Statistics")
        
        table_data = [["Protocol", "Count", "Percentage"]]
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
                table_data.append([proto, str(count), f"{percentage:.1f}%"])
        
        print_table(table_data)
        print()
        
        # Top conversations
        if self.captured_packets:
            print_subsection("Top Conversations")
            
            conversations = {}
            for pkt in self.captured_packets:
                src = pkt.get('src', '?')
                dst = pkt.get('dst', '?')
                key = f"{src} <-> {dst}"
                conversations[key] = conversations.get(key, 0) + 1
            
            top_conversations = sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:10]
            
            table_data = [["Conversation", "Packets"]]
            for conv, count in top_conversations:
                table_data.append([conv[:50], str(count)])
            
            print_table(table_data)
            print()
        
        # Top ports
        if self.captured_packets:
            print_subsection("Top Destination Ports")
            
            port_counts = {}
            for pkt in self.captured_packets:
                dst_port = pkt.get('dst_port')
                if dst_port:
                    port_counts[dst_port] = port_counts.get(dst_port, 0) + 1
            
            top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            table_data = [["Port", "Service", "Count"]]
            for port, count in top_ports:
                service = self.COMMON_PORTS.get(port, 'Unknown')
                table_data.append([str(port), service, str(count)])
            
            print_table(table_data)
            print()
        
        print()
    
    def _save_to_database(self, scan_id):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                # Save summary
                cursor.execute("""
                    INSERT INTO scan_results 
                    (scan_id, result_type, result_data)
                    VALUES (?, ?, ?)
                """, (
                    scan_id,
                    'capture_summary',
                    json.dumps({
                        'total_packets': self.packet_count,
                        'protocol_stats': self.protocol_stats,
                    })
                ))
                
                # Save sample packets (first 100)
                for pkt in self.captured_packets[:100]:
                    # Remove raw data for database storage
                    pkt_clean = {k: v for k, v in pkt.items() if k != 'raw'}
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, result_type, result_data)
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        'packet',
                        json.dumps(pkt_clean)
                    ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'capture_time': self.start_time.isoformat(),
                'total_packets': self.packet_count,
                'protocol_stats': self.protocol_stats,
                'packets': [
                    {k: v for k, v in pkt.items() if k != 'raw'}
                    for pkt in self.captured_packets
                ],
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
