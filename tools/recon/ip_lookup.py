"""
BYMA TOOLS - Advanced IP Lookup
Professional IP geolocation with ASN, threat intel, and blacklist check
"""
import requests
import socket
import json
import concurrent.futures
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_logger
from core.database import get_database


class IPLookup:
    """Professional IP geolocation lookup with threat intelligence"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.ip_info = {}
    
    def lookup(self, ip_address, output=None):
        """Main IP lookup function"""
        print_section(f"IP LOOKUP: {ip_address}")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("ip_lookup", ip_address, "recon")
        self.logger.scan_start("ip_lookup", ip_address)
        
        try:
            # Validate IP
            if not self._validate_ip(ip_address):
                # Try to resolve hostname
                try:
                    ip_address = socket.gethostbyname(ip_address)
                    print_info(f"Resolved to: {ip_address}")
                except:
                    print_error("Invalid IP address or hostname")
                    return None
            
            # Get basic IP info
            self._get_ip_info(ip_address)
            
            # Get ASN information
            self._get_asn_info(ip_address)
            
            # Check blacklists
            self._check_blacklists(ip_address)
            
            # Get reverse DNS
            self._get_reverse_dns(ip_address)
            
            # Display results
            self._display_results(ip_address)
            
            # Save to database
            self._save_to_database(ip_address)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", 1)
            self.logger.scan_complete("ip_lookup", ip_address, 1)
            
            # Save to file if requested
            if output:
                self._save_results(output, ip_address)
            
            return self.ip_info
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("ip_lookup", ip_address, str(e))
            print_error(f"IP lookup failed: {e}")
            return None
    
    def _validate_ip(self, ip):
        """Validate IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def _get_ip_info(self, ip):
        """Get IP geolocation information"""
        print_info("Getting IP information...")
        
        # Try multiple IP info services
        services = [
            f"https://ipinfo.io/{ip}/json",
            f"http://ip-api.com/json/{ip}",
            f"https://ipapi.co/{ip}/json/",
        ]
        
        for url in services:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Parse based on service
                    if 'ipinfo.io' in url:
                        self.ip_info = {
                            'ip': data.get('ip', ip),
                            'hostname': data.get('hostname', '-'),
                            'city': data.get('city', '-'),
                            'region': data.get('region', '-'),
                            'country': data.get('country', '-'),
                            'country_code': data.get('country', '-'),
                            'location': data.get('loc', '-'),
                            'org': data.get('org', '-'),
                            'postal': data.get('postal', '-'),
                            'timezone': data.get('timezone', '-'),
                        }
                    elif 'ip-api.com' in url:
                        self.ip_info = {
                            'ip': data.get('query', ip),
                            'hostname': data.get('isp', '-'),
                            'city': data.get('city', '-'),
                            'region': data.get('regionName', '-'),
                            'country': data.get('country', '-'),
                            'country_code': data.get('countryCode', '-'),
                            'location': f"{data.get('lat', '-')},{data.get('lon', '-')}",
                            'org': data.get('org', '-'),
                            'isp': data.get('isp', '-'),
                            'as': data.get('as', '-'),
                            'asname': data.get('asname', '-'),
                            'reverse': data.get('reverse', '-'),
                            'mobile': data.get('mobile', False),
                            'proxy': data.get('proxy', False),
                            'hosting': data.get('hosting', False),
                        }
                    elif 'ipapi.co' in url:
                        self.ip_info = {
                            'ip': data.get('ip', ip),
                            'city': data.get('city', '-'),
                            'region': data.get('region', '-'),
                            'country': data.get('country_name', '-'),
                            'country_code': data.get('country_code', '-'),
                            'location': f"{data.get('latitude', '-')},{data.get('longitude', '-')}",
                            'org': data.get('org', '-'),
                            'postal': data.get('postal', '-'),
                            'timezone': data.get('timezone', '-'),
                            'asn': data.get('asn', '-'),
                        }
                    
                    print_success(f"IP information retrieved from {url.split('/')[2]}")
                    break
            except Exception:
                continue
        
        if not self.ip_info:
            print_warning("Could not retrieve IP information")
            self.ip_info = {'ip': ip}
    
    def _get_asn_info(self, ip):
        """Get ASN information"""
        print_info("Getting ASN information...")
        
        try:
            # Try to get ASN from different sources
            services = [
                f"https://api.iptoasn.com/v1/as/ip/{ip}",
                f"https://stat.ripe.net/data/whois/data.json?resource={ip}",
            ]
            
            for url in services:
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        
                        if 'iptoasn' in url:
                            self.ip_info['asn'] = data.get('as_number', '-')
                            self.ip_info['as_description'] = data.get('as_description', '-')
                            self.ip_info['as_country'] = data.get('as_country_code', '-')
                            self.ip_info['as_domain'] = data.get('as_domain', '-')
                        elif 'ripe' in url:
                            # Parse RIPE data
                            if 'data' in data and 'records' in data['data']:
                                records = data['data']['records']
                                for record in records:
                                    for item in record:
                                        if 'key' in item and 'value' in item:
                                            key = item['key']
                                            value = item['value']
                                            if 'netname' in key.lower():
                                                self.ip_info['netname'] = value
                                            elif 'descr' in key.lower():
                                                self.ip_info['description'] = value
                                            elif 'country' in key.lower():
                                                self.ip_info['country'] = value
                        
                        print_success(f"ASN information retrieved")
                        break
                except Exception:
                    continue
        except Exception as e:
            print_warning(f"Could not get ASN info: {e}")
    
    def _check_blacklists(self, ip):
        """Check IP against blacklists"""
        print_info("Checking blacklists...")
        
        blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'b.barracudacentral.org',
            'dnsbl-1.unicode.net',
            'dnsbl-2.unicode.net',
            'dnsbl-3.unicode.net',
            'cbl.abuseat.org',
            'dnsbl.sorbs.net',
            'spam.dnsbl.sorbs.net',
            'dul.dnsbl.sorbs.net',
            'dnsbl-1.uceprotect.net',
            'dnsbl-2.uceprotect.net',
            'dnsbl-3.uceprotect.net',
            'dyna.spamrats.com',
            'noptr.spamrats.com',
            'spam.spamrats.com',
            'all.s5h.net',
            'rbl.intl.net',
        ]
        
        def check_blacklist(bl):
            try:
                # Reverse IP
                reversed_ip = '.'.join(reversed(ip.split('.')))
                query = f"{reversed_ip}.{bl}"
                
                # Check if IP is listed
                socket.gethostbyname(query)
                return bl, True
            except socket.gaierror:
                return bl, False
            except:
                return bl, False
        
        listed_blacklists = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_blacklist, bl): bl for bl in blacklists}
            
            for future in concurrent.futures.as_completed(futures):
                bl, is_listed = future.result()
                if is_listed:
                    listed_blacklists.append(bl)
        
        self.ip_info['blacklists'] = {
            'checked': len(blacklists),
            'listed': listed_blacklists,
            'count': len(listed_blacklists)
        }
        
        if listed_blacklists:
            print_warning(f"IP is listed on {len(listed_blacklists)} blacklists!")
        else:
            print_success("IP is not listed on any blacklists")
    
    def _get_reverse_dns(self, ip):
        """Get reverse DNS for IP"""
        print_info("Getting reverse DNS...")
        
        try:
            hostname = socket.gethostbyaddr(ip)
            if hostname:
                self.ip_info['reverse_dns'] = hostname[0]
                self.ip_info['reverse_aliases'] = hostname[1]
                print_success(f"Reverse DNS: {hostname[0]}")
        except socket.herror:
            print_info("No reverse DNS found")
        except Exception as e:
            print_warning(f"Reverse DNS lookup failed: {e}")
    
    def _display_results(self, ip):
        """Display IP lookup results"""
        print_section("IP INFORMATION")
        
        # Basic info
        print(f"  {Icons.TARGET} {Colors.BCYAN}IP Address:{Colors.BWHITE}    {ip}")
        
        if self.ip_info.get('hostname'):
            print(f"  {Icons.INFO} {Colors.BCYAN}Hostname:{Colors.BWHITE}     {self.ip_info['hostname']}")
        
        if self.ip_info.get('reverse_dns'):
            print(f"  {Icons.INFO} {Colors.BCYAN}Reverse DNS:{Colors.BWHITE}  {self.ip_info['reverse_dns']}")
        
        print_separator("-", 50)
        
        # Location
        print_subsection("Location Information")
        location_parts = []
        if self.ip_info.get('city') and self.ip_info['city'] != '-':
            location_parts.append(self.ip_info['city'])
        if self.ip_info.get('region') and self.ip_info['region'] != '-':
            location_parts.append(self.ip_info['region'])
        if self.ip_info.get('country') and self.ip_info['country'] != '-':
            location_parts.append(self.ip_info['country'])
        
        if location_parts:
            print(f"  {Colors.BCYAN}Location:{Colors.BWHITE}      {', '.join(location_parts)}")
        
        if self.ip_info.get('location') and self.ip_info['location'] != '-':
            print(f"  {Colors.BCYAN}Coordinates:{Colors.BWHITE}   {self.ip_info['location']}")
        
        if self.ip_info.get('timezone') and self.ip_info['timezone'] != '-':
            print(f"  {Colors.BCYAN}Timezone:{Colors.BWHITE}      {self.ip_info['timezone']}")
        
        if self.ip_info.get('postal') and self.ip_info['postal'] != '-':
            print(f"  {Colors.BCYAN}Postal Code:{Colors.BWHITE}  {self.ip_info['postal']}")
        
        # Network info
        print_subsection("Network Information")
        
        if self.ip_info.get('org') and self.ip_info['org'] != '-':
            print(f"  {Colors.BCYAN}Organization:{Colors.BWHITE} {self.ip_info['org']}")
        
        if self.ip_info.get('isp') and self.ip_info['isp'] != '-':
            print(f"  {Colors.BCYAN}ISP:{Colors.BWHITE}          {self.ip_info['isp']}")
        
        if self.ip_info.get('asn') and self.ip_info['asn'] != '-':
            print(f"  {Colors.BCYAN}ASN:{Colors.BWHITE}          {self.ip_info['asn']}")
        
        if self.ip_info.get('as_description') and self.ip_info['as_description'] != '-':
            print(f"  {Colors.BCYAN}ASN Description:{Colors.BWHITE} {self.ip_info['as_description']}")
        
        if self.ip_info.get('as_domain') and self.ip_info['as_domain'] != '-':
            print(f"  {Colors.BCYAN}ASN Domain:{Colors.BWHITE}   {self.ip_info['as_domain']}")
        
        if self.ip_info.get('netname') and self.ip_info['netname'] != '-':
            print(f"  {Colors.BCYAN}Network Name:{Colors.BWHITE} {self.ip_info['netname']}")
        
        # IP type
        print_subsection("IP Type")
        
        if self.ip_info.get('mobile'):
            cprint(f"  {Colors.BYELLOW}  Mobile Network", Colors.BYELLOW)
        
        if self.ip_info.get('proxy'):
            cprint(f"  {Colors.BYELLOW}  Proxy/VPN Detected", Colors.BYELLOW)
        
        if self.ip_info.get('hosting'):
            cprint(f"  {Colors.BBLUE}  Hosting/Datacenter IP", Colors.BBLUE)
        
        # Blacklist status
        print_subsection("Blacklist Status")
        
        bl_info = self.ip_info.get('blacklists', {})
        if bl_info:
            print(f"  {Colors.BCYAN}Checked:{Colors.BWHITE}      {bl_info.get('checked', 0)} blacklists")
            
            if bl_info.get('listed'):
                cprint(f"  {Colors.BRED}Listed on:{Colors.BWHITE}    {bl_info['count']} blacklists", Colors.BRED)
                for bl in bl_info['listed']:
                    cprint(f"    {Colors.BRED}- {bl}", Colors.BRED)
            else:
                print_success("Not listed on any blacklists")
        else:
            print_info("Blacklist check not performed")
        
        # Reverse DNS
        if self.ip_info.get('reverse_dns') or self.ip_info.get('reverse_aliases'):
            print_subsection("Reverse DNS Records")
            
            if self.ip_info.get('reverse_dns'):
                print(f"  {Colors.BCYAN}Primary:{Colors.BWHITE}      {self.ip_info['reverse_dns']}")
            
            if self.ip_info.get('reverse_aliases'):
                print(f"  {Colors.BCYAN}Aliases:{Colors.BWHITE}")
                for alias in self.ip_info['reverse_aliases']:
                    print(f"    {Colors.BWHITE}{alias}")
    
    def _save_to_database(self, ip):
        """Save IP info to database"""
        try:
            with self.db._cursor() as cursor:
                cursor.execute("""
                    INSERT OR REPLACE INTO network_hosts 
                    (scan_id, ip_address, hostname, vendor, os_guess, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    0,
                    ip,
                    self.ip_info.get('hostname', '-'),
                    self.ip_info.get('org', '-'),
                    f"{self.ip_info.get('city', '')}, {self.ip_info.get('country', '')}",
                    'active'
                ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file, ip):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'ip': ip,
                'lookup_time': datetime.now().isoformat(),
                'information': self.ip_info
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
