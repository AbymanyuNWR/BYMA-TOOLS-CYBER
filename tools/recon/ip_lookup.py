"""
BYMA TOOLS - IP Geolocation Lookup
Tools untuk mencari informasi geografis dari IP address
"""
import requests
import json
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class IPLookup:
    """IP geolocation and information lookup"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    def lookup(self, ip_address, output=None):
        """Perform IP lookup"""
        print_section(f"IP Lookup: {ip_address}")
        
        # Create scan record
        scan_id = self.db.create_scan("ip_lookup", ip_address, "recon")
        self.logger.scan_start("ip_lookup", ip_address)
        
        try:
            # Get IP information from multiple APIs
            info = self._get_ip_info(ip_address)
            
            if info:
                # Display results
                self._display_results(info)
                
                # Update scan status
                self.db.update_scan(scan_id, "completed", 1)
                self.logger.scan_complete("ip_lookup", ip_address, 1)
                
                # Save to file if requested
                if output:
                    self._save_results(ip_address, info, output)
                
                return info
            else:
                print_error("Could not retrieve IP information")
                self.db.update_scan(scan_id, "failed")
                return None
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("ip_lookup", ip_address, str(e))
            print_error(f"IP lookup failed: {e}")
            return None
    
    def _get_ip_info(self, ip_address):
        """Get IP information from APIs"""
        info = {
            'ip': ip_address,
            'queries': []
        }
        
        # Query 1: ip-api.com (free, no key required)
        print_info("Querying ip-api.com...")
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    info.update({
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'asname': data.get('asname'),
                        'mobile': data.get('mobile'),
                        'proxy': data.get('proxy'),
                        'hosting': data.get('hosting'),
                    })
                    info['queries'].append('ip-api.com')
                    print_success("Got data from ip-api.com")
        except Exception as e:
            print_warning(f"ip-api.com query failed: {e}")
        
        # Query 2: ipinfo.io (free tier)
        print_info("Querying ipinfo.io...")
        try:
            response = requests.get(
                f"https://ipinfo.io/{ip_address}/json",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if 'bogon' not in data:
                    info.update({
                        'hostname': data.get('hostname'),
                        'city': info.get('city') or data.get('city'),
                        'region': info.get('region') or data.get('region'),
                        'country': info.get('country') or data.get('country'),
                        'loc': data.get('loc'),
                        'org': info.get('org') or data.get('org'),
                        'postal': data.get('postal'),
                        'timezone': info.get('timezone') or data.get('timezone'),
                    })
                    info['queries'].append('ipinfo.io')
                    print_success("Got data from ipinfo.io")
        except Exception as e:
            print_warning(f"ipinfo.io query failed: {e}")
        
        return info
    
    def _display_results(self, info):
        """Display IP information"""
        print_section("IP Information")
        
        if not info:
            print_warning("No information found")
            return
        
        # Basic Info
        cprint(f"    {'IP Address:':<25} {info.get('ip', 'N/A')}", Colors.BWHITE)
        
        if info.get('hostname'):
            cprint(f"    {'Hostname:':<25} {info['hostname']}", Colors.BCYAN)
        
        # Location
        print()
        cprint(f"    {'Location Information:':<25}", Colors.BCYAN)
        
        location_parts = []
        if info.get('city'):
            location_parts.append(info['city'])
        if info.get('region'):
            location_parts.append(info['region'])
        if info.get('country'):
            location_parts.append(info['country'])
        
        if location_parts:
            cprint(f"      {'Location:':<23} {', '.join(location_parts)}", Colors.BWHITE)
        
        if info.get('zip'):
            cprint(f"      {'ZIP Code:':<23} {info['zip']}", Colors.BWHITE)
        
        if info.get('latitude') and info.get('longitude'):
            cprint(f"      {'Coordinates:':<23} {info['latitude']}, {info['longitude']}", Colors.BWHITE)
        
        if info.get('timezone'):
            cprint(f"      {'Timezone:':<23} {info['timezone']}", Colors.BWHITE)
        
        # Network Info
        print()
        cprint(f"    {'Network Information:':<25}", Colors.BCYAN)
        
        if info.get('isp'):
            cprint(f"      {'ISP:':<23} {info['isp']}", Colors.BWHITE)
        
        if info.get('org'):
            cprint(f"      {'Organization:':<23} {info['org']}", Colors.BWHITE)
        
        if info.get('as'):
            cprint(f"      {'AS Number:':<23} {info['as']}", Colors.BWHITE)
        
        if info.get('asname'):
            cprint(f"      {'AS Name:':<23} {info['asname']}", Colors.BWHITE)
        
        # Additional Info
        print()
        cprint(f"    {'Additional Info:':<25}", Colors.BCYAN)
        
        if info.get('mobile') is not None:
            status = "Yes" if info['mobile'] else "No"
            cprint(f"      {'Mobile Network:':<23} {status}", Colors.BWHITE)
        
        if info.get('proxy') is not None:
            status = "Yes" if info['proxy'] else "No"
            color = Colors.BRED if info['proxy'] else Colors.BGREEN
            cprint(f"      {'Proxy/VPN:':<23} {status}", color)
        
        if info.get('hosting') is not None:
            status = "Yes" if info['hosting'] else "No"
            cprint(f"      {'Hosting Provider:':<23} {status}", Colors.BWHITE)
    
    def _save_results(self, ip_address, info, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'ip': ip_address,
                    'info': info,
                    'lookup_time': str(Path().absolute())
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
