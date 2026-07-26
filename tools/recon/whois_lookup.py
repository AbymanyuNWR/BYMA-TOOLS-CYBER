"""
BYMA TOOLS - WHOIS Lookup
Tools untuk WHOIS information gathering
"""
import whois
import json
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class WhoisLookup:
    """WHOIS lookup for domain information"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    def lookup(self, domain, output=None):
        """Perform WHOIS lookup"""
        print_section(f"WHOIS Lookup: {domain}")
        
        # Create scan record
        scan_id = self.db.create_scan("whois_lookup", domain, "recon")
        self.logger.scan_start("whois_lookup", domain)
        
        try:
            # Perform WHOIS query
            print_info(f"Querying WHOIS for {domain}...")
            w = whois.whois(domain)
            
            # Extract information
            info = self._extract_info(w)
            
            # Display results
            self._display_results(info)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", 1)
            self.logger.scan_complete("whois_lookup", domain, 1)
            
            # Save to file if requested
            if output:
                self._save_results(domain, info, output)
            
            return info
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("whois_lookup", domain, str(e))
            print_error(f"WHOIS lookup failed: {e}")
            return None
    
    def _extract_info(self, w):
        """Extract WHOIS information"""
        info = {
            'domain_name': self._safe_get(w.domain_name),
            'registrar': self._safe_get(w.registrar),
            'whois_server': self._safe_get(w.whois_server),
            'referral_url': self._safe_get(w.referral_url),
            'updated_date': self._format_date(w.updated_date),
            'creation_date': self._format_date(w.creation_date),
            'expiration_date': self._format_date(w.expiration_date),
            'name_servers': self._safe_get(w.name_servers),
            'status': self._safe_get(w.status),
            'emails': self._safe_get(w.emails),
            'dnssec': self._safe_get(w.dnssec),
            'registrant_name': self._safe_get(w.get('name')),
            'registrant_org': self._safe_get(w.org),
            'registrant_address': self._safe_get(w.address),
            'registrant_city': self._safe_get(w.city),
            'registrant_state': self._safe_get(w.state),
            'registrant_zipcode': self._safe_get(w.zipcode),
            'registrant_country': self._safe_get(w.country),
        }
        
        return info
    
    def _safe_get(self, value):
        """Safely get value from WHOIS response"""
        if value is None:
            return None
        if isinstance(value, list):
            return ', '.join(str(v) for v in value)
        return str(value)
    
    def _format_date(self, date):
        """Format date"""
        if date is None:
            return None
        if isinstance(date, list):
            return ', '.join(str(d) for d in date)
        if isinstance(date, datetime):
            return date.strftime("%Y-%m-%d %H:%M:%S")
        return str(date)
    
    def _display_results(self, info):
        """Display WHOIS results"""
        print_section("WHOIS Information")
        
        if not info:
            print_warning("No WHOIS information found")
            return
        
        # Domain Name
        cprint(f"    {'Domain Name:':<25} {info.get('domain_name', 'N/A')}", Colors.BWHITE)
        
        # Registrar
        cprint(f"    {'Registrar:':<25} {info.get('registrar', 'N/A')}", Colors.BCYAN)
        
        # WHOIS Server
        if info.get('whois_server'):
            cprint(f"    {'WHOIS Server:':<25} {info['whois_server']}", Colors.BWHITE)
        
        # Dates
        print()
        cprint(f"    {'Creation Date:':<25} {info.get('creation_date', 'N/A')}", Colors.BGREEN)
        cprint(f"    {'Expiration Date:':<25} {info.get('expiration_date', 'N/A')}", Colors.BYELLOW)
        cprint(f"    {'Updated Date:':<25} {info.get('updated_date', 'N/A')}", Colors.BWHITE)
        
        # Status
        print()
        cprint(f"    {'Status:':<25}", Colors.BCYAN)
        status = info.get('status', 'N/A')
        if status:
            for s in status.split(','):
                cprint(f"      - {s.strip()}", Colors.BWHITE)
        
        # Name Servers
        print()
        cprint(f"    {'Name Servers:':<25}", Colors.BCYAN)
        name_servers = info.get('name_servers', '')
        if name_servers:
            for ns in name_servers.split(','):
                cprint(f"      - {ns.strip()}", Colors.BWHITE)
        
        # Registrant Information
        print()
        cprint(f"    {'Registrant Information:':<25}", Colors.BCYAN)
        cprint(f"      {'Name:':<23} {info.get('registrant_name', 'N/A')}", Colors.BWHITE)
        cprint(f"      {'Organization:':<23} {info.get('registrant_org', 'N/A')}", Colors.BWHITE)
        cprint(f"      {'Country:':<23} {info.get('registrant_country', 'N/A')}", Colors.BWHITE)
        
        # DNSSEC
        if info.get('dnssec'):
            print()
            cprint(f"    {'DNSSEC:':<25} {info['dnssec']}", Colors.BYELLOW)
    
    def _save_results(self, domain, info, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'domain': domain,
                    'whois_info': info,
                    'lookup_time': datetime.now().isoformat()
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
