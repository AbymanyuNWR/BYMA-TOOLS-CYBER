"""
BYMA TOOLS - Advanced WHOIS Lookup
Professional WHOIS lookup with history, abuse contacts, and analysis
"""
import whois
import socket
import json
import re
from pathlib import Path
from datetime import datetime, timedelta
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_logger
from core.database import get_database


class WhoisLookup:
    """Professional WHOIS lookup with advanced features"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.whois_data = {}
    
    def lookup(self, domain, output=None):
        """Main WHOIS lookup function"""
        print_section(f"WHOIS LOOKUP: {domain}")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("whois_lookup", domain, "recon")
        self.logger.scan_start("whois_lookup", domain)
        
        try:
            # Clean domain
            domain = domain.strip().lower()
            if domain.startswith('http'):
                domain = domain.split('://')[1].split('/')[0]
            
            print_info(f"Performing WHOIS lookup for {domain}")
            print()
            
            # Get WHOIS data
            w = whois.whois(domain)
            
            if w is None:
                print_error("No WHOIS data found")
                return None
            
            # Parse and organize data
            self.whois_data = self._parse_whois(w, domain)
            
            # Display results
            self._display_results(domain)
            
            # Security analysis
            self._security_analysis(domain)
            
            # Check for abuse contacts
            self._find_abuse_contacts()
            
            # Domain age and expiration
            self._analyze_domain_age()
            
            # Save to database
            self._save_to_database(domain)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", 1)
            self.logger.scan_complete("whois_lookup", domain, 1)
            
            # Save to file if requested
            if output:
                self._save_results(output, domain)
            
            return self.whois_data
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("whois_lookup", domain, str(e))
            print_error(f"WHOIS lookup failed: {e}")
            return None
    
    def _parse_whois(self, w, domain):
        """Parse WHOIS data into organized structure"""
        data = {
            'domain': domain,
            'registrar': None,
            'whois_server': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'status': [],
            'registrant': {
                'name': None,
                'organization': None,
                'email': None,
                'phone': None,
                'address': None,
                'city': None,
                'state': None,
                'country': None,
                'postal_code': None,
            },
            'admin': {
                'name': None,
                'organization': None,
                'email': None,
                'phone': None,
            },
            'tech': {
                'name': None,
                'organization': None,
                'email': None,
                'phone': None,
            },
            'dnssec': None,
            'raw': str(w),
        }
        
        # Extract registrar
        if hasattr(w, 'registrar'):
            data['registrar'] = w.registrar
        
        # Extract WHOIS server
        if hasattr(w, 'whois_server'):
            data['whois_server'] = w.whois_server
        
        # Extract dates
        if hasattr(w, 'creation_date'):
            data['creation_date'] = self._parse_date(w.creation_date)
        
        if hasattr(w, 'expiration_date'):
            data['expiration_date'] = self._parse_date(w.expiration_date)
        
        if hasattr(w, 'updated_date'):
            data['updated_date'] = self._parse_date(w.updated_date)
        
        # Extract name servers
        if hasattr(w, 'name_servers'):
            if isinstance(w.name_servers, list):
                data['name_servers'] = [ns.lower() for ns in w.name_servers if ns]
            elif w.name_servers:
                data['name_servers'] = [w.name_servers.lower()]
        
        # Extract status
        if hasattr(w, 'status'):
            if isinstance(w.status, list):
                data['status'] = w.status
            elif w.status:
                data['status'] = [w.status]
        
        # Extract registrant info
        registrant_fields = {
            'name': ['name', 'registrant_name'],
            'organization': ['org', 'organization', 'registrant_organization'],
            'email': ['email', 'registrant_email'],
            'phone': ['phone', 'registrant_phone'],
            'address': ['address', 'street', 'registrant_address'],
            'city': ['city', 'registrant_city'],
            'state': ['state', 'registrant_state'],
            'country': ['country', 'registrant_country'],
            'postal_code': ['postal_code', 'registrant_postal_code'],
        }
        
        for field, attrs in registrant_fields.items():
            for attr in attrs:
                if hasattr(w, attr) and getattr(w, attr):
                    data['registrant'][field] = getattr(w, attr)
                    break
        
        # Extract admin contact
        admin_fields = {
            'name': ['admin_name', 'admin_contact'],
            'organization': ['admin_org', 'admin_organization'],
            'email': ['admin_email'],
            'phone': ['admin_phone'],
        }
        
        for field, attrs in admin_fields.items():
            for attr in attrs:
                if hasattr(w, attr) and getattr(w, attr):
                    data['admin'][field] = getattr(w, attr)
                    break
        
        # Extract tech contact
        tech_fields = {
            'name': ['tech_name', 'tech_contact'],
            'organization': ['tech_org', 'tech_organization'],
            'email': ['tech_email'],
            'phone': ['tech_phone'],
        }
        
        for field, attrs in tech_fields.items():
            for attr in attrs:
                if hasattr(w, attr) and getattr(w, attr):
                    data['tech'][field] = getattr(w, attr)
                    break
        
        # Extract DNSSEC
        if hasattr(w, 'dnssec'):
            data['dnssec'] = w.dnssec
        
        return data
    
    def _parse_date(self, date_value):
        """Parse date from various formats"""
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        if isinstance(date_value, datetime):
            return date_value.isoformat()
        
        if isinstance(date_value, str):
            try:
                return datetime.fromisoformat(date_value).isoformat()
            except:
                pass
        
        return str(date_value) if date_value else None
    
    def _display_results(self, domain):
        """Display WHOIS results"""
        print_section("WHOIS INFORMATION")
        
        # Domain info
        print(f"  {Icons.TARGET} {Colors.BCYAN}Domain:{Colors.BWHITE}        {domain}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Registrar:{Colors.BWHITE}     {self.whois_data.get('registrar', '-')}")
        print(f"  {Icons.INFO} {Colors.BCYAN}WHOIS Server:{Colors.BWHITE}  {self.whois_data.get('whois_server', '-')}")
        print(f"  {Icons.INFO} {Colors.BCYAN}DNSSEC:{Colors.BWHITE}        {self.whois_data.get('dnssec', '-')}")
        
        print_separator("-", 50)
        
        # Dates
        print_subsection("Important Dates")
        print(f"  {Colors.BGREEN}Created:{Colors.BWHITE}      {self.whois_data.get('creation_date', '-')}")
        print(f"  {Colors.BYELLOW}Expires:{Colors.BWHITE}      {self.whois_data.get('expiration_date', '-')}")
        print(f"  {Colors.BBLUE}Updated:{Colors.BWHITE}      {self.whois_data.get('updated_date', '-')}")
        
        print_separator("-", 50)
        
        # Name servers
        if self.whois_data.get('name_servers'):
            print_subsection("Name Servers")
            for ns in self.whois_data['name_servers']:
                print(f"  {Colors.BWHITE}  - {ns}")
        
        # Status
        if self.whois_data.get('status'):
            print_subsection("Domain Status")
            for status in self.whois_data['status']:
                cprint(f"  {Colors.BYELLOW}  - {status}", Colors.BYELLOW)
        
        # Registrant info
        if self.whois_data.get('registrant'):
            print_subsection("Registrant Contact")
            reg = self.whois_data['registrant']
            for key, value in reg.items():
                if value:
                    print(f"  {Colors.BCYAN}{key.title():<15}{Colors.BWHITE} {value}")
        
        # Admin contact
        if self.whois_data.get('admin'):
            print_subsection("Admin Contact")
            admin = self.whois_data['admin']
            for key, value in admin.items():
                if value:
                    print(f"  {Colors.BCYAN}{key.title():<15}{Colors.BWHITE} {value}")
        
        # Tech contact
        if self.whois_data.get('tech'):
            print_subsection("Tech Contact")
            tech = self.whois_data['tech']
            for key, value in tech.items():
                if value:
                    print(f"  {Colors.BCYAN}{key.title():<15}{Colors.BWHITE} {value}")
    
    def _security_analysis(self, domain):
        """Perform security analysis on domain"""
        print_subsection("Security Analysis")
        
        issues = []
        
        # Check if domain is expired
        if self.whois_data.get('expiration_date'):
            try:
                exp_date = datetime.fromisoformat(self.whois_data['expiration_date'])
                if exp_date < datetime.now():
                    issues.append(("CRITICAL", "Domain has expired!"))
                elif exp_date < datetime.now() + timedelta(days=30):
                    issues.append(("WARNING", "Domain expires within 30 days!"))
                elif exp_date < datetime.now() + timedelta(days=90):
                    issues.append(("INFO", "Domain expires within 90 days"))
            except:
                pass
        
        # Check DNSSEC
        if self.whois_data.get('dnssec') and 'unsigned' in str(self.whois_data['dnssec']).lower():
            issues.append(("WARNING", "DNSSEC is not enabled"))
        
        # Check privacy protection
        registrant = self.whois_data.get('registrant', {})
        if registrant.get('name'):
            name = registrant['name'].lower()
            if any(word in name for word in ['privacy', 'protected', 'redacted', 'proxy', 'whoisguard']):
                issues.append(("INFO", "WHOIS privacy protection is enabled"))
        
        # Check name servers
        if not self.whois_data.get('name_servers'):
            issues.append(("WARNING", "No name servers found"))
        elif len(self.whois_data.get('name_servers', [])) < 2:
            issues.append(("WARNING", "Only one name server - single point of failure"))
        
        # Display issues
        if issues:
            for severity, message in issues:
                if severity == "CRITICAL":
                    cprint(f"  {Colors.BRED}[!!!] {message}", Colors.BRED)
                elif severity == "WARNING":
                    cprint(f"  {Colors.BYELLOW}[*] {message}", Colors.BYELLOW)
                else:
                    cprint(f"  {Icons.INFO} {message}", Colors.BCYAN)
        else:
            print_success("No security issues detected")
    
    def _find_abuse_contacts(self):
        """Find abuse contact information"""
        print_subsection("Abuse Contacts")
        
        contacts = []
        
        # Extract from registrant
        reg = self.whois_data.get('registrant', {})
        if reg.get('email'):
            contacts.append(('Registrant', reg['email']))
        
        # Extract from admin
        admin = self.whois_data.get('admin', {})
        if admin.get('email'):
            contacts.append(('Admin', admin['email']))
        
        # Extract from raw data (common patterns)
        raw = self.whois_data.get('raw', '')
        email_pattern = r'[\w.-]+@[\w.-]+\.\w+'
        emails = re.findall(email_pattern, raw)
        
        for email in emails:
            if 'abuse' in email.lower():
                contacts.append(('Abuse', email))
            elif 'security' in email.lower():
                contacts.append(('Security', email))
            elif 'report' in email.lower():
                contacts.append(('Report', email))
        
        # Display contacts
        if contacts:
            for contact_type, email in set(contacts):
                print(f"  {Colors.BCYAN}{contact_type:<15}{Colors.BWHITE} {email}")
        else:
            print_warning("No abuse contacts found")
    
    def _analyze_domain_age(self):
        """Analyze domain age and history"""
        print_subsection("Domain Age Analysis")
        
        if self.whois_data.get('creation_date'):
            try:
                creation_date = datetime.fromisoformat(self.whois_data['creation_date'])
                age = datetime.now() - creation_date
                
                years = age.days // 365
                months = (age.days % 365) // 30
                days = age.days % 30
                
                print(f"  {Colors.BCYAN}Age:{Colors.BWHITE}            {years} years, {months} months, {days} days")
                print(f"  {Colors.BCYAN}Created:{Colors.BWHITE}       {creation_date.strftime('%Y-%m-%d')}")
                
                # Risk assessment
                if years < 1:
                    cprint(f"  {Colors.BYELLOW}[!] New domain (< 1 year) - Higher risk", Colors.BYELLOW)
                elif years < 3:
                    cprint(f"  {Colors.BBLUE}[i] Relatively new domain (< 3 years)", Colors.BBLUE)
                else:
                    cprint(f"  {Colors.BGREEN}[+] Established domain (>{ years} years)", Colors.BGREEN)
                
                # Calculate expiration
                if self.whois_data.get('expiration_date'):
                    exp_date = datetime.fromisoformat(self.whois_data['expiration_date'])
                    remaining = exp_date - datetime.now()
                    
                    if remaining.days > 0:
                        exp_years = remaining.days // 365
                        exp_months = (remaining.days % 365) // 30
                        print(f"  {Colors.BCYAN}Expires in:{Colors.BWHITE}    {exp_years} years, {exp_months} months")
                    else:
                        cprint(f"  {Colors.BRED}[!] Domain has expired!", Colors.BRED)
            except Exception as e:
                print_warning(f"Could not calculate domain age: {e}")
        else:
            print_warning("Creation date not available")
    
    def _save_to_database(self, domain):
        """Save WHOIS data to database"""
        try:
            with self.db._cursor() as cursor:
                cursor.execute("""
                    INSERT OR REPLACE INTO whois_info 
                    (domain, registrar, creation_date, expiration_date, updated_date,
                     name_servers, status, registrant_name, registrant_org, registrant_country)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    domain,
                    self.whois_data.get('registrar'),
                    self.whois_data.get('creation_date'),
                    self.whois_data.get('expiration_date'),
                    self.whois_data.get('updated_date'),
                    json.dumps(self.whois_data.get('name_servers', [])),
                    json.dumps(self.whois_data.get('status', [])),
                    self.whois_data.get('registrant', {}).get('name'),
                    self.whois_data.get('registrant', {}).get('organization'),
                    self.whois_data.get('registrant', {}).get('country'),
                ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file, domain):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'domain': domain,
                'lookup_time': datetime.now().isoformat(),
                'whois_data': self.whois_data
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
