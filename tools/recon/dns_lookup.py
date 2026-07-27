"""
BYMA TOOLS - Advanced DNS Lookup
Professional DNS enumeration with zone transfer and record analysis
"""
import dns.resolver
import dns.rdatatype
import dns.zone
import dns.query
import dns.exception
import socket
import json
import re
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_logger
from core.database import get_database


class DNSLookup:
    """Professional DNS lookup with advanced features"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.dns_records = {}
        self.dns_servers = []
    
    def lookup(self, domain, output=None, enum_all=True):
        """Main DNS lookup function"""
        print_section(f"DNS LOOKUP: {domain}")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("dns_lookup", domain, "recon")
        self.logger.scan_start("dns_lookup", domain)
        
        try:
            # Clean domain
            domain = domain.strip().lower()
            if domain.startswith('http'):
                domain = domain.split('://')[1].split('/')[0]
            
            print_info(f"Performing DNS lookup for {domain}")
            print()
            
            # Get name servers first
            self._get_name_servers(domain)
            
            # Enumerate all record types
            if enum_all:
                self._enumerate_all_records(domain)
            else:
                self._basic_lookup(domain)
            
            # Test zone transfer
            print_subsection("Zone Transfer Test")
            self._test_zone_transfer(domain)
            
            # DNS security analysis
            self._dns_security_analysis(domain)
            
            # Display results
            self._display_results(domain)
            
            # Save to database
            self._save_to_database(domain)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.dns_records))
            self.logger.scan_complete("dns_lookup", domain, len(self.dns_records))
            
            # Save to file if requested
            if output:
                self._save_results(output, domain)
            
            return self.dns_records
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("dns_lookup", domain, str(e))
            print_error(f"DNS lookup failed: {e}")
            return {}
    
    def _get_name_servers(self, domain):
        """Get name servers for domain"""
        print_info("Getting name servers...")
        
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            self.dns_servers = [str(ns).rstrip('.') for ns in answers]
            
            print_success(f"Found {len(self.dns_servers)} name servers:")
            for ns in self.dns_servers:
                print(f"    {Colors.BWHITE}{ns}")
        except Exception as e:
            print_warning(f"Could not get name servers: {e}")
    
    def _enumerate_all_records(self, domain):
        """Enumerate all DNS record types"""
        record_types = [
            ('A', 'IPv4 Addresses'),
            ('AAAA', 'IPv6 Addresses'),
            ('MX', 'Mail Exchangers'),
            ('NS', 'Name Servers'),
            ('TXT', 'Text Records'),
            ('CNAME', 'Canonical Names'),
            ('SOA', 'Start of Authority'),
            ('SRV', 'Service Records'),
            ('CAA', 'Certificate Authority'),
            ('DNSKEY', 'DNS Security Keys'),
            ('DS', 'Delegation Signer'),
            ('NSEC', 'Next Secure'),
            ('NSEC3', 'Next Secure v3'),
            ('PTR', 'Pointer Records'),
            ('HINFO', 'Host Information'),
            ('RP', 'Responsible Person'),
            ('AFSDB', 'AFS Database'),
            ('SSHFP', 'SSH Fingerprints'),
            ('TLSA', 'DANE TLSA'),
        ]
        
        print_subsection("Record Enumeration")
        
        for record_type, description in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = []
                
                for rdata in answers:
                    record = self._format_record(record_type, rdata)
                    if record:
                        records.append(record)
                
                if records:
                    self.dns_records[record_type] = {
                        'description': description,
                        'records': records,
                        'count': len(records)
                    }
                    print_success(f"{record_type}: {len(records)} records")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                print_error(f"Domain does not exist")
                break
            except dns.resolver.NoNameservers:
                pass
            except dns.exception.Timeout:
                pass
            except Exception:
                pass
    
    def _format_record(self, record_type, rdata):
        """Format DNS record for display"""
        try:
            if record_type == 'A':
                return str(rdata)
            elif record_type == 'AAAA':
                return str(rdata)
            elif record_type == 'MX':
                return f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
            elif record_type == 'NS':
                return str(rdata).rstrip('.')
            elif record_type == 'TXT':
                return str(rdata).strip('"')
            elif record_type == 'CNAME':
                return str(rdata).rstrip('.')
            elif record_type == 'SOA':
                return (f"MName: {str(rdata.mname).rstrip('.')} | "
                       f"RName: {str(rdata.rname).rstrip('.')} | "
                       f"Serial: {rdata.serial}")
            elif record_type == 'SRV':
                return f"{rdata.priority} {rdata.weight} {rdata.port} {str(rdata.target).rstrip('.')}"
            elif record_type == 'CAA':
                return f"{rdata.flags} {rdata.tag} {rdata.value}"
            elif record_type == 'DNSKEY':
                return f"Flags: {rdata.flags} | Protocol: {rdata.protocol} | Algorithm: {rdata.algorithm}"
            elif record_type == 'DS':
                return f"Key Tag: {rdata.key_tag} | Algorithm: {rdata.algorithm} | Digest Type: {rdata.digest_type}"
            elif record_type == 'NSEC':
                return f"Next: {str(rdata.next_domain).rstrip('.')}"
            elif record_type == 'NSEC3':
                return f"Hash: {rdata.salt.hex() if rdata.salt else 'N/A'}"
            elif record_type == 'SSHFP':
                return f"Algorithm: {rdata.algorithm} | Fingerprint Type: {rdata.fp_type}"
            elif record_type == 'TLSA':
                return f"Certificate Usage: {rdata.cert_usage} | Selector: {rdata.selector} | Matching Type: {rdata.mtype}"
            else:
                return str(rdata)
        except:
            return str(rdata)
    
    def _basic_lookup(self, domain):
        """Basic DNS lookup for common records"""
        common_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        print_subsection("Basic DNS Records")
        
        for record_type in common_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = []
                
                for rdata in answers:
                    record = self._format_record(record_type, rdata)
                    if record:
                        records.append(record)
                
                if records:
                    self.dns_records[record_type] = {
                        'description': record_type,
                        'records': records,
                        'count': len(records)
                    }
                    print_success(f"{record_type}: {len(records)} records")
            except:
                pass
    
    def _test_zone_transfer(self, domain):
        """Test for DNS zone transfer vulnerability"""
        if not self.dns_servers:
            print_warning("No name servers to test")
            return
        
        vulnerable_ns = []
        
        for ns in self.dns_servers:
            try:
                print_info(f"Testing zone transfer on {ns}...")
                
                # Try zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                
                if zone:
                    # Get all records from zone
                    names = zone.nodes.keys()
                    record_count = len(list(names))
                    
                    vulnerable_ns.append((ns, record_count))
                    print_warning(f"ZONE TRANSFER SUCCESSFUL on {ns}! ({record_count} records)")
                    
                    # Extract records
                    for name in names:
                        node = zone.nodes[name]
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                subdomain = str(name) + '.' + domain if str(name) != '@' else domain
                                record_type = dns.rdatatype.to_text(rdataset.rdtype)
                                
                                if subdomain not in self.dns_records:
                                    self.dns_records[subdomain] = {
                                        'description': f'Zone transfer - {record_type}',
                                        'records': [],
                                        'count': 0
                                    }
                                
                                self.dns_records[subdomain]['records'].append(
                                    f"{record_type}: {self._format_record(record_type, rdata)}"
                                )
                                self.dns_records[subdomain]['count'] += 1
                    
            except dns.exception.Timeout:
                print_info(f"Timeout on {ns} - likely protected")
            except dns.exception.FormError:
                print_info(f"Zone transfer refused on {ns}")
            except Exception as e:
                if 'REFUSED' in str(e) or 'NOTAUTH' in str(e):
                    print_info(f"Zone transfer refused on {ns}")
                else:
                    print_info(f"Zone transfer failed on {ns}: {e}")
        
        if vulnerable_ns:
            print()
            print_error("CRITICAL: Zone transfer is enabled on vulnerable servers!")
            for ns, count in vulnerable_ns:
                print_error(f"  {ns}: {count} records exposed")
        else:
            print_success("Zone transfer is properly restricted")
    
    def _dns_security_analysis(self, domain):
        """Analyze DNS security"""
        print_subsection("DNS Security Analysis")
        
        issues = []
        
        # Check for DNSSEC
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            print_success("DNSSEC is enabled")
        except:
            issues.append(("WARNING", "DNSSEC is not enabled"))
        
        # Check for SPF
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if 'v=spf1' in str(rdata):
                    print_success("SPF record found")
                    break
            else:
                issues.append(("WARNING", "No SPF record found"))
        except:
            issues.append(("WARNING", "Could not check SPF"))
        
        # Check for DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            print_success("DMARC record found")
        except:
            issues.append(("INFO", "No DMARC record found"))
        
        # Check for CAA
        try:
            answers = dns.resolver.resolve(domain, 'CAA')
            print_success("CAA record found")
        except:
            issues.append(("INFO", "No CAA record found"))
        
        # Display issues
        for severity, message in issues:
            if severity == "WARNING":
                cprint(f"  {Colors.BYELLOW}[*] {message}", Colors.BYELLOW)
            else:
                cprint(f"  {Icons.INFO} {message}", Colors.BCYAN)
    
    def _display_results(self, domain):
        """Display DNS lookup results"""
        print_section("DNS RECORDS")
        
        if not self.dns_records:
            print_warning("No DNS records found")
            return
        
        # Summary
        total_records = sum(r.get('count', 0) for r in self.dns_records.values())
        
        print(f"  {Icons.TARGET} {Colors.BCYAN}Domain:{Colors.BWHITE}        {domain}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Record Types:{Colors.BWHITE}  {len(self.dns_records)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Total Records:{Colors.BWHITE} {total_records}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Name Servers:{Colors.BWHITE}  {len(self.dns_servers)}")
        
        print_separator("-", 50)
        print()
        
        # Display each record type
        for record_type, data in sorted(self.dns_records.items()):
            print_subsection(f"{record_type} Records ({data['count']})")
            
            for record in data.get('records', [])[:20]:  # Limit display
                print(f"    {Colors.BWHITE}{record}")
            
            if data.get('count', 0) > 20:
                print(f"    {Colors.BBLUE}... and {data['count'] - 20} more records")
            print()
    
    def _save_to_database(self, domain):
        """Save DNS records to database"""
        try:
            with self.db._cursor() as cursor:
                for record_type, data in self.dns_records.items():
                    for record in data.get('records', []):
                        cursor.execute("""
                            INSERT INTO dns_records 
                            (scan_id, domain, record_type, record_value)
                            VALUES (?, ?, ?, ?)
                        """, (0, domain, record_type, record))
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
                'name_servers': self.dns_servers,
                'records': self.dns_records,
                'total_records': sum(r.get('count', 0) for r in self.dns_records.values())
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
