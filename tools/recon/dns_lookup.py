"""
BYMA TOOLS - DNS Lookup
Tools untuk DNS enumeration dan record lookup
"""
import dns.resolver
import dns.zone
import dns.query
import json
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_table, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class DNSLookup:
    """DNS lookup and enumeration"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.records = {}
    
    def lookup(self, domain, output=None):
        """Perform DNS lookup"""
        print_section(f"DNS Lookup: {domain}")
        
        # Create scan record
        scan_id = self.db.create_scan("dns_lookup", domain, "recon")
        self.logger.scan_start("dns_lookup", domain)
        
        try:
            # Query all record types
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
            
            for record_type in record_types:
                self._query_record(domain, record_type, scan_id)
            
            # Check for zone transfer
            print_info("Checking for zone transfer...")
            self._check_zone_transfer(domain)
            
            # Display results
            self._display_results(domain)
            
            # Update scan status
            total_records = sum(len(v) for v in self.records.values())
            self.db.update_scan(scan_id, "completed", total_records)
            self.logger.scan_complete("dns_lookup", domain, total_records)
            
            # Save to file if requested
            if output:
                self._save_results(domain, output)
            
            return self.records
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("dns_lookup", domain, str(e))
            print_error(f"DNS lookup failed: {e}")
            return {}
    
    def _query_record(self, domain, record_type, scan_id):
        """Query specific DNS record type"""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            self.records[record_type] = []
            
            for rdata in answers:
                if record_type == 'A':
                    value = str(rdata)
                    self.records[record_type].append({'value': value})
                    self.db.add_dns_record(scan_id, domain, record_type, value)
                
                elif record_type == 'AAAA':
                    value = str(rdata)
                    self.records[record_type].append({'value': value})
                    self.db.add_dns_record(scan_id, domain, record_type, value)
                
                elif record_type == 'MX':
                    value = str(rdata.exchange).rstrip('.')
                    preference = rdata.preference
                    self.records[record_type].append({
                        'value': value,
                        'preference': preference
                    })
                    self.db.add_dns_record(scan_id, domain, record_type, value, preference)
                
                elif record_type == 'NS':
                    value = str(rdata).rstrip('.')
                    self.records[record_type].append({'value': value})
                    self.db.add_dns_record(scan_id, domain, record_type, value)
                
                elif record_type == 'TXT':
                    value = str(rdata).strip('"')
                    self.records[record_type].append({'value': value})
                    self.db.add_dns_record(scan_id, domain, record_type, value)
                
                elif record_type == 'CNAME':
                    value = str(rdata).rstrip('.')
                    self.records[record_type].append({'value': value})
                    self.db.add_dns_record(scan_id, domain, record_type, value)
                
                elif record_type == 'SOA':
                    value = {
                        'mname': str(rdata.mname).rstrip('.'),
                        'rname': str(rdata.rname).rstrip('.'),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum
                    }
                    self.records[record_type].append(value)
                
                elif record_type == 'SRV':
                    value = {
                        'target': str(rdata.target).rstrip('.'),
                        'port': rdata.port,
                        'priority': rdata.priority,
                        'weight': rdata.weight
                    }
                    self.records[record_type].append(value)
            
            if self.records[record_type]:
                print_success(f"Found {len(self.records[record_type])} {record_type} records")
        
        except dns.resolver.NoAnswer:
            print_warning(f"No {record_type} records found")
        except dns.resolver.NXDOMAIN:
            print_error(f"Domain {domain} does not exist")
        except dns.resolver.NoNameservers:
            print_warning(f"No nameservers available for {record_type} query")
        except Exception as e:
            print_warning(f"Error querying {record_type}: {e}")
    
    def _check_zone_transfer(self, domain):
        """Check for DNS zone transfer vulnerability"""
        try:
            # Get nameservers
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                ns_ip = str(ns).rstrip('.')
                
                try:
                    # Try zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=5))
                    
                    if zone:
                        print_warning(f"Zone transfer possible from {ns_ip}!")
                        
                        # List all records
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                for rdata in rdataset:
                                    print_info(f"  {name}.{domain}: {rdata}")
                except:
                    pass
        
        except:
            pass
    
    def _display_results(self, domain):
        """Display DNS results"""
        print_section("DNS Records")
        
        if not self.records:
            print_warning("No DNS records found")
            return
        
        # A Records
        if 'A' in self.records:
            cprint(f"    {'A Records:':<15}", Colors.BCYAN)
            for record in self.records['A']:
                cprint(f"      - {record['value']}", Colors.BWHITE)
        
        # AAAA Records
        if 'AAAA' in self.records:
            cprint(f"    {'AAAA Records:':<15}", Colors.BCYAN)
            for record in self.records['AAAA']:
                cprint(f"      - {record['value']}", Colors.BWHITE)
        
        # MX Records
        if 'MX' in self.records:
            cprint(f"    {'MX Records:':<15}", Colors.BCYAN)
            for record in self.records['MX']:
                cprint(f"      - {record['value']} (priority: {record['preference']})", Colors.BWHITE)
        
        # NS Records
        if 'NS' in self.records:
            cprint(f"    {'NS Records:':<15}", Colors.BCYAN)
            for record in self.records['NS']:
                cprint(f"      - {record['value']}", Colors.BWHITE)
        
        # TXT Records
        if 'TXT' in self.records:
            cprint(f"    {'TXT Records:':<15}", Colors.BCYAN)
            for record in self.records['TXT']:
                value = record['value'][:80] + '...' if len(record['value']) > 80 else record['value']
                cprint(f"      - {value}", Colors.BWHITE)
        
        # CNAME Records
        if 'CNAME' in self.records:
            cprint(f"    {'CNAME Records:':<15}", Colors.BCYAN)
            for record in self.records['CNAME']:
                cprint(f"      - {record['value']}", Colors.BWHITE)
        
        # SOA Record
        if 'SOA' in self.records:
            cprint(f"    {'SOA Record:':<15}", Colors.BCYAN)
            for record in self.records['SOA']:
                cprint(f"      - Primary NS: {record['mname']}", Colors.BWHITE)
                cprint(f"      - Admin: {record['rname']}", Colors.BWHITE)
                cprint(f"      - Serial: {record['serial']}", Colors.BWHITE)
        
        # SRV Records
        if 'SRV' in self.records:
            cprint(f"    {'SRV Records:':<15}", Colors.BCYAN)
            for record in self.records['SRV']:
                cprint(f"      - {record['target']}:{record['port']} (priority: {record['priority']}, weight: {record['weight']})", Colors.BWHITE)
    
    def _save_results(self, domain, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'domain': domain,
                    'dns_records': self.records,
                    'total_records': sum(len(v) for v in self.records.values())
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
