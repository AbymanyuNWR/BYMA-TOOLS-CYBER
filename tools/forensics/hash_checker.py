"""
BYMA TOOLS - Advanced Hash Checker
Professional hash verification and lookup
"""
import hashlib
import json
import requests
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class HashChecker:
    """Professional hash checker with online lookups"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    # Hash type patterns
    HASH_PATTERNS = {
        'MD5': (32, r'^[a-f0-9]{32}$'),
        'SHA1': (40, r'^[a-f0-9]{40}$'),
        'SHA256': (64, r'^[a-f0-9]{64}$'),
        'SHA384': (96, r'^[a-f0-9]{96}$'),
        'SHA512': (128, r'^[a-f0-9]{128}$'),
        'NTLM': (32, r'^[a-f0-9]{32}$'),
        'RIPEMD160': (40, r'^[a-f0-9]{40}$'),
        'CRC32': (8, r'^[a-f0-9]{8}$'),
        'Adler32': (8, r'^[a-f0-9]{8}$'),
    }
    
    # Online hash lookup APIs
    LOOKUP_SERVICES = [
        {
            'name': 'MD5Decrypt',
            'url': 'https://md5decrypt.net/Api/api.php',
            'hash_types': ['MD5', 'SHA1', 'SHA256'],
        },
        {
            'name': 'Hashes.com',
            'url': 'https://hashes.com/en/decrypt/hash',
            'hash_types': ['MD5', 'SHA1', 'SHA256'],
        },
    ]
    
    def check(self, hash_value=None, file_path=None, output=None):
        """Main check function"""
        print_section("HASH CHECKER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("hash_check", hash_value or file_path, "forensics")
        self.logger.scan_start("hash_check", hash_value or file_path)
        
        try:
            if file_path:
                # Calculate hashes from file
                print_subsection("Calculating File Hashes")
                hashes = self._calculate_file_hashes(file_path)
                self._display_hashes(hashes)
            elif hash_value:
                # Check provided hash
                print_subsection("Hash Analysis")
                analysis = self._analyze_hash(hash_value)
                self._display_analysis(analysis)
                
                # Online lookup
                print_subsection("Online Lookup")
                self._online_lookup(hash_value)
            else:
                print_error("No hash or file provided")
                return None
            
            # Save to database
            self._save_to_database(scan_id, hash_value or file_path)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", 1)
            self.logger.scan_complete("hash_check", hash_value or file_path, 1)
            
            # Save to file if requested
            if output:
                self._save_results(output, hash_value or file_path)
            
            return True
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("hash_check", hash_value or file_path, str(e))
            print_error(f"Check failed: {e}")
            return False
    
    def _calculate_file_hashes(self, file_path):
        """Calculate hashes for a file"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            print_error(f"File not found: {file_path}")
            return {}
        
        hashes = {}
        
        # Calculate different hashes
        hash_funcs = {
            'MD5': hashlib.md5,
            'SHA1': hashlib.sha1,
            'SHA256': hashlib.sha256,
            'SHA384': hashlib.sha384,
            'SHA512': hashlib.sha512,
        }
        
        with open(file_path, 'rb') as f:
            content = f.read()
            
            for name, func in hash_funcs.items():
                hashes[name] = func(content).hexdigest()
        
        # File info
        hashes['Size'] = f"{len(content):,} bytes"
        hashes['File'] = file_path.name
        
        return hashes
    
    def _analyze_hash(self, hash_value):
        """Analyze hash value"""
        import re
        
        analysis = {
            'hash': hash_value,
            'length': len(hash_value),
            'possible_types': [],
            'format': 'Unknown',
        }
        
        # Check format
        if re.match(r'^[a-f0-9]+$', hash_value.lower()):
            analysis['format'] = 'Hexadecimal'
        elif re.match(r'^[A-Za-z0-9+/]+=*$', hash_value):
            analysis['format'] = 'Base64'
        else:
            analysis['format'] = 'Unknown'
        
        # Detect possible hash types
        for htype, (length, pattern) in self.HASH_PATTERNS.items():
            if len(hash_value) == length:
                if re.match(pattern, hash_value.lower()):
                    analysis['possible_types'].append(htype)
        
        return analysis
    
    def _online_lookup(self, hash_value):
        """Perform online hash lookup"""
        print_info("Attempting online lookup...")
        print()
        
        found = False
        
        for service in self.LOOKUP_SERVICES:
            try:
                print_info(f"Checking {service['name']}...")
                
                # This is a simplified lookup
                # In production, you'd need API keys or proper form submission
                print_info(f"  Service: {service['name']}")
                print_info(f"  URL: {service['url']}")
                print_info(f"  Supported types: {', '.join(service['hash_types'])}")
                print()
            
            except Exception as e:
                print_warning(f"  Lookup failed: {e}")
        
        if not found:
            print_info("Online lookup requires manual verification")
            print_info("Try these services manually:")
            for service in self.LOOKUP_SERVICES:
                print_info(f"  - {service['name']}: {service['url']}")
    
    def _display_hashes(self, hashes):
        """Display calculated hashes"""
        print()
        for name, value in hashes.items():
            if name in ['Size', 'File']:
                print(f"  {Colors.BCYAN}{name}:{Colors.BWHITE} {value}")
            else:
                print(f"  {Colors.BCYAN}{name}:{Colors.BWHITE} {value}")
        print()
    
    def _display_analysis(self, analysis):
        """Display hash analysis"""
        print()
        print(f"  {Colors.BCYAN}Hash:{Colors.BWHITE}       {analysis['hash'][:60]}...")
        print(f"  {Colors.BCYAN}Length:{Colors.BWHITE}     {analysis['length']}")
        print(f"  {Colors.BCYAN}Format:{Colors.BWHITE}     {analysis['format']}")
        
        if analysis['possible_types']:
            print(f"  {Colors.BCYAN}Possible Types:{Colors.BWHITE} {', '.join(analysis['possible_types'])}")
        else:
            print_warning("  Could not determine hash type")
        
        print()
    
    def _save_to_database(self, scan_id, hash_value):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                cursor.execute("""
                    INSERT INTO scan_results 
                    (scan_id, result_type, result_data)
                    VALUES (?, ?, ?)
                """, (
                    scan_id,
                    'hash_check',
                    json.dumps({
                        'hash': hash_value,
                    })
                ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file, hash_value):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'scan_time': datetime.now().isoformat(),
                'hash': hash_value,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
