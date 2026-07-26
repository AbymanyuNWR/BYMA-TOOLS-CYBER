"""
BYMA TOOLS - Hash Checker
Tools untuk memeriksa hash file terhadap database malware
"""
import hashlib
import json
import requests
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class HashChecker:
    """Check file hash against malware databases"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    def check(self, file_path, output=None):
        """Check file hash"""
        print_section(f"Hash Checker: {file_path}")
        
        if not Path(file_path).exists():
            print_error(f"File not found: {file_path}")
            return None
        
        try:
            # Calculate file hashes
            print_info("Calculating file hashes...")
            hashes = self._calculate_hashes(file_path)
            
            # Display hashes
            self._display_hashes(hashes)
            
            # Check against databases
            print_info("Checking against malware databases...")
            results = self._check_databases(hashes)
            
            # Display results
            self._display_results(results)
            
            # Save to database
            for hash_type, hash_value in hashes.items():
                self.db.add_hash(hash_type, hash_value, None, file_path)
            
            # Save to file if requested
            if output:
                self._save_results(file_path, hashes, results, output)
            
            return results
        
        except Exception as e:
            print_error(f"Hash check failed: {e}")
            return None
    
    def _calculate_hashes(self, file_path):
        """Calculate file hashes"""
        hashes = {}
        
        with open(file_path, 'rb') as f:
            content = f.read()
        
        hashes['md5'] = hashlib.md5(content).hexdigest()
        hashes['sha1'] = hashlib.sha1(content).hexdigest()
        hashes['sha256'] = hashlib.sha256(content).hexdigest()
        
        return hashes
    
    def _check_databases(self, hashes):
        """Check hashes against malware databases"""
        results = {
            'sha256': hashes.get('sha256'),
            'databases': {},
            'is_malicious': False
        }
        
        # Check VirusTotal (requires API key)
        vt_result = self._check_virustotal(hashes.get('sha256'))
        if vt_result:
            results['databases']['virustotal'] = vt_result
        
        # Check MalwareBazaar
        mb_result = self._check_malwarebazaar(hashes.get('sha256'))
        if mb_result:
            results['databases']['malwarebazaar'] = mb_result
        
        # Check HashInfo
        hi_result = self._check_hashinfo(hashes.get('md5'))
        if hi_result:
            results['databases']['hashinfo'] = hi_result
        
        return results
    
    def _check_virustotal(self, sha256):
        """Check hash against VirusTotal"""
        try:
            # Note: Requires API key for full functionality
            # This is a placeholder for the API integration
            print_info("  VirusTotal: API key required for full check")
            return None
        except:
            return None
    
    def _check_malwarebazaar(self, sha256):
        """Check hash against MalwareBazaar"""
        try:
            response = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data={'query': 'get_info', 'hash': sha256},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return {
                        'status': 'malicious',
                        'data': data.get('data', [{}])[0]
                    }
        except:
            pass
        
        return None
    
    def _check_hashinfo(self, md5):
        """Check hash against HashInfo"""
        try:
            response = requests.get(
                f'https://hashinfo.net/api/v1/{md5}',
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        return None
    
    def _display_hashes(self, hashes):
        """Display calculated hashes"""
        print_section("File Hashes")
        
        for algo, hash_val in hashes.items():
            cprint(f"    {algo.upper():<10} {hash_val}", Colors.BWHITE)
    
    def _display_results(self, results):
        """Display check results"""
        print_section("Malware Check Results")
        
        if not results.get('databases'):
            print_warning("No results from malware databases")
            print_info("File appears to be clean (not found in checked databases)")
            return
        
        for db_name, db_result in results['databases'].items():
            if db_result and db_result.get('status') == 'malicious':
                print_error(f"FOUND IN {db_name.upper()} - MALICIOUS!")
                if db_result.get('data'):
                    data = db_result['data']
                    if data.get('signature'):
                        cprint(f"      Signature: {data['signature']}", Colors.BRED)
                    if data.get('tags'):
                        cprint(f"      Tags: {', '.join(data['tags'])}", Colors.BRED)
            else:
                print_success(f"Not found in {db_name}")
    
    def _save_results(self, file_path, hashes, results, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'file': file_path,
                    'hashes': hashes,
                    'results': results
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
