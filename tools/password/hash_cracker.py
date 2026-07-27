"""
BYMA TOOLS - Advanced Hash Cracker
Professional hash cracking with multiple attack modes
"""
import hashlib
import hmac
import json
import itertools
import string
import time
import os
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class HashCracker:
    """Professional hash cracker with multiple attack modes"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.start_time = None
        self.cracked = False
        self.attempts = 0
        self.hashes_per_second = 0
    
    # Common hash patterns
    HASH_PATTERNS = {
        'MD5': (32, '^[a-f0-9]{32}$'),
        'SHA1': (40, '^[a-f0-9]{40}$'),
        'SHA256': (64, '^[a-f0-9]{64}$'),
        'SHA384': (96, '^[a-f0-9]{96}$'),
        'SHA512': (128, '^[a-f0-9]{128}$'),
        'NTLM': (32, '^[a-f0-9]{32}$'),
        'MySQL': (40, '^[a-f0-9]{40}$'),
        'MD5crypt': (34, '^\$1\$'),
        'SHA256crypt': (14, '^\$5\$'),
        'SHA512crypt': (14, '^\$6\$'),
        'Bcrypt': (60, '^\$2[aby]?\$'),
        'Blowfish': (60, '^\$2[aby]?\$'),
        'Drupal': (35, '^\$S\$'),
        'Wordpress': (34, '^\$P\$'),
        'PHPass': (34, '^\$[HPB]\$'),
    }
    
    # Common wordlists
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
        'dragon', 'login', 'princess', 'football', 'shadow', 'sunshine', 'trustno1',
        'iloveyou', 'batman', 'access', 'hello', 'charlie', 'donald', 'password1',
        'qwerty123', 'letmein', 'welcome', 'admin', 'admin123', 'root', 'toor',
        'pass', 'test', 'guest', 'master', 'changeme', 'secret', 'passw0rd',
        '123456789', '1234567890', '12345678901', '123456789012', '1234567890123',
        'password123', 'password1234', 'password12345', 'password123456',
        'qwerty1234', 'qwerty12345', 'qwerty123456',
        'abc12345', 'abc123456', 'abc1234567',
    ]
    
    def crack(self, hash_value, hash_type=None, wordlist=None, mode='dictionary', 
              output=None, max_length=8, charset=None):
        """Main hash crack function"""
        self.start_time = datetime.now()
        self.cracked = False
        self.attempts = 0
        
        print_section("HASH CRACKER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("hash_crack", hash_value[:20], "password")
        self.logger.scan_start("hash_crack", hash_value[:20])
        
        try:
            # Detect hash type
            if not hash_type:
                hash_type = self._detect_hash_type(hash_value)
                if hash_type:
                    print_info(f"Detected hash type: {hash_type}")
                else:
                    print_warning("Could not detect hash type")
                    hash_type = 'MD5'
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}Hash:{Colors.BWHITE}         {hash_value[:50]}...")
            print(f"  {Icons.INFO} {Colors.BCYAN}Type:{Colors.BWHITE}         {hash_type}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Mode:{Colors.BWHITE}         {mode.upper()}")
            print_separator("-", 50)
            print()
            
            # Start cracking
            if mode == 'dictionary':
                self._dictionary_attack(hash_value, hash_type, wordlist)
            elif mode == 'bruteforce':
                self._bruteforce_attack(hash_value, hash_type, max_length, charset)
            elif mode == 'hybrid':
                self._hybrid_attack(hash_value, hash_type, wordlist, max_length)
            elif mode == 'rainbow':
                self._rainbow_table_lookup(hash_value, hash_type)
            else:
                self._dictionary_attack(hash_value, hash_type, wordlist)
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", self.attempts)
            self.logger.scan_complete("hash_crack", hash_value[:20], self.attempts)
            
            # Save to file if requested
            if output:
                self._save_results(output, hash_value)
            
            return self.cracked
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("hash_crack", hash_value[:20], str(e))
            print_error(f"Cracking failed: {e}")
            return False
    
    def _detect_hash_type(self, hash_value):
        """Detect hash type from value"""
        import re
        
        hash_value = hash_value.strip()
        
        # Check for specific prefixes
        if hash_value.startswith('$1$'):
            return 'MD5crypt'
        elif hash_value.startswith('$5$'):
            return 'SHA256crypt'
        elif hash_value.startswith('$6$'):
            return 'SHA512crypt'
        elif hash_value.startswith(('$2a$', '$2b$', '$2y$')):
            return 'Bcrypt'
        elif hash_value.startswith('$P$'):
            return 'Wordpress'
        elif hash_value.startswith('$H$'):
            return 'PHPass'
        elif hash_value.startswith('$S$'):
            return 'Drupal'
        
        # Check length
        length = len(hash_value)
        
        for htype, (expected_len, pattern) in self.HASH_PATTERNS.items():
            if length == expected_len:
                if re.match(pattern, hash_value):
                    return htype
        
        # Default based on length
        if length == 32:
            return 'MD5'
        elif length == 40:
            return 'SHA1'
        elif length == 64:
            return 'SHA256'
        elif length == 96:
            return 'SHA384'
        elif length == 128:
            return 'SHA512'
        
        return None
    
    def _dictionary_attack(self, hash_value, hash_type, wordlist=None):
        """Dictionary attack"""
        print_subsection("Dictionary Attack")
        
        # Build wordlist
        words = []
        
        if wordlist and os.path.exists(wordlist):
            print_info(f"Loading wordlist: {wordlist}")
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            print_info(f"Loaded {len(words)} words")
        else:
            print_info("Using built-in password list")
            words = self.COMMON_PASSWORDS
        
        print_info(f"Testing {len(words)} passwords...")
        print()
        
        start_time = time.time()
        
        for word in words:
            if self.cracked:
                break
            
            self.attempts += 1
            
            # Test word
            if self._test_password(hash_value, word, hash_type):
                self.cracked = True
                self.hashes_per_second = self.attempts / (time.time() - start_time)
                print()
                print_success(f"Password cracked: {word}")
                return
            
            # Display progress
            if self.attempts % 1000 == 0:
                elapsed = time.time() - start_time
                rate = self.attempts / elapsed if elapsed > 0 else 0
                cprint(f"  Attempts: {self.attempts:,} | Rate: {rate:.0f} h/s", Colors.BWHITE)
        
        if not self.cracked:
            print()
            print_warning("Password not found in dictionary")
    
    def _bruteforce_attack(self, hash_value, hash_type, max_length=8, charset=None):
        """Bruteforce attack"""
        print_subsection("Bruteforce Attack")
        
        if not charset:
            charset = string.ascii_lowercase + string.digits
        
        print_info(f"Charset: {charset}")
        print_info(f"Max length: {max_length}")
        print()
        
        start_time = time.time()
        
        for length in range(1, max_length + 1):
            if self.cracked:
                break
            
            print_info(f"Testing length {length}...")
            
            for combo in itertools.product(charset, repeat=length):
                if self.cracked:
                    break
                
                word = ''.join(combo)
                self.attempts += 1
                
                if self._test_password(hash_value, word, hash_type):
                    self.cracked = True
                    self.hashes_per_second = self.attempts / (time.time() - start_time)
                    print()
                    print_success(f"Password cracked: {word}")
                    return
                
                if self.attempts % 10000 == 0:
                    elapsed = time.time() - start_time
                    rate = self.attempts / elapsed if elapsed > 0 else 0
                    cprint(f"  Attempts: {self.attempts:,} | Rate: {rate:.0f} h/s", Colors.BWHITE)
        
        if not self.cracked:
            print()
            print_warning("Password not found with bruteforce")
    
    def _hybrid_attack(self, hash_value, hash_type, wordlist=None, max_length=8):
        """Hybrid attack (dictionary + mutations)"""
        print_subsection("Hybrid Attack")
        
        # Load base words
        words = self.COMMON_PASSWORDS
        if wordlist and os.path.exists(wordlist):
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        
        print_info(f"Base words: {len(words)}")
        print_info("Applying mutations...")
        print()
        
        start_time = time.time()
        mutations = []
        
        # Generate mutations
        for word in words:
            # Original
            mutations.append(word)
            
            # Capitalize
            mutations.append(word.capitalize())
            
            # Uppercase
            mutations.append(word.upper())
            
            # Reverse
            mutations.append(word[::-1])
            
            # Add numbers
            for i in range(10):
                mutations.append(f"{word}{i}")
                mutations.append(f"{i}{word}")
            
            # Add symbols
            for sym in ['!', '@', '#', '$', '%']:
                mutations.append(f"{word}{sym}")
                mutations.append(f"{sym}{word}")
        
        print_info(f"Total mutations: {len(mutations)}")
        print()
        
        for word in mutations:
            if self.cracked:
                break
            
            self.attempts += 1
            
            if self._test_password(hash_value, word, hash_type):
                self.cracked = True
                self.hashes_per_second = self.attempts / (time.time() - start_time)
                print()
                print_success(f"Password cracked: {word}")
                return
            
            if self.attempts % 10000 == 0:
                elapsed = time.time() - start_time
                rate = self.attempts / elapsed if elapsed > 0 else 0
                cprint(f"  Attempts: {self.attempts:,} | Rate: {rate:.0f} h/s", Colors.BWHITE)
        
        if not self.cracked:
            print()
            print_warning("Password not found with hybrid attack")
    
    def _rainbow_table_lookup(self, hash_value, hash_type):
        """Rainbow table lookup (simulated)"""
        print_subsection("Rainbow Table Lookup")
        
        print_info("Rainbow tables provide instant lookups but require pre-computed tables")
        print_info("This is a simulated lookup for demonstration")
        print()
        
        # In a real implementation, you'd load rainbow tables
        # For now, we'll do a quick dictionary check
        self._dictionary_attack(hash_value, hash_type, None)
    
    def _test_password(self, hash_value, password, hash_type):
        """Test if password matches hash"""
        password_bytes = password.encode('utf-8')
        
        if hash_type == 'MD5':
            computed = hashlib.md5(password_bytes).hexdigest()
        elif hash_type == 'SHA1':
            computed = hashlib.sha1(password_bytes).hexdigest()
        elif hash_type == 'SHA256':
            computed = hashlib.sha256(password_bytes).hexdigest()
        elif hash_type == 'SHA384':
            computed = hashlib.sha384(password_bytes).hexdigest()
        elif hash_type == 'SHA512':
            computed = hashlib.sha512(password_bytes).hexdigest()
        elif hash_type == 'NTLM':
            computed = hashlib.new('md4', password_bytes).hexdigest()
        else:
            computed = hashlib.md5(password_bytes).hexdigest()
        
        return computed.lower() == hash_value.lower()
    
    def _display_results(self):
        """Display cracking results"""
        print_section("HASH CRACK RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}CRACK SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Attempts:{Colors.BWHITE}      {self.attempts:,}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}         {elapsed:.1f}s")
        print(f"  {Icons.INFO} {Colors.BCYAN}Rate:{Colors.BWHITE}         {self.hashes_per_second:.0f} h/s")
        print(f"  {Icons.INFO} {Colors.BCYAN}Result:{Colors.BWHITE}       {'CRACKED' if self.cracked else 'NOT CRACKED'}")
        
        print_separator("-", 50)
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
                    'hash_crack_result',
                    json.dumps({
                        'cracked': self.cracked,
                        'attempts': self.attempts,
                        'hashes_per_second': self.hashes_per_second,
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
                'scan_time': self.start_time.isoformat(),
                'hash': hash_value,
                'cracked': self.cracked,
                'attempts': self.attempts,
                'hashes_per_second': self.hashes_per_second,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
