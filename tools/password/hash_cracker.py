"""
BYMA TOOLS - Hash Cracker
Tools untuk cracking password hash
"""
import hashlib
import json
from pathlib import Path
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class HashCracker:
    """Hash cracking using dictionary attack"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    def hash_text(self, text, algorithm='md5'):
        """Generate hash from text"""
        print_section(f"Hash Generator")
        
        print_info(f"Text: {text}")
        print_info(f"Algorithm: {algorithm}")
        print()
        
        # Generate hash
        hash_obj = self._get_hash(text, algorithm)
        
        if hash_obj:
            print_success(f"Hash ({algorithm.upper()}):")
            cprint(f"    {hash_obj}", Colors.BWHITE)
            
            # Save to database
            self.db.add_hash(algorithm, hash_obj, text, "generated")
            
            return hash_obj
        
        return None
    
    def crack(self, target_hash, algorithm, wordlist=None, output=None):
        """Crack hash using dictionary attack"""
        print_section(f"Hash Cracker")
        
        print_info(f"Target Hash: {target_hash}")
        print_info(f"Algorithm: {algorithm}")
        
        # Load wordlist
        words = self._load_wordlist(wordlist)
        print_info(f"Wordlist: {len(words)} words")
        print()
        
        # Try to crack
        print_info("Cracking hash...")
        result = self._dictionary_attack(target_hash, algorithm, words)
        
        if result:
            print_success(f"Hash cracked!")
            print()
            cprint(f"    Hash: {target_hash}", Colors.BWHITE)
            cprint(f"    Password: {result}", Colors.BGREEN)
            
            # Save to database
            self.db.add_hash(algorithm, target_hash, result, "cracked")
            
            if output:
                self._save_result(target_hash, result, output)
            
            return result
        else:
            print_warning("Could not crack hash with provided wordlist")
            self.db.add_hash(algorithm, target_hash, None, "uncracked")
            return None
    
    def _get_hash(self, text, algorithm):
        """Generate hash for text"""
        text_bytes = text.encode('utf-8')
        
        if algorithm == 'md5':
            return hashlib.md5(text_bytes).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(text_bytes).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(text_bytes).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(text_bytes).hexdigest()
        else:
            print_error(f"Unsupported algorithm: {algorithm}")
            return None
    
    def _load_wordlist(self, wordlist_path):
        """Load wordlist from file"""
        if wordlist_path and Path(wordlist_path).exists():
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        
        # Default wordlist
        return self._get_default_wordlist()
    
    def _get_default_wordlist(self):
        """Get default password wordlist"""
        return [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', 'master', 'dragon', 'login', 'princess',
            'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou',
            'batman', 'access', 'hello', 'charlie', 'letmein',
            'welcome', 'password1', 'password123', 'admin', 'admin123',
            'root', 'toor', 'pass', 'test', 'guest', 'master',
            'changeme', 'secret', '123456789', '1234567890',
            'qwerty123', '1q2w3e4r', '654321', '555555', 'lovely',
            '7777777', '123123', '666666', 'qwertyuiop', '123321',
            'mustang', '121212', '000000', 'amanda', 'love',
            'ashley', 'bailey', 'passw0rd', 'master123', 'superman',
            'michael', 'football1', 'shadow1', 'monkey1', 'dragon1'
        ]
    
    def _dictionary_attack(self, target_hash, algorithm, words):
        """Perform dictionary attack"""
        for word in tqdm(words, desc="    Cracking"):
            # Try word as-is
            if self._check_hash(target_hash, word, algorithm):
                return word
            
            # Try word in lowercase
            if self._check_hash(target_hash, word.lower(), algorithm):
                return word.lower()
            
            # Try word with capital first letter
            if self._check_hash(target_hash, word.capitalize(), algorithm):
                return word.capitalize()
            
            # Try word with numbers appended
            for num in ['1', '12', '123', '!', '@', '#']:
                if self._check_hash(target_hash, word + num, algorithm):
                    return word + num
        
        return None
    
    def _check_hash(self, target_hash, word, algorithm):
        """Check if word produces target hash"""
        word_hash = self._get_hash(word, algorithm)
        return word_hash and word_hash.lower() == target_hash.lower()
    
    def _save_result(self, target_hash, password, output_file):
        """Save result to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'hash': target_hash,
                    'password': password
                }, f, indent=2)
            
            print_success(f"Result saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save result: {e}")
