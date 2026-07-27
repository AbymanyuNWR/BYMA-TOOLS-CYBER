"""
BYMA TOOLS - Advanced Password Generator
Professional password generation with customization
"""
import random
import string
import json
import hashlib
import secrets
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class PasswordGenerator:
    """Professional password generator with advanced features"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.generated_passwords = []
    
    # Character sets
    CHARSETS = {
        'lowercase': string.ascii_lowercase,
        'uppercase': string.ascii_uppercase,
        'digits': string.digits,
        'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?',
        'extended': string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?',
    }
    
    # Common patterns
    PATTERNS = {
        'alphanumeric': string.ascii_letters + string.digits,
        'alpha_special': string.ascii_letters + '!@#$%^&*',
        'numeric_only': string.digits,
        'memorable': 'abcdefghjkmnpqrstuvwxyz23456789',  # Excludes confusing chars
    }
    
    # Password strength criteria
    STRENGTH_CRITERIA = {
        'length': {
            'weak': 6,
            'medium': 8,
            'strong': 12,
            'very_strong': 16,
        },
        'complexity': {
            'lowercase': 1,
            'uppercase': 1,
            'digits': 1,
            'symbols': 1,
        },
    }
    
    def generate(self, count=1, length=16, mode='random', charset=None, 
                 exclude=None, output=None, **kwargs):
        """Main password generation function"""
        print_section("PASSWORD GENERATOR")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("password_gen", f"count={count}", "password")
        self.logger.scan_start("password_gen", f"count={count}")
        
        try:
            print(f"  {Icons.INFO} {Colors.BCYAN}Count:{Colors.BWHITE}       {count}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Length:{Colors.BWHITE}      {length}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Mode:{Colors.BWHITE}        {mode.upper()}")
            if charset:
                print(f"  {Icons.INFO} {Colors.BCYAN}Charset:{Colors.BWHITE}     Custom")
            if exclude:
                print(f"  {Icons.INFO} {Colors.BCYAN}Exclude:{Colors.BWHITE}     {exclude}")
            print_separator("-", 50)
            print()
            
            # Generate passwords
            for i in range(count):
                if mode == 'random':
                    password = self._generate_random(length, charset, exclude)
                elif mode == 'memorable':
                    password = self._generate_memorable(length)
                elif mode == 'pin':
                    password = self._generate_pin(length)
                elif mode == 'passphrase':
                    password = self._generate_passphrase(length)
                elif mode == 'pronounceable':
                    password = self._generate_pronounceable(length)
                elif mode == 'pattern':
                    password = self._generate_pattern(kwargs.get('pattern', 'LlLlLlLl'), length)
                else:
                    password = self._generate_random(length, charset, exclude)
                
                # Calculate strength
                strength = self._calculate_strength(password)
                
                self.generated_passwords.append({
                    'password': password,
                    'strength': strength,
                    'length': len(password),
                })
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", count)
            self.logger.scan_complete("password_gen", f"count={count}", count)
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.generated_passwords
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("password_gen", f"count={count}", str(e))
            print_error(f"Generation failed: {e}")
            return []
    
    def _generate_random(self, length, charset=None, exclude=None):
        """Generate random password"""
        if charset:
            chars = charset
        else:
            chars = self.CHARSETS['extended']
        
        if exclude:
            chars = ''.join(c for c in chars if c not in exclude)
        
        # Use secrets for cryptographically secure random
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def _generate_memorable(self, length=12):
        """Generate memorable password"""
        # Common word parts
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowels = 'aeiou'
        
        password = []
        
        for i in range(length):
            if i % 3 == 0:
                password.append(secrets.choice(consonants))
            elif i % 3 == 1:
                password.append(secrets.choice(vowels))
            else:
                password.append(secrets.choice(string.digits))
        
        return ''.join(password)
    
    def _generate_pin(self, length=6):
        """Generate PIN code"""
        return ''.join(secrets.choice(string.digits) for _ in range(length))
    
    def _generate_passphrase(self, word_count=4):
        """Generate passphrase"""
        # Common words (simplified)
        words = [
            'correct', 'horse', 'battery', 'staple', 'quick', 'brown',
            'fox', 'jumps', 'over', 'lazy', 'dog', 'hello', 'world',
            'computer', 'keyboard', 'monitor', 'screen', 'mouse',
            'keyboard', 'security', 'password', 'network', 'system',
            'admin', 'user', 'guest', 'root', 'master',
        ]
        
        selected_words = [secrets.choice(words) for _ in range(word_count)]
        
        # Capitalize first letter of each word
        passphrase = ''.join(word.capitalize() for word in selected_words)
        
        # Add number and symbol
        passphrase += secrets.choice(string.digits)
        passphrase += secrets.choice('!@#$%^&*')
        
        return passphrase
    
    def _generate_pronounceable(self, length=12):
        """Generate pronounceable password"""
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowels = 'aeiou'
        
        password = []
        use_consonant = True
        
        for _ in range(length):
            if use_consonant:
                password.append(secrets.choice(consonants))
            else:
                password.append(secrets.choice(vowels))
            use_consonant = not use_consonant
        
        # Capitalize some letters
        password = [c.upper() if i % 4 == 0 else c for i, c in enumerate(password)]
        
        # Add numbers
        password.append(secrets.choice(string.digits))
        password.append(secrets.choice(string.digits))
        
        return ''.join(password)
    
    def _generate_pattern(self, pattern, length=16):
        """Generate password from pattern"""
        pattern_map = {
            'L': string.ascii_uppercase,
            'l': string.ascii_lowercase,
            'd': string.digits,
            's': '!@#$%^&*',
            'x': string.ascii_letters + string.digits,
        }
        
        password = []
        pattern_length = len(pattern)
        
        for i in range(length):
            pattern_char = pattern[i % pattern_length] if pattern_length > 0 else 'x'
            
            if pattern_char in pattern_map:
                password.append(secrets.choice(pattern_map[pattern_char]))
            else:
                password.append(pattern_char)
        
        return ''.join(password)
    
    def _calculate_strength(self, password):
        """Calculate password strength"""
        strength = 0
        criteria = []
        
        # Length check
        if len(password) >= 16:
            strength += 4
            criteria.append('length_16+')
        elif len(password) >= 12:
            strength += 3
            criteria.append('length_12+')
        elif len(password) >= 8:
            strength += 2
            criteria.append('length_8+')
        else:
            strength += 1
            criteria.append('length_short')
        
        # Character variety
        if any(c in string.ascii_lowercase for c in password):
            strength += 1
            criteria.append('lowercase')
        
        if any(c in string.ascii_uppercase for c in password):
            strength += 1
            criteria.append('uppercase')
        
        if any(c in string.digits for c in password):
            strength += 1
            criteria.append('digits')
        
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            strength += 1
            criteria.append('symbols')
        
        # Unique characters
        unique_ratio = len(set(password)) / len(password)
        if unique_ratio > 0.8:
            strength += 1
            criteria.append('unique_chars')
        
        # No common patterns
        common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
        if not any(pattern in password.lower() for pattern in common_patterns):
            strength += 1
            criteria.append('no_patterns')
        
        # Determine strength level
        if strength >= 8:
            level = 'VERY STRONG'
            color = Colors.BGREEN
        elif strength >= 6:
            level = 'STRONG'
            color = Colors.BGREEN
        elif strength >= 4:
            level = 'MEDIUM'
            color = Colors.BYELLOW
        elif strength >= 2:
            level = 'WEAK'
            color = Colors.RED
        else:
            level = 'VERY WEAK'
            color = Colors.BRED
        
        return {
            'score': strength,
            'level': level,
            'color': color,
            'criteria': criteria,
        }
    
    def _display_results(self):
        """Display generated passwords"""
        print_section("GENERATED PASSWORDS")
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}GENERATION SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Total:{Colors.BWHITE}         {len(self.generated_passwords)}")
        
        # Strength distribution
        strengths = {}
        for p in self.generated_passwords:
            level = p['strength']['level']
            strengths[level] = strengths.get(level, 0) + 1
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Strength Distribution:{Colors.BWHITE}")
        for level, count in sorted(strengths.items()):
            print(f"       {level}: {count}")
        
        print_separator("-", 50)
        print()
        
        # Display passwords
        print_subsection("Passwords")
        
        table_data = [["#", "Password", "Length", "Strength"]]
        for i, p in enumerate(self.generated_passwords, 1):
            # Mask password for display
            masked = p['password'][:3] + '*' * (len(p['password']) - 3)
            table_data.append([
                str(i),
                masked,
                str(p['length']),
                p['strength']['level'],
            ])
        
        print_table(table_data)
        print()
        
        # Show full passwords
        print_subsection("Full Passwords (Copy These)")
        for i, p in enumerate(self.generated_passwords, 1):
            cprint(f"  {i}. {p['password']}", Colors.BWHITE)
        print()
        
        # Security tips
        print_subsection("Security Tips")
        print_info("- Never reuse passwords across accounts")
        print_info("- Use a password manager")
        print_info("- Enable two-factor authentication")
        print_info("- Change passwords regularly")
        print()
    
    def _save_to_database(self, scan_id):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                for p in self.generated_passwords:
                    # Store hash of password for security
                    pwd_hash = hashlib.sha256(p['password'].encode()).hexdigest()
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, result_type, result_data)
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        'generated_password',
                        json.dumps({
                            'hash': pwd_hash,
                            'strength': p['strength']['level'],
                            'length': p['length'],
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
                'generated_time': datetime.now().isoformat(),
                'total': len(self.generated_passwords),
                'passwords': [
                    {
                        'password': p['password'],
                        'strength': p['strength']['level'],
                        'length': p['length'],
                    }
                    for p in self.generated_passwords
                ],
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
