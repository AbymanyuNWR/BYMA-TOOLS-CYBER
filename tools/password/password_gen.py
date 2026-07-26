"""
BYMA TOOLS - Password Generator
Tools untuk generate password acak
"""
import random
import string
import json
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger


class PasswordGenerator:
    """Password generator with various options"""
    
    def __init__(self):
        self.logger = get_logger()
    
    def generate(self, length=12, count=1, use_upper=True, use_lower=True,
                 use_digits=True, use_special=True, output=None):
        """Generate random passwords"""
        print_section("Password Generator")
        
        print_info(f"Length: {length}")
        print_info(f"Count: {count}")
        print_info(f"Uppercase: {use_upper}")
        print_info(f"Lowercase: {use_lower}")
        print_info(f"Digits: {use_digits}")
        print_info(f"Special: {use_special}")
        print()
        
        # Build character set
        chars = ''
        if use_lower:
            chars += string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if not chars:
            print_error("No character set selected")
            return []
        
        # Generate passwords
        passwords = []
        for i in range(count):
            password = self._generate_password(length, chars)
            passwords.append(password)
        
        # Display passwords
        print_success(f"Generated {count} password(s):")
        print()
        
        for i, password in enumerate(passwords, 1):
            strength = self._calculate_strength(password)
            color = {
                'Very Weak': Colors.BRED,
                'Weak': Colors.RED,
                'Fair': Colors.BYELLOW,
                'Strong': Colors.BGREEN,
                'Very Strong': Colors.BGREEN
            }.get(strength['level'], Colors.BWHITE)
            
            cprint(f"    {i}. {password:<30} Strength: {strength['level']} ({strength['score']}/100)", color)
        
        print()
        
        # Calculate entropy
        entropy = self._calculate_entropy(length, len(chars))
        print_info(f"Entropy: {entropy:.2f} bits")
        
        # Save to file if requested
        if output:
            self._save_passwords(passwords, output)
        
        return passwords
    
    def _generate_password(self, length, chars):
        """Generate single password"""
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _calculate_strength(self, password):
        """Calculate password strength"""
        score = 0
        length = len(password)
        
        # Length score
        if length >= 8:
            score += 25
        if length >= 12:
            score += 25
        if length >= 16:
            score += 25
        
        # Character variety
        if any(c in string.ascii_lowercase for c in password):
            score += 5
        if any(c in string.ascii_uppercase for c in password):
            score += 5
        if any(c in string.digits for c in password):
            score += 5
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            score += 10
        
        # Determine level
        if score < 20:
            level = 'Very Weak'
        elif score < 40:
            level = 'Weak'
        elif score < 60:
            level = 'Fair'
        elif score < 80:
            level = 'Strong'
        else:
            level = 'Very Strong'
        
        return {'score': min(score, 100), 'level': level}
    
    def _calculate_entropy(self, length, charset_size):
        """Calculate password entropy"""
        import math
        return length * math.log2(charset_size)
    
    def _save_passwords(self, passwords, output_file):
        """Save passwords to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'passwords': passwords,
                    'count': len(passwords)
                }, f, indent=2)
            
            print_success(f"Passwords saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save passwords: {e}")
