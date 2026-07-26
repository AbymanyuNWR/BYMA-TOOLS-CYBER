"""
BYMA TOOLS - Input Validator
Validasi semua input user
"""
import re
import os
from pathlib import Path


class ValidationError(Exception):
    """Custom exception untuk validation error"""
    pass


class Validator:
    """Validator untuk semua input"""
    
    @staticmethod
    def validate_ip(ip):
        """Validasi IP address"""
        ip_pattern = re.compile(
            r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        )
        match = ip_pattern.match(ip)
        if not match:
            raise ValidationError(f"Invalid IP address: {ip}")
        
        for octet in match.groups():
            if int(octet) > 255:
                raise ValidationError(f"Invalid IP address: {ip}")
        
        return True
    
    @staticmethod
    def validate_cidr(cidr):
        """Validasi CIDR notation"""
        if '/' in cidr:
            ip, mask = cidr.split('/')
            Validator.validate_ip(ip)
            if not mask.isdigit() or int(mask) > 32:
                raise ValidationError(f"Invalid CIDR mask: {mask}")
        else:
            Validator.validate_ip(cidr)
        return True
    
    @staticmethod
    def validate_domain(domain):
        """Validasi domain name"""
        domain_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        if not domain_pattern.match(domain):
            raise ValidationError(f"Invalid domain: {domain}")
        return True
    
    @staticmethod
    def validate_url(url):
        """Validasi URL"""
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(url):
            raise ValidationError(f"Invalid URL: {url}")
        return True
    
    @staticmethod
    def validate_port(port):
        """Validasi port number"""
        if isinstance(port, str):
            if '-' in port:
                start, end = port.split('-')
                start, end = int(start), int(end)
                if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                    raise ValidationError(f"Invalid port range: {port}")
                if start > end:
                    raise ValidationError(f"Invalid port range: start > end")
            else:
                port = int(port)
                if not (1 <= port <= 65535):
                    raise ValidationError(f"Invalid port: {port}")
        return True
    
    @staticmethod
    def validate_port_range(port_str):
        """Validasi port range string"""
        ports = []
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                start, end = int(start), int(end)
                if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                    raise ValidationError(f"Invalid port range: {part}")
                if start > end:
                    raise ValidationError(f"Invalid port range: {part}")
                ports.extend(range(start, end + 1))
            elif part.isdigit():
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValidationError(f"Invalid port: {port}")
                ports.append(port)
            else:
                raise ValidationError(f"Invalid port format: {part}")
        return ports
    
    @staticmethod
    def validate_hash(hash_str, expected_type=None):
        """Validasi hash string"""
        hash_patterns = {
            'md5': r'^[a-fA-F0-9]{32}$',
            'sha1': r'^[a-fA-F0-9]{40}$',
            'sha256': r'^[a-fA-F0-9]{64}$',
            'sha512': r'^[a-fA-F0-9]{128}$',
            'ntlm': r'^[a-fA-F0-9]{32}$',
        }
        
        if expected_type:
            pattern = hash_patterns.get(expected_type)
            if pattern and not re.match(pattern, hash_str):
                raise ValidationError(f"Invalid {expected_type} hash: {hash_str}")
        else:
            # Auto-detect hash type
            for hash_type, pattern in hash_patterns.items():
                if re.match(pattern, hash_str):
                    return hash_type
        
        raise ValidationError(f"Invalid hash format: {hash_str}")
    
    @staticmethod
    def validate_file_path(file_path):
        """Validasi file path"""
        path = Path(file_path)
        if not path.exists():
            raise ValidationError(f"File not found: {file_path}")
        if not path.is_file():
            raise ValidationError(f"Not a file: {file_path}")
        return True
    
    @staticmethod
    def validate_directory(dir_path):
        """Validasi directory path"""
        path = Path(dir_path)
        if not path.exists():
            raise ValidationError(f"Directory not found: {dir_path}")
        if not path.is_dir():
            raise ValidationError(f"Not a directory: {dir_path}")
        return True
    
    @staticmethod
    def validate_wordlist(wordlist_path):
        """Validasi wordlist file"""
        Validator.validate_file_path(wordlist_path)
        path = Path(wordlist_path)
        if path.stat().st_size == 0:
            raise ValidationError(f"Empty wordlist: {wordlist_path}")
        return True
    
    @staticmethod
    def validate_email(email):
        """Validasi email address"""
        email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        if not email_pattern.match(email):
            raise ValidationError(f"Invalid email: {email}")
        return True
    
    @staticmethod
    def validate_username(username):
        """Validasi username"""
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters")
        if len(username) > 32:
            raise ValidationError("Username must be at most 32 characters")
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            raise ValidationError("Username can only contain alphanumeric, underscore, and hyphen")
        return True
    
    @staticmethod
    def validate_threads(threads):
        """Validasi thread count"""
        if not isinstance(threads, int):
            threads = int(threads)
        if threads < 1:
            raise ValidationError("Threads must be at least 1")
        if threads > 200:
            raise ValidationError("Threads must be at most 200")
        return True
    
    @staticmethod
    def validate_timeout(timeout):
        """Validasi timeout"""
        if not isinstance(timeout, (int, float)):
            timeout = float(timeout)
        if timeout < 1:
            raise ValidationError("Timeout must be at least 1 second")
        if timeout > 60:
            raise ValidationError("Timeout must be at most 60 seconds")
        return True
    
    @staticmethod
    def validate_target(target):
        """Validasi target (bisa IP, domain, atau URL)"""
        # Check if it's a URL
        if target.startswith(('http://', 'https://')):
            Validator.validate_url(target)
            return 'url'
        
        # Check if it's a CIDR
        if '/' in target:
            Validator.validate_cidr(target)
            return 'cidr'
        
        # Check if it's an IP
        parts = target.split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            Validator.validate_ip(target)
            return 'ip'
        
        # Check if it's a domain
        try:
            Validator.validate_domain(target)
            return 'domain'
        except ValidationError:
            pass
        
        raise ValidationError(f"Invalid target: {target}")


# Singleton instance
validator = Validator()


def get_validator():
    """Get validator instance"""
    return validator
