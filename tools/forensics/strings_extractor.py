"""
BYMA TOOLS - Strings Extractor
Tools untuk mengekstrak strings dari file binary
"""
import re
import json
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger


class StringsExtractor:
    """Extract strings from binary files"""
    
    def __init__(self):
        self.logger = get_logger()
    
    def extract(self, file_path, min_length=4, output=None):
        """Extract strings from file"""
        print_section(f"Strings Extractor: {file_path}")
        
        if not Path(file_path).exists():
            print_error(f"File not found: {file_path}")
            return []
        
        try:
            print_info(f"Minimum string length: {min_length}")
            print()
            
            # Read file as binary
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Extract ASCII strings
            print_info("Extracting ASCII strings...")
            ascii_strings = self._extract_ascii(content, min_length)
            
            # Extract Unicode strings
            print_info("Extracting Unicode strings...")
            unicode_strings = self._extract_unicode(content, min_length)
            
            # Combine and deduplicate
            all_strings = list(set(ascii_strings + unicode_strings))
            
            # Display results
            self._display_results(all_strings, min_length)
            
            # Save to file if requested
            if output:
                self._save_results(file_path, all_strings, output)
            
            return all_strings
        
        except Exception as e:
            print_error(f"Strings extraction failed: {e}")
            return []
    
    def _extract_ascii(self, content, min_length):
        """Extract ASCII strings"""
        # Match printable ASCII characters
        pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        matches = re.findall(pattern, content)
        return [m.decode('ascii', errors='ignore') for m in matches]
    
    def _extract_unicode(self, content, min_length):
        """Extract Unicode strings"""
        # Match Unicode (UTF-16 LE) strings
        pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        matches = re.findall(pattern, content)
        strings = []
        for m in matches:
            try:
                decoded = m.decode('utf-16-le', errors='ignore')
                if len(decoded) >= min_length:
                    strings.append(decoded)
            except:
                pass
        return strings
    
    def _display_results(self, strings, min_length):
        """Display extracted strings"""
        print_section("Extracted Strings")
        
        if not strings:
            print_warning("No strings found")
            return
        
        print_success(f"Found {len(strings)} strings:")
        print()
        
        # Categorize strings
        urls = [s for s in strings if s.startswith(('http://', 'https://'))]
        emails = [s for s in strings if '@' in s and '.' in s]
        ips = [s for s in strings if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)]
        paths = [s for s in strings if '/' in s and ('.' in s or '..' in s)]
        other = [s for s in strings if s not in urls + emails + ips + paths]
        
        # Display URLs
        if urls:
            cprint(f"    {'URLs:':<20}", Colors.BCYAN)
            for url in urls[:20]:
                cprint(f"      {url[:80]}", Colors.BWHITE)
        
        # Display emails
        if emails:
            print()
            cprint(f"    {'Emails:':<20}", Colors.BCYAN)
            for email in emails[:20]:
                cprint(f"      {email}", Colors.BWHITE)
        
        # Display IPs
        if ips:
            print()
            cprint(f"    {'IP Addresses:':<20}", Colors.BCYAN)
            for ip in ips[:20]:
                cprint(f"      {ip}", Colors.BWHITE)
        
        # Display paths
        if paths:
            print()
            cprint(f"    {'File Paths:':<20}", Colors.BCYAN)
            for path in paths[:20]:
                cprint(f"      {path[:80]}", Colors.BWHITE)
        
        # Display other strings
        if other:
            print()
            cprint(f"    {'Other Strings:':<20}", Colors.BCYAN)
            for s in other[:50]:
                cprint(f"      {s[:80]}", Colors.BWHITE)
            if len(other) > 50:
                cprint(f"      ... and {len(other) - 50} more", Colors.BBLACK)
    
    def _save_results(self, file_path, strings, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'file': file_path,
                    'strings': strings,
                    'total': len(strings)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
