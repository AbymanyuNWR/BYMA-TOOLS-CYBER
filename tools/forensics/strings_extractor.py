"""
BYMA TOOLS - Advanced Strings Extractor
Professional string extraction from binary files
"""
import re
import json
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class StringsExtractor:
    """Professional strings extractor for binary analysis"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    # String patterns
    STRING_PATTERNS = {
        'ascii': {
            'name': 'ASCII Strings',
            'min_length': 4,
            'pattern': rb'[\x20-\x7e]{4,}',
        },
        'unicode_le': {
            'name': 'Unicode (LE)',
            'min_length': 4,
            'pattern': rb'(?:[\x20-\x7e]\x00){4,}',
        },
        'unicode_be': {
            'name': 'Unicode (BE)',
            'min_length': 4,
            'pattern': rb'(?:\x00[\x20-\x7e]){4,}',
        },
    }
    
    # Interesting string patterns
    INTERESTING_PATTERNS = {
        'URLs': r'https?://[^\s<>"\']+',
        'IP Addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'Email Addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'File Paths': r'[A-Z]:\\[^\s<>"\']+|/[^\s<>"\']+',
        'Registry Keys': r'(?:HKLM|HKCU|HKEY_)[^\s<>"\']+',
        'Base64 Strings': r'[A-Za-z0-9+/]{20,}={0,2}',
        'Hex Strings': r'(?:0x)?[0-9a-fA-F]{16,}',
        'MAC Addresses': r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}',
        'Phone Numbers': r'(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}',
        'Dates': r'\d{4}[-/]\d{2}[-/]\d{2}',
    }
    
    # Command patterns
    COMMAND_PATTERNS = {
        'Shell Commands': r'\b(?:cmd|bash|sh|powershell|exec|eval|system|passthru|shell_exec)\b',
        'Network Commands': r'\b(?:curl|wget|nc|netcat|ssh|telnet|ftp|sftp)\b',
        'File Operations': r'\b(?:read|write|open|close|delete|copy|move|mkdir|rmdir)\b',
        'Crypto Keywords': r'\b(?:encrypt|decrypt|cipher|aes|rsa|md5|sha)\b',
        'Database Keywords': r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b',
    }
    
    def extract(self, file_path, min_length=4, output=None, analysis_mode='full'):
        """Main extract function"""
        print_section("STRINGS EXTRACTOR")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("strings_extract", str(file_path), "forensics")
        self.logger.scan_start("strings_extract", str(file_path))
        
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                print_error(f"File not found: {file_path}")
                return None
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}File:{Colors.BWHITE}         {file_path.name}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Min Length:{Colors.BWHITE}   {min_length}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Mode:{Colors.BWHITE}         {analysis_mode.upper()}")
            print_separator("-", 50)
            print()
            
            # Read file
            with open(file_path, 'rb') as f:
                content = f.read()
            
            print_info(f"File size: {len(content):,} bytes")
            print()
            
            # Extract strings
            print_subsection("Extracting Strings")
            strings = self._extract_strings(content, min_length)
            self._display_string_counts(strings)
            
            # Analyze strings
            if analysis_mode in ['full', 'analyze']:
                print_subsection("String Analysis")
                analysis = self._analyze_strings(strings)
                self._display_analysis(analysis)
            
            # Search for interesting patterns
            if analysis_mode in ['full', 'patterns']:
                print_subsection("Interesting Patterns")
                patterns = self._find_patterns(content)
                self._display_patterns(patterns)
            
            # Search for commands
            if analysis_mode in ['full', 'commands']:
                print_subsection("Command Detection")
                commands = self._find_commands(content)
                self._display_commands(commands)
            
            # Export strings
            if output:
                print_subsection("Exporting Strings")
                self._export_strings(strings, output)
            
            # Save to database
            self._save_to_database(scan_id, file_path, strings)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", sum(len(v) for v in strings.values()))
            self.logger.scan_complete("strings_extract", str(file_path), sum(len(v) for v in strings.values()))
            
            return strings
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("strings_extract", str(file_path), str(e))
            print_error(f"Extraction failed: {e}")
            return None
    
    def _extract_strings(self, content, min_length):
        """Extract strings from content"""
        strings = {}
        
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        strings['ascii'] = [s.decode('ascii', errors='ignore') for s in re.findall(ascii_pattern, content)]
        
        # Unicode LE strings
        unicode_le_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
        unicode_le = re.findall(unicode_le_pattern, content)
        strings['unicode_le'] = [s.decode('utf-16-le', errors='ignore') for s in unicode_le]
        
        # Unicode BE strings
        unicode_be_pattern = rb'(?:\x00[\x20-\x7e]){2,}'
        unicode_be = re.findall(unicode_be_pattern, content)
        strings['unicode_be'] = [s.decode('utf-16-be', errors='ignore') for s in unicode_be]
        
        return strings
    
    def _analyze_strings(self, strings):
        """Analyze extracted strings"""
        analysis = {
            'total': 0,
            'by_type': {},
            'unique': 0,
            'avg_length': 0,
            'longest': '',
            'shortest': '',
        }
        
        all_strings = []
        for string_list in strings.values():
            all_strings.extend(string_list)
        
        analysis['total'] = len(all_strings)
        
        # Count by type
        for stype, string_list in strings.items():
            analysis['by_type'][stype] = len(string_list)
        
        # Unique strings
        unique_strings = set(all_strings)
        analysis['unique'] = len(unique_strings)
        
        # Length statistics
        if all_strings:
            lengths = [len(s) for s in all_strings]
            analysis['avg_length'] = sum(lengths) / len(lengths)
            analysis['longest'] = max(all_strings, key=len)
            analysis['shortest'] = min(all_strings, key=len)
        
        return analysis
    
    def _find_patterns(self, content):
        """Find interesting patterns in content"""
        patterns = {}
        
        text = content.decode('utf-8', errors='ignore')
        
        for pattern_name, pattern in self.INTERESTING_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                patterns[pattern_name] = {
                    'count': len(matches),
                    'samples': list(set(matches))[:10],
                }
        
        return patterns
    
    def _find_commands(self, content):
        """Find command patterns in content"""
        commands = {}
        
        text = content.decode('utf-8', errors='ignore')
        
        for cmd_name, pattern in self.COMMAND_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Count unique matches
                unique_matches = {}
                for match in matches:
                    match_lower = match.lower()
                    unique_matches[match_lower] = unique_matches.get(match_lower, 0) + 1
                
                commands[cmd_name] = {
                    'count': len(matches),
                    'unique': len(unique_matches),
                    'top': sorted(unique_matches.items(), key=lambda x: x[1], reverse=True)[:10],
                }
        
        return commands
    
    def _display_string_counts(self, strings):
        """Display string counts"""
        print()
        for stype, string_list in strings.items():
            print(f"  {Colors.BCYAN}{stype.replace('_', ' ').title()}:{Colors.BWHITE} {len(string_list):,}")
        
        total = sum(len(v) for v in strings.values())
        print(f"  {Colors.BCYAN}Total:{Colors.BWHITE}    {total:,}")
        print()
    
    def _display_analysis(self, analysis):
        """Display analysis results"""
        print(f"  {Colors.BCYAN}Total Strings:{Colors.BWHITE}     {analysis['total']:,}")
        print(f"  {Colors.BCYAN}Unique Strings:{Colors.BWHITE}    {analysis['unique']:,}")
        print(f"  {Colors.BCYAN}Average Length:{Colors.BWHITE}    {analysis['avg_length']:.1f}")
        
        if analysis['longest']:
            print(f"  {Colors.BCYAN}Longest String:{Colors.BWHITE}   {analysis['longest'][:50]}...")
        
        print()
    
    def _display_patterns(self, patterns):
        """Display found patterns"""
        if patterns:
            for pattern_name, info in patterns.items():
                print(f"  {Colors.BYELLOW}{pattern_name}: {info['count']} found")
                
                # Show samples
                for sample in info['samples'][:5]:
                    print(f"    {Colors.BCYAN}{sample[:60]}")
        else:
            print_info("No interesting patterns found")
        
        print()
    
    def _display_commands(self, commands):
        """Display found commands"""
        if commands:
            for cmd_name, info in commands.items():
                print(f"  {Colors.BYELLOW}{cmd_name}: {info['count']} found ({info['unique']} unique)")
                
                # Show top commands
                for cmd, count in info['top'][:5]:
                    print(f"    {Colors.BCYAN}{cmd}: {count}")
        else:
            print_info("No command patterns found")
        
        print()
    
    def _export_strings(self, strings, output_file):
        """Export strings to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Export to text file
            txt_file = str(output_path).replace('.json', '.txt')
            with open(txt_file, 'w', encoding='utf-8') as f:
                for stype, string_list in strings.items():
                    f.write(f"=== {stype.upper()} ===\n")
                    for s in string_list:
                        f.write(f"{s}\n")
                    f.write("\n")
            
            print_success(f"Strings exported to {txt_file}")
        
        except Exception as e:
            print_error(f"Export failed: {e}")
    
    def _save_to_database(self, scan_id, file_path, strings):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                total = sum(len(v) for v in strings.values())
                cursor.execute("""
                    INSERT INTO scan_results 
                    (scan_id, result_type, result_data)
                    VALUES (?, ?, ?)
                """, (
                    scan_id,
                    'strings_extract',
                    json.dumps({
                        'file': str(file_path),
                        'total_strings': total,
                    })
                ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
