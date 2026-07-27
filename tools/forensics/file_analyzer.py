"""
BYMA TOOLS - Advanced File Analyzer
Professional file analysis for digital forensics
"""
import os
import json
import hashlib
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
import struct
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class FileAnalyzer:
    """Professional file analyzer for digital forensics"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    # Magic numbers for common file types
    MAGIC_NUMBERS = {
        '4d5a': 'EXE/DLL (MZ)',
        '504b0304': 'ZIP Archive',
        '52617221': 'RAR Archive',
        '377abcaf': '7-Zip Archive',
        '1f8b': 'GZIP Archive',
        '425a68': 'BZIP2 Archive',
        'fd377a585a00': 'XZ Archive',
        '89504e47': 'PNG Image',
        'ffd8ff': 'JPEG Image',
        '47494638': 'GIF Image',
        '52494646': 'RIFF (WEBP)',
        '25504446': 'PDF Document',
        'd0cf11e0': 'OLE2 (DOC/XLS)',
        '504b0304': 'Office Open XML (DOCX/XLSX)',
        '4f676753': 'OGG Audio/Video',
        '664c6143': 'FLAC Audio',
        '494433': 'MP3 Audio',
        '0000001c': 'ISO Base Media',
        '66747970': 'MP4 Video',
        '1a45dfa3': 'MKV/WebM Video',
        '49492a00': 'TIFF Image',
        '4d4d002a': 'TIFF Image',
        '424d': 'BMP Image',
        '4344303031': 'ISO 9660',
        'efbbbf': 'UTF-8 BOM',
        'fffe': 'UTF-16 LE BOM',
        'feff': 'UTF-16 BE BOM',
    }
    
    # Common file extensions
    FILE_EXTENSIONS = {
        '.exe': 'Executable',
        '.dll': 'Dynamic Link Library',
        '.sys': 'System File',
        '.bat': 'Batch Script',
        '.cmd': 'Command Script',
        '.ps1': 'PowerShell Script',
        '.sh': 'Shell Script',
        '.py': 'Python Script',
        '.js': 'JavaScript',
        '.php': 'PHP Script',
        '.asp': 'ASP Script',
        '.aspx': 'ASP.NET Script',
        '.jsp': 'JSP Script',
        '.html': 'HTML Document',
        '.css': 'CSS Stylesheet',
        '.xml': 'XML Document',
        '.json': 'JSON Data',
        '.csv': 'CSV Data',
        '.txt': 'Text File',
        '.log': 'Log File',
        '.md': 'Markdown Document',
        '.pdf': 'PDF Document',
        '.doc': 'Word Document',
        '.docx': 'Word Document',
        '.xls': 'Excel Spreadsheet',
        '.xlsx': 'Excel Spreadsheet',
        '.ppt': 'PowerPoint Presentation',
        '.pptx': 'PowerPoint Presentation',
        '.zip': 'ZIP Archive',
        '.rar': 'RAR Archive',
        '.7z': '7-Zip Archive',
        '.tar': 'TAR Archive',
        '.gz': 'GZIP Archive',
        '.bz2': 'BZIP2 Archive',
        '.jpg': 'JPEG Image',
        '.jpeg': 'JPEG Image',
        '.png': 'PNG Image',
        '.gif': 'GIF Image',
        '.bmp': 'BMP Image',
        '.ico': 'Icon',
        '.svg': 'SVG Image',
        '.mp3': 'MP3 Audio',
        '.mp4': 'MP4 Video',
        '.avi': 'AVI Video',
        '.mkv': 'MKV Video',
        '.mov': 'QuickTime Video',
        '.wmv': 'Windows Media Video',
        '.flv': 'Flash Video',
        '.apk': 'Android Package',
        '.ipa': 'iOS App',
        '.msi': 'Windows Installer',
        '.deb': 'Debian Package',
        '.rpm': 'RPM Package',
    }
    
    def analyze(self, file_path, output=None):
        """Main analyze function"""
        print_section("FILE ANALYZER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("file_analysis", str(file_path), "forensics")
        self.logger.scan_start("file_analysis", str(file_path))
        
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                print_error(f"File not found: {file_path}")
                return None
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}File:{Colors.BWHITE}         {file_path.name}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Path:{Colors.BWHITE}         {file_path}")
            print_separator("-", 50)
            print()
            
            # Basic file info
            print_subsection("Basic Information")
            basic_info = self._get_basic_info(file_path)
            self._display_basic_info(basic_info)
            
            # File hashes
            print_subsection("File Hashes")
            hashes = self._calculate_hashes(file_path)
            self._display_hashes(hashes)
            
            # File type detection
            print_subsection("File Type Detection")
            file_type = self._detect_file_type(file_path)
            self._display_file_type(file_type)
            
            # Entropy analysis
            print_subsection("Entropy Analysis")
            entropy = self._analyze_entropy(file_path)
            self._display_entropy(entropy)
            
            # String analysis
            print_subsection("String Analysis")
            strings = self._extract_strings(file_path)
            self._display_strings(strings)
            
            # Suspicious indicators
            print_subsection("Suspicious Indicators")
            indicators = self._check_suspicious_indicators(file_path, strings)
            self._display_indicators(indicators)
            
            # Save to database
            self._save_to_database(scan_id, basic_info, hashes, file_type, entropy, indicators)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", 1)
            self.logger.scan_complete("file_analysis", str(file_path), 1)
            
            # Save to file if requested
            if output:
                self._save_results(output, basic_info, hashes, file_type, entropy, strings, indicators)
            
            return {
                'basic_info': basic_info,
                'hashes': hashes,
                'file_type': file_type,
                'entropy': entropy,
                'strings': strings,
                'indicators': indicators,
            }
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("file_analysis", str(file_path), str(e))
            print_error(f"Analysis failed: {e}")
            return None
    
    def _get_basic_info(self, file_path):
        """Get basic file information"""
        stat = file_path.stat()
        
        return {
            'name': file_path.name,
            'path': str(file_path),
            'size': stat.st_size,
            'size_human': self._human_size(stat.st_size),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'extension': file_path.suffix.lower(),
            'permissions': oct(stat.st_mode)[-3:],
        }
    
    def _human_size(self, size):
        """Convert size to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def _calculate_hashes(self, file_path):
        """Calculate file hashes"""
        hashes = {}
        
        # Calculate different hashes
        hash_funcs = {
            'MD5': hashlib.md5,
            'SHA1': hashlib.sha1,
            'SHA256': hashlib.sha256,
            'SHA512': hashlib.sha512,
        }
        
        with open(file_path, 'rb') as f:
            content = f.read()
            
            for name, func in hash_funcs.items():
                hashes[name] = func(content).hexdigest()
        
        # SSDEEP (if available)
        try:
            import ssdeep
            hashes['SSDEEP'] = ssdeep.hash(content)
        except:
            pass
        
        return hashes
    
    def _detect_file_type(self, file_path):
        """Detect file type"""
        result = {
            'extension_type': 'Unknown',
            'magic_type': 'Unknown',
            'mime_type': 'Unknown',
        }
        
        # Extension-based detection
        ext = file_path.suffix.lower()
        if ext in self.FILE_EXTENSIONS:
            result['extension_type'] = self.FILE_EXTENSIONS[ext]
        
        # Magic number detection
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
                # Check magic numbers
                header_hex = header[:8].hex()
                
                for magic, desc in self.MAGIC_NUMBERS.items():
                    if header_hex.startswith(magic):
                        result['magic_type'] = desc
                        break
        except:
            pass
        
        # MIME type detection
        try:
            if MAGIC_AVAILABLE:
                result['mime_type'] = magic.from_file(str(file_path), mime=True)
            else:
                import mimetypes
                result['mime_type'], _ = mimetypes.guess_type(str(file_path))
        except:
            pass
        
        return result
    
    def _analyze_entropy(self, file_path):
        """Analyze file entropy"""
        import math
        
        with open(file_path, 'rb') as f:
            content = f.read()
        
        if not content:
            return {'entropy': 0, 'analysis': 'Empty file'}
        
        # Calculate byte frequency
        byte_freq = [0] * 256
        for byte in content:
            byte_freq[byte] += 1
        
        # Calculate entropy
        entropy = 0
        file_size = len(content)
        
        for freq in byte_freq:
            if freq > 0:
                probability = freq / file_size
                entropy -= probability * math.log2(probability)
        
        # Analyze entropy
        if entropy < 1:
            analysis = 'Low entropy - likely empty or simple text'
        elif entropy < 4:
            analysis = 'Medium entropy - likely text or code'
        elif entropy < 6:
            analysis = 'High entropy - likely compressed or encrypted'
        else:
            analysis = 'Very high entropy - likely encrypted or random data'
        
        # Check for high entropy sections (possible encryption)
        high_entropy_sections = []
        chunk_size = 1024
        
        for i in range(0, len(content), chunk_size):
            chunk = content[i:i+chunk_size]
            if len(chunk) < 256:
                continue
            
            chunk_freq = [0] * 256
            for byte in chunk:
                chunk_freq[byte] += 1
            
            chunk_entropy = 0
            for freq in chunk_freq:
                if freq > 0:
                    prob = freq / len(chunk)
                    chunk_entropy -= prob * math.log2(prob)
            
            if chunk_entropy > 7.5:
                high_entropy_sections.append({
                    'offset': i,
                    'size': len(chunk),
                    'entropy': chunk_entropy,
                })
        
        return {
            'entropy': entropy,
            'analysis': analysis,
            'high_entropy_sections': high_entropy_sections,
        }
    
    def _extract_strings(self, file_path, min_length=4):
        """Extract strings from file"""
        strings = {
            'ascii': [],
            'unicode': [],
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # ASCII strings
            import re
            ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
            ascii_strings = re.findall(ascii_pattern, content)
            strings['ascii'] = [s.decode('ascii', errors='ignore') for s in ascii_strings[:1000]]
            
            # Unicode strings
            unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
            unicode_strings = re.findall(unicode_pattern, content)
            strings['unicode'] = [s.decode('utf-16-le', errors='ignore') for s in unicode_strings[:1000]]
        
        except:
            pass
        
        return strings
    
    def _check_suspicious_indicators(self, file_path, strings):
        """Check for suspicious indicators"""
        indicators = []
        
        # Check for suspicious strings
        suspicious_patterns = {
            'URLs': r'https?://[^\s]+',
            'IP Addresses': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'Email Addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Registry Keys': r'(?:HKLM|HKCU|HKEY)[^\s]+',
            'File Paths': r'[A-Z]:\\[^\s]+',
            'Base64 Strings': r'[A-Za-z0-9+/]{20,}={0,2}',
            'Hex Strings': r'(?:0x)?[0-9a-fA-F]{16,}',
        }
        
        all_strings = ' '.join(strings.get('ascii', []) + strings.get('unicode', []))
        
        for pattern_name, pattern in suspicious_patterns.items():
            import re
            matches = re.findall(pattern, all_strings)
            if matches:
                indicators.append({
                    'type': pattern_name,
                    'count': len(matches),
                    'samples': matches[:5],
                })
        
        # Check for suspicious commands
        command_patterns = [
            'cmd', 'powershell', 'bash', 'sh', 'exec', 'eval',
            'system', 'passthru', 'shell_exec', 'popen',
            'curl', 'wget', 'nc', 'netcat',
            'base64', 'decode', 'encode',
        ]
        
        for pattern in command_patterns:
            count = all_strings.lower().count(pattern.lower())
            if count > 0:
                indicators.append({
                    'type': f'Command: {pattern}',
                    'count': count,
                    'samples': [],
                })
        
        return indicators
    
    def _display_basic_info(self, info):
        """Display basic information"""
        print(f"  {Colors.BCYAN}Name:{Colors.BWHITE}       {info['name']}")
        print(f"  {Colors.BCYAN}Size:{Colors.BWHITE}       {info['size_human']} ({info['size']:,} bytes)")
        print(f"  {Colors.BCYAN}Extension:{Colors.BWHITE}  {info['extension']}")
        print(f"  {Colors.BCYAN}Created:{Colors.BWHITE}    {info['created']}")
        print(f"  {Colors.BCYAN}Modified:{Colors.BWHITE}   {info['modified']}")
        print(f"  {Colors.BCYAN}Accessed:{Colors.BWHITE}   {info['accessed']}")
        print(f"  {Colors.BCYAN}Permissions:{Colors.BWHITE} {info['permissions']}")
        print()
    
    def _display_hashes(self, hashes):
        """Display file hashes"""
        for name, value in hashes.items():
            print(f"  {Colors.BCYAN}{name}:{Colors.BWHITE} {value}")
        print()
    
    def _display_file_type(self, file_type):
        """Display file type"""
        print(f"  {Colors.BCYAN}Extension:{Colors.BWHITE} {file_type['extension_type']}")
        print(f"  {Colors.BCYAN}Magic:{Colors.BWHITE}     {file_type['magic_type']}")
        print(f"  {Colors.BCYAN}MIME:{Colors.BWHITE}      {file_type['mime_type']}")
        print()
    
    def _display_entropy(self, entropy):
        """Display entropy analysis"""
        print(f"  {Colors.BCYAN}Entropy:{Colors.BWHITE}   {entropy['entropy']:.4f}")
        print(f"  {Colors.BCYAN}Analysis:{Colors.BWHITE}  {entropy['analysis']}")
        
        if entropy['high_entropy_sections']:
            print_warning(f"  High entropy sections: {len(entropy['high_entropy_sections'])}")
        
        print()
    
    def _display_strings(self, strings):
        """Display extracted strings"""
        ascii_count = len(strings.get('ascii', []))
        unicode_count = len(strings.get('unicode', []))
        
        print(f"  {Colors.BCYAN}ASCII Strings:{Colors.BWHITE}  {ascii_count}")
        print(f"  {Colors.BCYAN}Unicode Strings:{Colors.BWHITE} {unicode_count}")
        
        # Show sample strings
        if strings.get('ascii'):
            print(f"\n  {Colors.BCYAN}Sample ASCII Strings:{Colors.BWHITE}")
            for s in strings['ascii'][:10]:
                print(f"    {s[:80]}")
        
        print()
    
    def _display_indicators(self, indicators):
        """Display suspicious indicators"""
        if indicators:
            for indicator in indicators:
                print(f"  {Colors.BYELLOW}{indicator['type']}: {indicator['count']} found")
        else:
            print_success("No suspicious indicators found")
        
        print()
    
    def _save_to_database(self, scan_id, basic_info, hashes, file_type, entropy, indicators):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                cursor.execute("""
                    INSERT INTO scan_results 
                    (scan_id, result_type, result_data)
                    VALUES (?, ?, ?)
                """, (
                    scan_id,
                    'file_analysis',
                    json.dumps({
                        'basic_info': basic_info,
                        'hashes': hashes,
                        'file_type': file_type,
                        'entropy': entropy['entropy'],
                        'indicators_count': len(indicators),
                    })
                ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file, basic_info, hashes, file_type, entropy, strings, indicators):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'scan_time': datetime.now().isoformat(),
                'basic_info': basic_info,
                'hashes': hashes,
                'file_type': file_type,
                'entropy': entropy,
                'strings': {
                    'ascii_count': len(strings.get('ascii', [])),
                    'unicode_count': len(strings.get('unicode', [])),
                    'ascii_sample': strings.get('ascii', [])[:100],
                    'unicode_sample': strings.get('unicode', [])[:100],
                },
                'indicators': indicators,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
