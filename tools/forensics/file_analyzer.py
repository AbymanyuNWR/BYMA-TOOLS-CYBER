"""
BYMA TOOLS - File Analyzer
Tools untuk analisis file
"""
import hashlib
import json
import os
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, cprint, Colors
)
from core.logger import get_logger


class FileAnalyzer:
    """File analysis tool"""
    
    def __init__(self):
        self.logger = get_logger()
    
    def analyze(self, file_path, output=None):
        """Analyze file"""
        print_section(f"File Analyzer: {file_path}")
        
        if not Path(file_path).exists():
            print_error(f"File not found: {file_path}")
            return None
        
        try:
            # Get file info
            info = self._get_file_info(file_path)
            
            # Calculate hashes
            print_info("Calculating hashes...")
            hashes = self._calculate_hashes(file_path)
            info['hashes'] = hashes
            
            # Detect file type
            print_info("Detecting file type...")
            file_type = self._detect_file_type(file_path)
            info['type'] = file_type
            
            # Get file metadata
            print_info("Getting metadata...")
            metadata = self._get_metadata(file_path)
            info['metadata'] = metadata
            
            # Display results
            self._display_results(info)
            
            # Save to file if requested
            if output:
                self._save_results(file_path, info, output)
            
            return info
        
        except Exception as e:
            print_error(f"File analysis failed: {e}")
            return None
    
    def _get_file_info(self, file_path):
        """Get basic file information"""
        path = Path(file_path)
        stat = path.stat()
        
        return {
            'name': path.name,
            'extension': path.suffix,
            'size': stat.st_size,
            'size_human': self._human_size(stat.st_size),
            'created': str(stat.st_ctime),
            'modified': str(stat.st_mtime),
            'accessed': str(stat.st_atime),
        }
    
    def _calculate_hashes(self, file_path):
        """Calculate file hashes"""
        hashes = {}
        
        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Calculate different hashes
        hashes['md5'] = hashlib.md5(content).hexdigest()
        hashes['sha1'] = hashlib.sha1(content).hexdigest()
        hashes['sha256'] = hashlib.sha256(content).hexdigest()
        hashes['sha512'] = hashlib.sha512(content).hexdigest()
        
        return hashes
    
    def _detect_file_type(self, file_path):
        """Detect file type using magic bytes"""
        try:
            import subprocess
            result = subprocess.run(['file', '-b', file_path], capture_output=True, text=True)
            return result.stdout.strip()
        except:
            # Fallback: check extension
            ext = Path(file_path).suffix.lower()
            type_map = {
                '.exe': 'PE32 executable',
                '.dll': 'PE32 DLL',
                '.pdf': 'PDF document',
                '.zip': 'ZIP archive',
                '.rar': 'RAR archive',
                '.jpg': 'JPEG image',
                '.png': 'PNG image',
                '.gif': 'GIF image',
                '.txt': 'Text file',
                '.py': 'Python script',
                '.js': 'JavaScript file',
            }
            return type_map.get(ext, 'Unknown')
    
    def _get_metadata(self, file_path):
        """Get file metadata"""
        metadata = {}
        
        # Try to get EXIF data for images
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            img = Image.open(file_path)
            exifdata = img.getexif()
            
            for tag_id, value in exifdata.items():
                tag = TAGS.get(tag_id, tag_id)
                metadata[str(tag)] = str(value)
        except:
            pass
        
        return metadata
    
    def _human_size(self, size):
        """Convert size to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def _display_results(self, info):
        """Display analysis results"""
        print_section("File Analysis Results")
        
        # Basic Info
        cprint(f"    {'File Name:':<25} {info['name']}", Colors.BWHITE)
        cprint(f"    {'Extension:':<25} {info['extension']}", Colors.BWHITE)
        cprint(f"    {'Size:':<25} {info['size_human']}", Colors.BWHITE)
        cprint(f"    {'Type:':<25} {info['type']}", Colors.BCYAN)
        
        # Timestamps
        print()
        cprint(f"    {'Timestamps:':<25}", Colors.BCYAN)
        cprint(f"      {'Created:':<23} {info['created']}", Colors.BWHITE)
        cprint(f"      {'Modified:':<23} {info['modified']}", Colors.BWHITE)
        cprint(f"      {'Accessed:':<23} {info['accessed']}", Colors.BWHITE)
        
        # Hashes
        print()
        cprint(f"    {'Hashes:':<25}", Colors.BCYAN)
        for algo, hash_val in info['hashes'].items():
            cprint(f"      {algo.upper():<23} {hash_val}", Colors.BWHITE)
        
        # Metadata
        if info.get('metadata'):
            print()
            cprint(f"    {'Metadata:':<25}", Colors.BCYAN)
            for key, value in list(info['metadata'].items())[:10]:
                cprint(f"      {key}: {value[:50]}", Colors.BWHITE)
    
    def _save_results(self, file_path, info, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'file': file_path,
                    'info': info
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
