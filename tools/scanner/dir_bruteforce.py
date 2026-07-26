"""
BYMA TOOLS - Directory Bruteforcer
Tools untuk brute force direktori dan file tersembunyi
"""
import requests
import json
import concurrent.futures
from pathlib import Path
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_table, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class DirBruteforcer:
    """Directory and file bruteforcer"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.found_paths = []
    
    def bruteforce(self, url, wordlist=None, extensions=None, threads=50, output=None):
        """Main bruteforce function"""
        print_section(f"Directory Bruteforce: {url}")
        
        scan_id = self.db.create_scan("dir_bruteforce", url, "vulnerability")
        self.logger.scan_start("dir_bruteforce", url)
        
        try:
            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            # Load wordlist
            words = self._load_wordlist(wordlist)
            
            # Add extensions if specified
            if extensions:
                extended_words = []
                for word in words:
                    extended_words.append(word)
                    for ext in extensions.split(','):
                        ext = ext.strip().lstrip('.')
                        extended_words.append(f"{word}.{ext}")
                words = extended_words
            
            print_info(f"Testing {len(words)} paths...")
            
            # Start bruteforce
            self._bruteforce(url, words, threads)
            
            # Save to database
            for path_info in self.found_paths:
                self.db.add_vulnerability(
                    scan_id, url, 'Directory Found', 'INFO',
                    f"Directory/File Found: {path_info['path']}",
                    f"Found accessible path: {path_info['path']}",
                    f"Status: {path_info['status']}, Size: {path_info['size']}",
                    None
                )
            
            self.db.update_scan(scan_id, "completed", len(self.found_paths))
            self.logger.scan_complete("dir_bruteforce", url, len(self.found_paths))
            
            self._display_results()
            
            if output:
                self._save_results(url, output)
            
            return self.found_paths
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("dir_bruteforce", url, str(e))
            print_error(f"Bruteforce failed: {e}")
            return []
    
    def _load_wordlist(self, wordlist_path):
        """Load wordlist from file or use default"""
        if wordlist_path and Path(wordlist_path).exists():
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        
        # Use default wordlist
        return self._get_default_wordlist()
    
    def _get_default_wordlist(self):
        """Get default directory wordlist"""
        return [
            'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php',
            'panel', 'cpanel', 'phpmyadmin', 'phpMyAdmin',
            'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'test',
            'api', 'v1', 'v2', 'graphql', 'swagger', 'docs',
            'config', 'configuration', 'settings', 'setup', 'install',
            'database', 'db', 'sql', 'mysql', 'postgres',
            'uploads', 'upload', 'files', 'media', 'images', 'img',
            'static', 'assets', 'css', 'js', 'javascript', 'scripts',
            'cgi-bin', 'bin', 'sbin',
            '.git', '.svn', '.env', '.htaccess', '.htpasswd',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'server-status', 'server-info',
            'webmail', 'mail', 'email', 'smtp',
            'blog', 'news', 'forum', 'community', 'support',
            'help', 'faq', 'about', 'contact',
            'dashboard', 'home', 'index', 'default',
            'status', 'health', 'ping', 'info',
            'debug', 'trace', 'log', 'logs', 'error',
            'register', 'signup', 'signin', 'auth', 'oauth',
            'search', 'find', 'query',
            'user', 'users', 'account', 'accounts', 'profile',
            'admin.php', 'admin.html', 'admin/',
            'wp-content', 'wp-includes', 'wp-config.php.bak',
            'config.php', 'config.php.bak', 'config.php.old',
            'database.sql', 'dump.sql', 'backup.sql',
            '.env', '.env.local', '.env.production',
            'Dockerfile', 'docker-compose.yml',
            'package.json', 'composer.json', 'Gemfile',
            'Makefile', 'Gruntfile.js', 'gulpfile.js',
            'webpack.config.js', 'tsconfig.json',
            'README.md', 'CHANGELOG.md', 'LICENSE',
            '.DS_Store', 'Thumbs.db'
        ]
    
    def _bruteforce(self, url, words, threads):
        """Perform bruteforce with threading"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_path, url, word): word
                for word in words
            }
            
            with tqdm(total=len(futures), desc="    Bruteforcing",
                     bar_format='    {l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]') as pbar:
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.found_paths.append(result)
                    pbar.update(1)
    
    def _check_path(self, url, path):
        """Check if path exists"""
        try:
            # Clean path
            path = path.strip('/')
            test_url = f"{url}/{path}"
            
            response = requests.get(test_url, timeout=5, verify=False, 
                                  allow_redirects=False)
            
            # Filter out common false positives
            if response.status_code not in [404, 403, 500, 502, 503, 504]:
                if response.status_code in [200, 301, 302, 401]:
                    return {
                        'path': path,
                        'url': test_url,
                        'status': response.status_code,
                        'size': len(response.content),
                        'redirect': response.headers.get('Location', None)
                    }
        except:
            pass
        
        return None
    
    def _display_results(self):
        """Display bruteforce results"""
        print_section("Bruteforce Results")
        
        if not self.found_paths:
            print_warning("No paths found")
            return
        
        print_success(f"Found {len(self.found_paths)} accessible paths:")
        print()
        
        headers = ["Status", "Size", "Path"]
        rows = []
        
        for path_info in sorted(self.found_paths, key=lambda x: x['status']):
            rows.append([
                str(path_info['status']),
                f"{path_info['size']}B",
                path_info['path']
            ])
        
        print_table(headers, rows)
    
    def _save_results(self, url, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'url': url,
                    'found_paths': self.found_paths,
                    'total': len(self.found_paths)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
