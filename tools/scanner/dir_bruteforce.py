"""
BYMA TOOLS - Advanced Directory Bruteforcer
Professional directory/file discovery with recursive scanning
"""
import requests
import os
import time
import json
import random
import concurrent.futures
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class DirectoryBruteforcer:
    """Professional directory and file bruteforcer"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.results = {
            'directories': [],
            'files': [],
            'backup_files': [],
            'sensitive_files': [],
            'config_files': [],
            'hidden_content': [],
            'api_endpoints': [],
        }
        self.total_tested = 0
        self.start_time = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    # Common directories to discover
    COMMON_DIRECTORIES = [
        'admin', 'administrator', 'backup', 'backups', 'config', 'conf',
        'database', 'db', 'debug', 'dev', 'development', 'docs', 'documentation',
        'download', 'downloads', 'ftp', 'help', 'hidden', 'images', 'img',
        'include', 'includes', 'install', 'internal', 'lib', 'libraries',
        'log', 'logs', 'login', 'logout', 'mail', 'management', 'media',
        'menu', 'misc', 'modules', 'old', 'original', 'pages', 'panel',
        'password', 'phpmyadmin', 'private', 'public', 'raw', 'release',
        'releases', 'remote', 'resources', 'root', 'secret', 'secrets',
        'secure', 'security', 'server', 'settings', 'setup', 'shadow',
        'shell', 'site', 'sources', 'sql', 'ssh', 'staging', 'static',
        'stats', 'status', 'storage', 'system', 'temp', 'template',
        'templates', 'test', 'testing', 'tmp', 'tools', 'upload',
        'uploads', 'user', 'users', 'util', 'utils', 'var', 'vendor',
        'version', 'web', 'webmail', 'wp-admin', 'wp-content', 'wp-includes',
        'wp-login', 'xmlrpc', '.env', '.git', '.svn', '.hg', '.bzr',
        'cgi-bin', 'icons', 'manual', 'scripts', 'server-status',
    ]
    
    # Common files to discover
    COMMON_FILES = [
        'robots.txt', 'sitemap.xml', '.htaccess', '.htpasswd', 'web.config',
        'crossdomain.xml', 'favicon.ico', 'index.php', 'index.html',
        'default.php', 'default.html', 'login.php', 'login.html',
        'admin.php', 'admin.html', 'config.php', 'config.inc.php',
        'settings.php', 'configuration.php', 'wp-config.php',
        'config/database.yml', 'config.yml', 'config.json',
        'composer.json', 'package.json', 'Gemfile', 'requirements.txt',
        'Makefile', 'Dockerfile', 'docker-compose.yml',
        'README.md', 'README.txt', 'README', 'CHANGELOG.md',
        'LICENSE', 'LICENSE.md', 'TODO', 'TODO.md',
        'debug.php', 'test.php', 'info.php', 'phpinfo.php',
        'phpmyadmin/index.php', 'adminer.php', 'dbadmin.php',
        '.env', '.env.local', '.env.production', '.env.development',
        '.git/HEAD', '.git/config', '.svn/entries', '.svn/wc.db',
        'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.sql.gz',
        'database.sql', 'dump.sql', 'export.sql',
        'server-status', 'server-info', 'server-info',
        'wp-login.php', 'wp-admin/install.php', 'xmlrpc.php',
        'feed', 'rss', 'atom.xml', 'feed.xml',
        'search', 'search.php', 'search.html',
        'help', 'help.php', 'help.html', 'faq', 'faq.php',
        'contact', 'contact.php', 'contact.html',
        'about', 'about.php', 'about.html',
        'links', 'links.php', 'links.html',
        'files', 'file', 'download', 'downloads',
        'upload', 'uploads', 'images', 'img', 'media',
        'css', 'js', 'javascript', 'scripts', 'style', 'styles',
        'api', 'api/v1', 'api/v2', 'api/v3', 'graphql',
        'swagger', 'swagger.json', 'swagger-ui', 'api-docs',
        'actuator', 'actuator/health', 'actuator/info', 'actuator/env',
    ]
    
    # Sensitive file patterns
    SENSITIVE_PATTERNS = [
        r'\.env',
        r'\.git',
        r'\.svn',
        r'\.hg',
        r'\.htpasswd',
        r'config\.php',
        r'configuration\.php',
        r'wp-config\.php',
        r'database\.yml',
        r'backup\.sql',
        r'dump\.sql',
        r'password',
        r'secret',
        r'private',
        r'credentials',
    ]
    
    # Backup file extensions
    BACKUP_EXTENSIONS = [
        '.bak', '.backup', '.old', '.orig', '.save', '.swp',
        '.tar', '.tar.gz', '.tgz', '.zip', '.rar', '.7z',
        '.sql', '.sql.gz', '.dump', '.export',
        '~', '.copy', '.tmp',
    ]
    
    def scan(self, url, threads=10, timeout=10, extensions=None, 
             output=None, mode='comprehensive', wordlist=None, recursive=False):
        """Main directory bruteforce scan"""
        self.start_time = datetime.now()
        
        print_section("DIRECTORY BRUTEFORCER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("dir_bruteforce", url, "recon")
        self.logger.scan_start("dir_bruteforce", url)
        
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            if not url.endswith('/'):
                url += '/'
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {url}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Threads:{Colors.BWHITE}      {threads}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Mode:{Colors.BWHITE}         {mode.upper()}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Extensions:{Colors.BWHITE}   {', '.join(extensions) if extensions else 'None'}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Recursive:{Colors.BWHITE}    {'Yes' if recursive else 'No'}")
            print_separator("-", 50)
            print()
            
            # Build wordlist
            wordlist = self._build_wordlist(wordlist, mode)
            
            # Generate test paths
            test_paths = self._generate_test_paths(url, wordlist, extensions)
            
            print(f"  {Icons.INFO} {Colors.BCYAN}Total paths to test:{Colors.BWHITE} {len(test_paths)}")
            print()
            
            # Run bruteforce
            self._run_bruteforce(url, test_paths, threads, timeout)
            
            # Backup file discovery
            if mode in ['comprehensive', 'backup']:
                print_subsection("Backup File Discovery")
                self._discover_backup_files(url, wordlist, timeout)
            
            # API endpoint discovery
            if mode in ['comprehensive', 'api']:
                print_subsection("API Endpoint Discovery")
                self._discover_api_endpoints(url, timeout)
            
            # Recursive scanning
            if recursive:
                print_subsection("Recursive Scanning")
                self._recursive_scan(url, extensions, threads, timeout)
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", self.total_tested)
            self.logger.scan_complete("dir_bruteforce", url, self.total_tested)
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.results
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("dir_bruteforce", url, str(e))
            print_error(f"Scan failed: {e}")
            return None
    
    def _build_wordlist(self, custom_wordlist, mode):
        """Build wordlist based on mode"""
        wordlist = set(self.COMMON_DIRECTORIES + self.COMMON_FILES)
        
        if custom_wordlist and os.path.exists(custom_wordlist):
            with open(custom_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    wordlist.add(line.strip())
        
        if mode == 'comprehensive':
            # Add more common paths
            additional = [
                'backup', 'backups', 'bak', 'old', 'temp', 'tmp',
                'copy', 'original', 'new', 'latest', 'dev', 'debug',
                'test', 'testing', 'staging', 'prod', 'production',
                'admin', 'panel', 'dashboard', 'manage', 'management',
                'api', 'v1', 'v2', 'v3', 'graphql', 'rest',
                'upload', 'uploads', 'file', 'files', 'download',
                'documents', 'docs', 'documentation', 'help',
                'images', 'img', 'media', 'assets', 'static',
                'css', 'js', 'scripts', 'fonts', 'icons',
            ]
            wordlist.update(additional)
        
        return list(wordlist)
    
    def _generate_test_paths(self, base_url, wordlist, extensions):
        """Generate test paths from wordlist"""
        paths = []
        
        for word in wordlist:
            # Add raw word
            paths.append(word)
            
            # Add with extensions
            if extensions:
                for ext in extensions:
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    paths.append(f"{word}{ext}")
            
            # Add common backup extensions
            for ext in self.BACKUP_EXTENSIONS:
                paths.append(f"{word}{ext}")
        
        # Remove duplicates
        paths = list(set(paths))
        
        return paths
    
    def _run_bruteforce(self, base_url, paths, threads, timeout):
        """Run the bruteforce scan"""
        print_subsection("Scanning")
        
        found = 0
        tested = 0
        
        def test_path(path):
            nonlocal found, tested
            
            url = urljoin(base_url, path)
            try:
                response = self.session.get(url, timeout=timeout, verify=False, allow_redirects=False)
                
                # Filter out common false positives
                if response.status_code in [404, 410]:
                    return
                
                if response.status_code == 200:
                    # Verify it's not a custom 404
                    if not self._is_custom_404(response, base_url):
                        self.results['directories'].append({
                            'path': path,
                            'url': url,
                            'status': response.status_code,
                            'size': len(response.text),
                            'type': self._detect_content_type(response),
                        })
                        print_success(f"Found: {path} [{response.status_code}] ({len(response.text)} bytes)")
                        found += 1
                
                elif response.status_code in [301, 302, 303, 307, 308]:
                    self.results['directories'].append({
                        'path': path,
                        'url': url,
                        'status': response.status_code,
                        'redirect': response.headers.get('Location', ''),
                        'type': 'redirect',
                    })
                    print_info(f"Redirect: {path} -> {response.headers.get('Location', '')}")
                    found += 1
                
                elif response.status_code == 403:
                    # Forbidden might indicate existing but restricted
                    self.results['directories'].append({
                        'path': path,
                        'url': url,
                        'status': response.status_code,
                        'type': 'forbidden',
                    })
                    print_warning(f"Forbidden: {path}")
                    found += 1
                
                tested += 1
                self.total_tested += 1
                
            except requests.exceptions.Timeout:
                pass
            except Exception:
                pass
        
        # Run with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(test_path, path): path for path in paths}
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
        
        print()
        print_info(f"Tested {tested} paths, found {found} results")
    
    def _is_custom_404(self, response, base_url):
        """Check if response is a custom 404 page"""
        # Common indicators of custom 404
        indicators = [
            'not found',
            '404',
            'page not found',
            'does not exist',
            'doesn\'t exist',
            'unable to find',
            'could not find',
            'error',
        ]
        
        text_lower = response.text.lower()
        
        for indicator in indicators:
            if indicator in text_lower:
                # Check if it's too short (likely custom 404)
                if len(response.text) < 100:
                    return True
                # Check if it contains the requested path (common in custom 404)
                requested_path = response.url.replace(base_url, '')
                if requested_path in response.text:
                    return True
        
        return False
    
    def _detect_content_type(self, response):
        """Detect content type of response"""
        content_type = response.headers.get('Content-Type', '')
        
        if 'html' in content_type:
            return 'html'
        elif 'json' in content_type:
            return 'json'
        elif 'xml' in content_type:
            return 'xml'
        elif 'text' in content_type:
            return 'text'
        elif 'image' in content_type:
            return 'image'
        elif 'javascript' in content_type:
            return 'javascript'
        elif 'css' in content_type:
            return 'css'
        else:
            return 'unknown'
    
    def _discover_backup_files(self, base_url, wordlist, timeout):
        """Discover backup files"""
        backup_found = 0
        
        for word in wordlist[:100]:  # Test top 100 words
            for ext in self.BACKUP_EXTENSIONS:
                path = f"{word}{ext}"
                url = urljoin(base_url, path)
                
                try:
                    response = self.session.get(url, timeout=timeout, verify=False, allow_redirects=False)
                    
                    if response.status_code == 200 and len(response.content) > 0:
                        # Verify it's actually a backup file
                        if self._is_backup_file(response):
                            self.results['backup_files'].append({
                                'path': path,
                                'url': url,
                                'size': len(response.content),
                                'type': ext,
                            })
                            print_success(f"Backup found: {path} ({len(response.content)} bytes)")
                            backup_found += 1
                
                except:
                    pass
        
        if backup_found == 0:
            print_info("No backup files found")
    
    def _is_backup_file(self, response):
        """Check if file is likely a backup"""
        content = response.text[:1000].lower()
        
        # SQL dump indicators
        sql_indicators = [
            'create table',
            'insert into',
            'drop table',
            'mysqldump',
            'pg_dump',
            '--',
            '/*',
        ]
        
        # Config file indicators
        config_indicators = [
            '<?php',
            'define(',
            'config',
            'database',
            'password',
            'username',
        ]
        
        # Archive indicators
        archive_indicators = [
            'pk',  # ZIP
            'rar',  # RAR
            '7z',  # 7-ZIP
        ]
        
        for indicator in sql_indicators + config_indicators:
            if indicator in content:
                return True
        
        return False
    
    def _discover_api_endpoints(self, base_url, timeout):
        """Discover API endpoints"""
        api_paths = [
            'api', 'api/v1', 'api/v2', 'api/v3',
            'graphql', 'rest', 'soap', 'ws',
            'swagger', 'swagger.json', 'swagger-ui',
            'api-docs', 'openapi', 'openapi.json',
            'actuator', 'actuator/health', 'actuator/info',
            'health', 'healthcheck', 'status',
            'metrics', 'prometheus', 'stats',
            'debug', 'trace', 'info',
        ]
        
        api_found = 0
        
        for path in api_paths:
            url = urljoin(base_url, path)
            
            try:
                response = self.session.get(url, timeout=timeout, verify=False, allow_redirects=False)
                
                if response.status_code in [200, 401, 403]:
                    # Check if it's actually an API
                    if self._is_api_response(response):
                        self.results['api_endpoints'].append({
                            'path': path,
                            'url': url,
                            'status': response.status_code,
                            'type': self._detect_api_type(response),
                        })
                        print_success(f"API found: {path} [{response.status_code}]")
                        api_found += 1
            
            except:
                pass
        
        if api_found == 0:
            print_info("No API endpoints found")
    
    def _is_api_response(self, response):
        """Check if response is from an API"""
        content_type = response.headers.get('Content-Type', '')
        
        # JSON response
        if 'json' in content_type:
            return True
        
        # Check for API-specific headers
        api_headers = [
            'x-api-version',
            'x-ratelimit-limit',
            'x-request-id',
            'x-correlation-id',
        ]
        
        for header in api_headers:
            if header in response.headers:
                return True
        
        # Check response body for API indicators
        try:
            data = response.json()
            if isinstance(data, dict) and ('error' in data or 'data' in data or 'status' in data):
                return True
        except:
            pass
        
        return False
    
    def _detect_api_type(self, response):
        """Detect API type"""
        content_type = response.headers.get('Content-Type', '')
        path = urlparse(response.url).path.lower()
        
        if 'graphql' in path:
            return 'GraphQL'
        elif 'swagger' in path or 'openapi' in path:
            return 'Swagger/OpenAPI'
        elif 'actuator' in path:
            return 'Spring Actuator'
        elif 'json' in content_type:
            return 'REST API'
        elif 'xml' in content_type:
            return 'SOAP API'
        else:
            return 'Unknown API'
    
    def _recursive_scan(self, base_url, extensions, threads, timeout):
        """Recursively scan discovered directories"""
        discovered_dirs = [d['path'] for d in self.results['directories'] 
                         if d.get('type') == 'html' and not '.' in d['path'].split('/')[-1]]
        
        if not discovered_dirs:
            print_info("No directories to scan recursively")
            return
        
        for dir_path in discovered_dirs[:5]:  # Limit recursive depth
            print_info(f"Scanning {dir_path}...")
            
            dir_url = urljoin(base_url, dir_path + '/')
            
            # Build sub-wordlist
            sub_wordlist = self.COMMON_DIRECTORIES[:50] + self.COMMON_FILES[:50]
            
            # Generate sub-paths
            sub_paths = self._generate_test_paths(dir_url, sub_wordlist, extensions)
            
            # Run scan on sub-directory
            self._run_bruteforce(dir_url, sub_paths, threads, timeout)
    
    def _display_results(self):
        """Display scan results"""
        print_section("DIRECTORY BRUTEFORCE RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}SCAN SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Total Tested:{Colors.BWHITE}    {self.total_tested}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Directories:{Colors.BWHITE}     {len(self.results['directories'])}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Files:{Colors.BWHITE}           {len(self.results['files'])}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Backup Files:{Colors.BWHITE}    {len(self.results['backup_files'])}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Sensitive Files:{Colors.BWHITE} {len(self.results['sensitive_files'])}")
        print(f"  {Icons.INFO} {Colors.BCYAN}API Endpoints:{Colors.BWHITE}   {len(self.results['api_endpoints'])}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}            {elapsed:.1f}s")
        
        print_separator("-", 50)
        print()
        
        # Display directories
        if self.results['directories']:
            print_subsection("Discovered Directories")
            
            table_data = [["Path", "Status", "Size", "Type"]]
            for item in self.results['directories'][:20]:
                table_data.append([
                    item['path'][:30],
                    str(item['status']),
                    str(item.get('size', '-')),
                    item.get('type', '-'),
                ])
            
            print_table(table_data)
            print()
        
        # Display backup files
        if self.results['backup_files']:
            print_subsection("Backup Files Found")
            
            table_data = [["Path", "Size", "Type"]]
            for item in self.results['backup_files'][:20]:
                table_data.append([
                    item['path'][:30],
                    str(item['size']),
                    item['type'],
                ])
            
            print_table(table_data)
            print()
        
        # Display API endpoints
        if self.results['api_endpoints']:
            print_subsection("API Endpoints")
            
            table_data = [["Path", "Status", "Type"]]
            for item in self.results['api_endpoints']:
                table_data.append([
                    item['path'],
                    str(item['status']),
                    item['type'],
                ])
            
            print_table(table_data)
            print()
    
    def _save_to_database(self, scan_id):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                # Save directories
                for item in self.results['directories']:
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, result_type, result_data)
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        'directory',
                        json.dumps(item)
                    ))
                
                # Save backup files
                for item in self.results['backup_files']:
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, result_type, result_data)
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        'backup_file',
                        json.dumps(item)
                    ))
                
                # Save API endpoints
                for item in self.results['api_endpoints']:
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, result_type, result_data)
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        'api_endpoint',
                        json.dumps(item)
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
                'total_tested': self.total_tested,
                'results': self.results,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
