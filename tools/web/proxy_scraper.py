"""
BYMA TOOLS - Advanced Proxy Scraper
Professional proxy discovery and validation
"""
import requests
import json
import time
import concurrent.futures
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class ProxyScraper:
    """Professional proxy scraper and validator"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.start_time = None
        self.proxies = []
        self.valid_proxies = []
    
    # Proxy sources
    PROXY_SOURCES = [
        'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
        'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt',
        'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
        'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
        'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt',
    ]
    
    # Test URLs
    TEST_URLS = [
        'http://httpbin.org/ip',
        'https://api.ipify.org?format=json',
        'http://icanhazip.com',
        'https://checkip.amazonaws.com',
    ]
    
    def scrape(self, sources=None, output=None, validate=True, 
               test_url=None, timeout=10, threads=50, min_speed=None):
        """Main proxy scrape function"""
        self.start_time = datetime.now()
        
        print_section("PROXY SCRAPER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("proxy_scrape", "proxy_list", "recon")
        self.logger.scan_start("proxy_scrape", "proxy_list")
        
        try:
            print(f"  {Icons.INFO} {Colors.BCYAN}Sources:{Colors.BWHITE}     {len(sources or self.PROXY_SOURCES)}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Validate:{Colors.BWHITE}    {'Yes' if validate else 'No'}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Threads:{Colors.BWHITE}     {threads}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Timeout:{Colors.BWHITE}     {timeout}s")
            print_separator("-", 50)
            print()
            
            # Scrape proxies
            print_subsection("Scraping Proxies")
            self._scrape_proxies(sources)
            
            # Remove duplicates
            self.proxies = list(set(self.proxies))
            print_info(f"Found {len(self.proxies)} unique proxies")
            print()
            
            # Validate proxies
            if validate:
                print_subsection("Validating Proxies")
                self._validate_proxies(test_url, timeout, threads, min_speed)
            else:
                self.valid_proxies = self.proxies
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.valid_proxies))
            self.logger.scan_complete("proxy_scrape", "proxy_list", len(self.valid_proxies))
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.valid_proxies
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("proxy_scrape", "proxy_list", str(e))
            print_error(f"Scrape failed: {e}")
            return []
    
    def _scrape_proxies(self, sources=None):
        """Scrape proxies from sources"""
        sources = sources or self.PROXY_SOURCES
        
        for source in sources:
            try:
                print_info(f"Fetching from: {source[:60]}...")
                
                response = requests.get(source, timeout=10)
                
                if response.status_code == 200:
                    # Parse proxies
                    lines = response.text.strip().split('\n')
                    
                    for line in lines:
                        line = line.strip()
                        if ':' in line and line[0].isdigit():
                            # Validate format
                            parts = line.split(':')
                            if len(parts) == 2:
                                ip, port = parts
                                try:
                                    port = int(port)
                                    if 1 <= port <= 65535:
                                        proxy_type = self._detect_proxy_type(source, line)
                                        self.proxies.append({
                                            'ip': ip,
                                            'port': port,
                                            'type': proxy_type,
                                            'source': source,
                                        })
                                except ValueError:
                                    pass
                    
                    print_success(f"  Fetched {len(lines)} entries")
                else:
                    print_warning(f"  HTTP {response.status_code}")
            
            except Exception as e:
                print_error(f"  Error: {e}")
    
    def _detect_proxy_type(self, source, proxy_str):
        """Detect proxy type from source or format"""
        source_lower = source.lower()
        
        if 'socks5' in source_lower:
            return 'SOCKS5'
        elif 'socks4' in source_lower or 'socks' in source_lower:
            return 'SOCKS4'
        elif 'https' in source_lower:
            return 'HTTPS'
        else:
            return 'HTTP'
    
    def _validate_proxies(self, test_url=None, timeout=10, threads=50, min_speed=None):
        """Validate proxies"""
        if not test_url:
            test_url = self.TEST_URLS[0]
        
        print_info(f"Testing {len(self.proxies)} proxies against {test_url}")
        print()
        
        def validate_proxy(proxy_info):
            proxy_str = f"http://{proxy_info['ip']}:{proxy_info['port']}"
            
            try:
                start_time = time.time()
                
                response = requests.get(
                    test_url,
                    proxies={'http': proxy_str, 'https': proxy_str},
                    timeout=timeout,
                    verify=False
                )
                
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    proxy_info['response_time'] = response_time
                    proxy_info['status'] = 'valid'
                    
                    # Check if min_speed requirement met
                    if min_speed and response_time > min_speed:
                        proxy_info['status'] = 'slow'
                    else:
                        self.valid_proxies.append(proxy_info)
                        print_success(f"  {proxy_info['ip']}:{proxy_info['port']} ({response_time:.2f}s)")
                    
                    return True
            
            except:
                pass
            
            return False
        
        # Run validation
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(validate_proxy, proxy): proxy for proxy in self.proxies}
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if completed % 100 == 0:
                    cprint(f"  Progress: {completed}/{len(self.proxies)}", Colors.BWHITE)
        
        print()
        print_info(f"Valid proxies: {len(self.valid_proxies)}/{len(self.proxies)}")
    
    def _display_results(self):
        """Display scrape results"""
        print_section("PROXY SCRAPE RESULTS")
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Summary
        print(f"\n  {Icons.INFO} {Colors.BCYAN}SCRAPE SUMMARY{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.INFO} {Colors.BCYAN}Total Scraped:{Colors.BWHITE}   {len(self.proxies)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Valid Proxies:{Colors.BWHITE}  {len(self.valid_proxies)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}            {elapsed:.1f}s")
        
        print_separator("-", 50)
        print()
        
        # Proxy type distribution
        if self.valid_proxies:
            print_subsection("Proxy Types")
            
            types = {}
            for proxy in self.valid_proxies:
                ptype = proxy.get('type', 'Unknown')
                types[ptype] = types.get(ptype, 0) + 1
            
            table_data = [["Type", "Count"]]
            for ptype, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
                table_data.append([ptype, str(count)])
            
            print_table(table_data)
            print()
        
        # Speed distribution
        if self.valid_proxies and any(p.get('response_time') for p in self.valid_proxies):
            print_subsection("Speed Distribution")
            
            speed_ranges = {'< 1s': 0, '1-3s': 0, '3-5s': 0, '> 5s': 0}
            
            for proxy in self.valid_proxies:
                rt = proxy.get('response_time', 0)
                if rt < 1:
                    speed_ranges['< 1s'] += 1
                elif rt < 3:
                    speed_ranges['1-3s'] += 1
                elif rt < 5:
                    speed_ranges['3-5s'] += 1
                else:
                    speed_ranges['> 5s'] += 1
            
            table_data = [["Speed", "Count"]]
            for speed, count in speed_ranges.items():
                table_data.append([speed, str(count)])
            
            print_table(table_data)
            print()
        
        # Top proxies
        if self.valid_proxies:
            print_subsection("Top 20 Fastest Proxies")
            
            sorted_proxies = sorted(
                [p for p in self.valid_proxies if p.get('response_time')],
                key=lambda x: x['response_time']
            )[:20]
            
            table_data = [["#", "Proxy", "Type", "Speed"]]
            for i, proxy in enumerate(sorted_proxies, 1):
                table_data.append([
                    str(i),
                    f"{proxy['ip']}:{proxy['port']}",
                    proxy.get('type', '?'),
                    f"{proxy.get('response_time', 0):.2f}s",
                ])
            
            print_table(table_data)
            print()
        
        print()
    
    def _save_to_database(self, scan_id):
        """Save results to database"""
        try:
            with self.db._cursor() as cursor:
                for proxy in self.valid_proxies[:100]:
                    cursor.execute("""
                        INSERT INTO scan_results 
                        (scan_id, result_type, result_data)
                        VALUES (?, ?, ?)
                    """, (
                        scan_id,
                        'proxy',
                        json.dumps({
                            'ip': proxy['ip'],
                            'port': proxy['port'],
                            'type': proxy.get('type', ''),
                            'response_time': proxy.get('response_time', 0),
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
                'scrape_time': self.start_time.isoformat(),
                'total_scraped': len(self.proxies),
                'valid_proxies': len(self.valid_proxies),
                'proxies': self.valid_proxies,
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
