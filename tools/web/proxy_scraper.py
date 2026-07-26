"""
BYMA TOOLS - Proxy Scraper
Tools untuk scraping dan testing proxy
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


class ProxyScraper:
    """Proxy scraper and tester"""
    
    def __init__(self):
        self.logger = get_logger()
        self.proxies = []
        self.working_proxies = []
    
    def test_proxies(self, proxy_list=None, output=None):
        """Main test function"""
        print_section("Proxy Tester")
        
        # Get proxy list
        if proxy_list:
            proxies = self._load_proxies(proxy_list)
        else:
            print_info("Scraping free proxies...")
            proxies = self._scrape_proxies()
        
        print_info(f"Testing {len(proxies)} proxies...")
        print()
        
        # Test proxies
        self._test_all_proxies(proxies)
        
        # Display results
        self._display_results()
        
        # Save to file if requested
        if output:
            self._save_results(output)
        
        return self.working_proxies
    
    def _load_proxies(self, proxy_file):
        """Load proxies from file"""
        try:
            with open(proxy_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return []
    
    def _scrape_proxies(self):
        """Scrape free proxies from the internet"""
        proxy_sources = [
            'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
            'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
            'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt'
        ]
        
        proxies = []
        for source in proxy_sources:
            try:
                response = requests.get(source, timeout=10)
                if response.status_code == 200:
                    proxy_list = response.text.strip().split('\n')
                    proxies.extend([p.strip() for p in proxy_list if p.strip()])
                    print_success(f"Scraped {len(proxy_list)} proxies from source")
            except:
                pass
        
        return list(set(proxies))
    
    def _test_all_proxies(self, proxies):
        """Test all proxies concurrently"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(self._test_single_proxy, proxy): proxy
                for proxy in proxies
            }
            
            with tqdm(total=len(futures), desc="    Testing",
                     bar_format='    {l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]') as pbar:
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.working_proxies.append(result)
                    pbar.update(1)
    
    def _test_single_proxy(self, proxy):
        """Test single proxy"""
        try:
            # Format proxy
            if not proxy.startswith(('http://', 'https://')):
                proxy = f"http://{proxy}"
            
            proxies = {
                'http': proxy,
                'https': proxy
            }
            
            # Test with httpbin
            response = requests.get(
                'http://httpbin.org/ip',
                proxies=proxies,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'proxy': proxy,
                    'ip': data.get('origin'),
                    'status': 'working'
                }
        except:
            pass
        
        return None
    
    def _display_results(self):
        """Display test results"""
        print_section("Proxy Test Results")
        
        if not self.working_proxies:
            print_warning("No working proxies found")
            return
        
        print_success(f"Found {len(self.working_proxies)} working proxies:")
        print()
        
        headers = ["Proxy", "IP Address", "Status"]
        rows = []
        
        for proxy_info in self.working_proxies:
            rows.append([
                proxy_info['proxy'],
                proxy_info.get('ip', 'N/A'),
                'Working'
            ])
        
        print_table(headers, rows)
    
    def _save_results(self, output_file):
        """Save results to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump({
                    'working_proxies': self.working_proxies,
                    'total': len(self.working_proxies)
                }, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
