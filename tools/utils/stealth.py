"""
BYMA TOOLS - Advanced Stealth Module
Professional anti-detection and stealth techniques
"""
import random
import time
import json
import hashlib
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class StealthModule:
    """Professional stealth module for anti-detection"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    # User agents for rotation
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    ]
    
    # Common headers
    COMMON_HEADERS = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
    }
    
    # Delay ranges (seconds)
    DELAY_RANGES = {
        'aggressive': (0.1, 0.5),
        'normal': (0.5, 2.0),
        'stealthy': (1.0, 5.0),
        'paranoid': (2.0, 10.0),
    }
    
    def configure(self, mode='normal', output=None):
        """Main configure function"""
        print_section("STEALTH CONFIGURATION")
        print()
        
        try:
            print(f"  {Icons.INFO} {Colors.BCYAN}Mode:{Colors.BWHITE}        {mode.upper()}")
            print_separator("-", 50)
            print()
            
            # Generate stealth config
            print_subsection("Generating Stealth Configuration")
            config = self._generate_config(mode)
            self._display_config(config)
            
            # Test configuration
            print_subsection("Testing Configuration")
            self._test_config(config)
            
            # Save to file
            if output:
                self._save_config(config, output)
            
            return config
        
        except Exception as e:
            print_error(f"Configuration failed: {e}")
            return None
    
    def _generate_config(self, mode):
        """Generate stealth configuration"""
        delay_range = self.DELAY_RANGES.get(mode, self.DELAY_RANGES['normal'])
        
        config = {
            'mode': mode,
            'user_agent': random.choice(self.USER_AGENTS),
            'headers': self.COMMON_HEADERS.copy(),
            'delay': {
                'min': delay_range[0],
                'max': delay_range[1],
            },
            'rotation': {
                'user_agent': True,
                'headers': True,
            },
            'evasion': {
                'randomize_headers': True,
                'add_referrer': True,
                'use_proxy': False,
                'proxy_list': [],
            },
        }
        
        # Add random referrer
        referrers = [
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://www.yahoo.com/',
            'https://duckduckgo.com/',
            'https://www.facebook.com/',
            'https://twitter.com/',
        ]
        config['headers']['Referer'] = random.choice(referrers)
        
        return config
    
    def _test_config(self, config):
        """Test stealth configuration"""
        import requests
        
        print_info("Testing User-Agent rotation...")
        
        for i in range(3):
            ua = random.choice(self.USER_AGENTS)
            print(f"  UA {i+1}: {ua[:60]}...")
        
        print()
        print_info("Testing header randomization...")
        
        for i in range(3):
            headers = self.COMMON_HEADERS.copy()
            headers['User-Agent'] = random.choice(self.USER_AGENTS)
            print(f"  Headers {i+1}: {len(headers)} headers")
        
        print()
        print_info("Testing delay timing...")
        
        for i in range(3):
            delay = random.uniform(config['delay']['min'], config['delay']['max'])
            print(f"  Delay {i+1}: {delay:.2f}s")
        
        print()
        print_success("Configuration test passed")
    
    def _display_config(self, config):
        """Display configuration"""
        print(f"  {Colors.BCYAN}Mode:{Colors.BWHITE}           {config['mode']}")
        print(f"  {Colors.BCYAN}User-Agent:{Colors.BWHITE}     {config['user_agent'][:50]}...")
        print(f"  {Colors.BCYAN}Headers:{Colors.BWHITE}        {len(config['headers'])}")
        print(f"  {Colors.BCYAN}Delay Range:{Colors.BWHITE}    {config['delay']['min']:.1f}s - {config['delay']['max']:.1f}s")
        print(f"  {Colors.BCYAN}UA Rotation:{Colors.BWHITE}    {'Enabled' if config['rotation']['user_agent'] else 'Disabled'}")
        print(f"  {Colors.BCYAN}Header Random:{Colors.BWHITE}  {'Enabled' if config['evasion']['randomize_headers'] else 'Disabled'}")
        print()
    
    def _save_config(self, config, output_file):
        """Save configuration to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            print_success(f"Configuration saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save configuration: {e}")
