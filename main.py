"""
BYMA TOOLS - Main Entry Point
Point of entry untuk semua operasi BYMA TOOLS dengan sistem login
"""
import os
import sys
import argparse
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.colors import (
    print_banner, print_success, print_error, print_warning,
    print_info, print_section, print_table, cprint, Colors, pause,
    print_header, print_footer, print_scan_start, print_scan_complete,
    print_vuln_found, print_loader, print_status, print_target,
    print_result, print_separator, print_subsection, Icons, clear_screen
)
from core.logger import get_logger
from core.database import get_database
from core.validator import get_validator, ValidationError
from core.user_manager import get_user_manager
from core.session import get_session_manager
from config.settings import (
    TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR, TOOL_DESCRIPTION
)


class BYMATools:
    """Main class untuk BYMA TOOLS"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.validator = get_validator()
        self.user_manager = get_user_manager()
        self.session = get_session_manager()
        self.parser = self._create_parser()
    
    def _create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            prog='byma',
            description=f'{TOOL_NAME} - {TOOL_DESCRIPTION}',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python main.py                        # Start interactive mode (with login)
  python main.py auto http://target.com # Direct command execution
  python main.py recon subdomain example.com
  python main.py scan vuln http://target.com
  python main.py stats
"""
        )
        
        parser.add_argument('--interactive', action='store_true',
                           help='Start interactive mode with login')
        
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Recon
        recon_parser = subparsers.add_parser('recon', help='Reconnaissance tools')
        recon_parser.add_argument('--subdomain', '-s', help='Enumerate subdomains')
        recon_parser.add_argument('--port', '-p', help='Scan ports')
        recon_parser.add_argument('--ports', default='1-1024', help='Port range')
        recon_parser.add_argument('--whois', '-w', help='WHOIS lookup')
        recon_parser.add_argument('--dns', '-d', help='DNS lookup')
        recon_parser.add_argument('--ip', '-i', help='IP geolocation')
        recon_parser.add_argument('--email', '-e', help='Email harvester')
        recon_parser.add_argument('--tech', '-t', help='Technology fingerprint')
        recon_parser.add_argument('--threads', type=int, default=50)
        recon_parser.add_argument('--output', '-o', help='Output file')
        recon_parser.add_argument('--format', choices=['text', 'json', 'csv'], default='json')
        
        # Scan
        scan_parser = subparsers.add_parser('scan', help='Vulnerability scanning')
        scan_parser.add_argument('--vuln', '-v', help='Vulnerability scan')
        scan_parser.add_argument('--sqli', help='SQL injection test')
        scan_parser.add_argument('--xss', help='XSS test')
        scan_parser.add_argument('--dir', help='Directory bruteforce')
        scan_parser.add_argument('--ssl', help='SSL/TLS check')
        scan_parser.add_argument('--threads', type=int, default=50)
        scan_parser.add_argument('--output', '-o', help='Output file')
        
        # Network
        network_parser = subparsers.add_parser('network', help='Network tools')
        network_parser.add_argument('--scan', help='Network scan')
        network_parser.add_argument('--port', help='Port scan')
        network_parser.add_argument('--ports', default='1-1024')
        network_parser.add_argument('--sniff', action='store_true')
        network_parser.add_argument('--arp', action='store_true')
        network_parser.add_argument('--target', help='Target IP')
        network_parser.add_argument('--gateway', help='Gateway IP')
        
        # Password
        password_parser = subparsers.add_parser('password', help='Password tools')
        password_parser.add_argument('--hash', help='Generate hash')
        password_parser.add_argument('--algo', default='md5', help='Hash algorithm')
        password_parser.add_argument('--crack', help='Crack hash file')
        password_parser.add_argument('--generate', action='store_true')
        password_parser.add_argument('--length', type=int, default=12)
        password_parser.add_argument('--count', type=int, default=10)
        password_parser.add_argument('--wordlist', help='Wordlist file')
        
        # Web
        web_parser = subparsers.add_parser('web', help='Web analysis')
        web_parser.add_argument('--crawl', help='Crawl website')
        web_parser.add_argument('--headers', help='Analyze headers')
        web_parser.add_argument('--proxy', action='store_true')
        
        # Exploit
        exploit_parser = subparsers.add_parser('exploit', help='Exploit tools')
        exploit_parser.add_argument('--reverse', nargs=2, metavar=('IP', 'PORT'))
        exploit_parser.add_argument('--webshell', action='store_true')
        exploit_parser.add_argument('--type', choices=['python', 'php', 'bash', 'powershell'])
        
        # Forensics
        forensics_parser = subparsers.add_parser('forensics', help='Forensics tools')
        forensics_parser.add_argument('--analyze', help='Analyze file')
        forensics_parser.add_argument('--strings', help='Extract strings')
        forensics_parser.add_argument('--hash', help='Check file hash')
        forensics_parser.add_argument('--min-length', type=int, default=4)
        forensics_parser.add_argument('--output', '-o')
        
        # Auto
        auto_parser = subparsers.add_parser('auto', help='Auto scan')
        auto_parser.add_argument('target', help='Target URL')
        auto_parser.add_argument('--mode', choices=['passive', 'aggressive'], default='passive')
        auto_parser.add_argument('--output', '-o')
        
        # WAF
        waf_parser = subparsers.add_parser('waf', help='WAF detection')
        waf_parser.add_argument('target', help='Target URL')
        waf_parser.add_argument('--output', '-o')
        
        # Credential
        cred_parser = subparsers.add_parser('credential', help='Credential harvesting')
        cred_parser.add_argument('target', help='Target URL')
        cred_parser.add_argument('--output', '-o')
        
        # Report
        report_parser = subparsers.add_parser('report', help='Generate report')
        report_parser.add_argument('--scan-id', type=int)
        report_parser.add_argument('--output-dir', default='output/reports')
        
        # Stealth
        stealth_parser = subparsers.add_parser('stealth', help='Stealth mode')
        stealth_parser.add_argument('--scan', help='Target to scan')
        stealth_parser.add_argument('--decoy', action='store_true')
        stealth_parser.add_argument('--slow', action='store_true')
        stealth_parser.add_argument('--ports', default='1-1024')
        stealth_parser.add_argument('--delay', type=float, default=1.0)
        
        # Plugin
        plugin_parser = subparsers.add_parser('plugin', help='Plugin management')
        plugin_parser.add_argument('--list', action='store_true')
        plugin_parser.add_argument('--run', help='Run plugin')
        plugin_parser.add_argument('--create', help='Create plugin')
        plugin_parser.add_argument('--uninstall', help='Uninstall plugin')
        
        # API
        api_parser = subparsers.add_parser('api', help='REST API server')
        api_parser.add_argument('--host', default='0.0.0.0')
        api_parser.add_argument('--port', type=int, default=8080)
        
        # Other commands
        subparsers.add_parser('stats', help='Show statistics')
        subparsers.add_parser('history', help='Show scan history')
        subparsers.add_parser('version', help='Show version')
        subparsers.add_parser('update', help='Update BYMA TOOLS')
        
        clear_parser = subparsers.add_parser('clear', help='Clear screen/database')
        clear_parser.add_argument('--database', action='store_true')
        
        return parser
    
    def run(self):
        """Main run method"""
        args = self.parser.parse_args()
        
        # No command = interactive mode
        if not args.command:
            self._run_interactive()
            return
        
        # Direct command execution (skip login)
        self._execute_command(args)
    
    def _run_interactive(self):
        """Run interactive mode with login"""
        clear_screen()
        print_banner()
        
        # Check if users exist
        if not self.user_manager.has_users():
            print_header("WELCOME - PERTAMA KALI MENGGUNAKAN BYMA TOOLS")
            cprint("  Anda perlu membuat akun terlebih dahulu.", Colors.BYELLOW)
            print()
            self._register_first_user()
        
        # Login menu
        while True:
            if self.user_manager.is_logged_in():
                self._show_main_menu()
            else:
                self._show_login_menu()
    
    def _register_first_user(self):
        """Register first user"""
        print_subsection("Buat Akun Baru")
        
        while True:
            try:
                username = input("  Username: ").strip()
                if not username:
                    continue
                
                password = input("  Password: ").strip()
                if not password:
                    continue
                
                email = input("  Email (opsional): ").strip() or None
                
                success, message = self.user_manager.register(username, password, email)
                
                if success:
                    print_success(message)
                    # Auto login
                    self.user_manager.login(username, password)
                    break
                else:
                    print_error(message)
            except KeyboardInterrupt:
                print()
                cprint("  [-] Dibatalkan oleh user", Colors.BRED)
                sys.exit(0)
    
    def _show_login_menu(self):
        """Show login menu"""
        print_header("LOGIN")
        
        options = {
            "1": "[>] Login",
            "2": "[+] Register (Buat Akun Baru)",
            "3": "[X] Keluar"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (1-3): ").strip()
                
                if choice == "1":
                    self._login()
                    break
                elif choice == "2":
                    self._register()
                    break
                elif choice == "3":
                    self._exit_program()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._exit_program()
    
    def _login(self):
        """Login process"""
        print_subsection("Login")
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                username = input("  Username: ").strip()
                password = input("  Password: ").strip()
                
                success, message = self.user_manager.login(username, password)
                
                if success:
                    print_success(message)
                    self.logger.action("LOGIN", f"User: {username}")
                    pause()
                    return
                else:
                    print_error(message)
                    if attempt < max_attempts - 1:
                        cprint(f"  Sisa percobaan: {max_attempts - attempt - 1}", Colors.BYELLOW)
            except KeyboardInterrupt:
                print()
                self._exit_program()
        
        print_error("Terlalu banyak percobaan gagal!")
        pause()
    
    def _register(self):
        """Register new user"""
        print_subsection("Register Akun Baru")
        
        while True:
            try:
                username = input("  Username (min 3 karakter): ").strip()
                if not username:
                    continue
                
                password = input("  Password (min 4 karakter): ").strip()
                if not password:
                    continue
                
                confirm = input("  Konfirmasi Password: ").strip()
                if password != confirm:
                    print_error("Password tidak cocok!")
                    continue
                
                email = input("  Email (opsional, tekan Enter untuk skip): ").strip() or None
                
                success, message = self.user_manager.register(username, password, email)
                
                if success:
                    print_success(message)
                    print_info("Silakan login dengan akun baru Anda")
                    pause()
                    return
                else:
                    print_error(message)
            except KeyboardInterrupt:
                print()
                return
    
    def _show_main_menu(self):
        """Show main menu after login"""
        clear_screen()
        print_banner()
        
        # User info
        user = self.user_manager.get_current_user()
        cprint(f"  Selamat datang, {Colors.BGREEN}{user}{Colors.BCYAN}!", Colors.BCYAN)
        print_separator("=", 60, Colors.BCYAN)
        print()
        
        # Main menu
        print_header("MENU UTAMA")
        
        options = {
            "1": "[>] Reconnaissance (Pengintaian)",
            "2": "[S] Vulnerability Scanner",
            "3": "[N] Network Tools",
            "4": "[P] Password Tools",
            "5": "[W] Web Analysis",
            "6": "[E] Exploit Tools",
            "7": "[F] Forensics",
            "8": "[A] Auto Scan (Cerdas)",
            "9": "[R] Generate Report",
            "10": "[U] Plugin Manager",
            "11": "[D] Database & Statistics",
            "12": "[L] Logout",
            "0": "[X] Keluar"
        }
        
        for key, value in options.items():
            if key in ["12", "0"]:
                print()
            cprint(f"  {key:>2}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih menu (0-12): ").strip()
                
                if choice == "1":
                    self._show_recon_menu()
                elif choice == "2":
                    self._show_scan_menu()
                elif choice == "3":
                    self._show_network_menu()
                elif choice == "4":
                    self._show_password_menu()
                elif choice == "5":
                    self._show_web_menu()
                elif choice == "6":
                    self._show_exploit_menu()
                elif choice == "7":
                    self._show_forensics_menu()
                elif choice == "8":
                    self._run_auto_scan()
                elif choice == "9":
                    self._run_report()
                elif choice == "10":
                    self._show_plugin_menu()
                elif choice == "11":
                    self._show_database_menu()
                elif choice == "12":
                    self._logout()
                elif choice == "0":
                    self._exit_program()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._exit_program()
    
    def _show_recon_menu(self):
        """Reconnaissance submenu"""
        self.session.push_menu("main")
        clear_screen()
        print_banner()
        print_header("RECONNAISSANCE TOOLS")
        
        options = {
            "1": "[S] Subdomain Enumeration",
            "2": "[P] Port Scanning",
            "3": "[W] WHOIS Lookup",
            "4": "[D] DNS Lookup",
            "5": "[I] IP Geolocation",
            "6": "[E] Email Harvesting",
            "7": "[T] Technology Fingerprint",
            "0": "[<] Kembali ke Menu Utama"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (0-7): ").strip()
                
                if choice == "0":
                    self._go_back()
                elif choice == "1":
                    self._run_recon_subdomain()
                elif choice == "2":
                    self._run_recon_port()
                elif choice == "3":
                    self._run_recon_whois()
                elif choice == "4":
                    self._run_recon_dns()
                elif choice == "5":
                    self._run_recon_ip()
                elif choice == "6":
                    self._run_recon_email()
                elif choice == "7":
                    self._run_recon_tech()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._go_back()
    
    def _show_scan_menu(self):
        """Scanner submenu"""
        self.session.push_menu("main")
        clear_screen()
        print_banner()
        print_header("VULNERABILITY SCANNER")
        
        options = {
            "1": "[V] General Vulnerability Scan",
            "2": "[S] SQL Injection Test",
            "3": "[X] XSS Scanner",
            "4": "[D] Directory Bruteforce",
            "5": "[L] SSL/TLS Checker",
            "6": "[C] CORS Scanner",
            "7": "[W] WAF Detection",
            "0": "[<] Kembali ke Menu Utama"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (0-7): ").strip()
                
                if choice == "0":
                    self._go_back()
                elif choice == "1":
                    self._run_scan_vuln()
                elif choice == "2":
                    self._run_scan_sqli()
                elif choice == "3":
                    self._run_scan_xss()
                elif choice == "4":
                    self._run_scan_dir()
                elif choice == "5":
                    self._run_scan_ssl()
                elif choice == "6":
                    self._run_scan_cors()
                elif choice == "7":
                    self._run_scan_waf()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._go_back()
    
    def _show_network_menu(self):
        """Network submenu"""
        self.session.push_menu("main")
        clear_screen()
        print_banner()
        print_header("NETWORK TOOLS")
        
        options = {
            "1": "[S] Network Scan (ARP Discovery)",
            "2": "[P] Port Scan",
            "3": "[N] Packet Sniffer",
            "4": "[A] ARP Spoofing",
            "5": "[T] Stealth Scan",
            "0": "[<] Kembali ke Menu Utama"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (0-5): ").strip()
                
                if choice == "0":
                    self._go_back()
                elif choice == "1":
                    self._run_network_scan()
                elif choice == "2":
                    self._run_network_port()
                elif choice == "3":
                    self._run_network_sniff()
                elif choice == "4":
                    self._run_network_arp()
                elif choice == "5":
                    self._run_stealth()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._go_back()
    
    def _show_password_menu(self):
        """Password submenu"""
        self.session.push_menu("main")
        clear_screen()
        print_banner()
        print_header("PASSWORD TOOLS")
        
        options = {
            "1": "[H] Generate Hash",
            "2": "[C] Crack Hash",
            "3": "[G] Generate Password",
            "4": "[B] Brute Force",
            "0": "[<] Kembali ke Menu Utama"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (0-4): ").strip()
                
                if choice == "0":
                    self._go_back()
                elif choice == "1":
                    self._run_password_hash()
                elif choice == "2":
                    self._run_password_crack()
                elif choice == "3":
                    self._run_password_generate()
                elif choice == "4":
                    self._run_password_brute()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._go_back()
    
    def _show_web_menu(self):
        """Web submenu"""
        self.session.push_menu("main")
        clear_screen()
        print_banner()
        print_header("WEB ANALYSIS")
        
        options = {
            "1": "[C] Crawl Website",
            "2": "[H] Analyze HTTP Headers",
            "3": "[P] Proxy Scraper",
            "0": "[<] Kembali ke Menu Utama"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (0-3): ").strip()
                
                if choice == "0":
                    self._go_back()
                elif choice == "1":
                    self._run_web_crawl()
                elif choice == "2":
                    self._run_web_headers()
                elif choice == "3":
                    self._run_web_proxy()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._go_back()
    
    def _show_exploit_menu(self):
        """Exploit submenu"""
        self.session.push_menu("main")
        clear_screen()
        print_banner()
        print_header("EXPLOIT TOOLS")
        
        options = {
            "1": "[R] Reverse Shell Generator",
            "2": "[W] Webshell Generator",
            "3": "[C] Credential Harvester",
            "0": "[<] Kembali ke Menu Utama"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (0-3): ").strip()
                
                if choice == "0":
                    self._go_back()
                elif choice == "1":
                    self._run_exploit_reverse()
                elif choice == "2":
                    self._run_exploit_webshell()
                elif choice == "3":
                    self._run_credential()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._go_back()
    
    def _show_forensics_menu(self):
        """Forensics submenu"""
        self.session.push_menu("main")
        clear_screen()
        print_banner()
        print_header("FORENSICS TOOLS")
        
        options = {
            "1": "[A] Analyze File",
            "2": "[S] Extract Strings",
            "3": "[H] Check File Hash",
            "0": "[<] Kembali ke Menu Utama"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (0-3): ").strip()
                
                if choice == "0":
                    self._go_back()
                elif choice == "1":
                    self._run_forensics_analyze()
                elif choice == "2":
                    self._run_forensics_strings()
                elif choice == "3":
                    self._run_forensics_hash()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._go_back()
    
    def _show_plugin_menu(self):
        """Plugin submenu"""
        self.session.push_menu("main")
        clear_screen()
        print_banner()
        print_header("PLUGIN MANAGER")
        
        options = {
            "1": "[L] List Plugins",
            "2": "[R] Run Plugin",
            "3": "[C] Create Plugin",
            "4": "[D] Delete Plugin",
            "0": "[<] Kembali ke Menu Utama"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (0-4): ").strip()
                
                if choice == "0":
                    self._go_back()
                elif choice == "1":
                    self._run_plugin_list()
                elif choice == "2":
                    self._run_plugin_run()
                elif choice == "3":
                    self._run_plugin_create()
                elif choice == "4":
                    self._run_plugin_delete()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._go_back()
    
    def _show_database_menu(self):
        """Database submenu"""
        self.session.push_menu("main")
        clear_screen()
        print_banner()
        print_header("DATABASE & STATISTICS")
        
        options = {
            "1": "[S] Show Statistics",
            "2": "[H] Scan History",
            "3": "[C] Clear Database",
            "0": "[<] Kembali ke Menu Utama"
        }
        
        for key, value in options.items():
            cprint(f"  {key}. {value}", Colors.BWHITE)
        
        print()
        
        while True:
            try:
                choice = input("  Pilih (0-3): ").strip()
                
                if choice == "0":
                    self._go_back()
                elif choice == "1":
                    self._show_stats()
                    pause()
                elif choice == "2":
                    self._show_history()
                    pause()
                elif choice == "3":
                    self._clear_database()
                else:
                    print_error("Pilihan tidak valid!")
            except KeyboardInterrupt:
                self._go_back()
    
    def _go_back(self):
        """Go back to previous menu"""
        current = self.session.go_back()
        if current == "main":
            self._show_main_menu()
        else:
            self._show_main_menu()
    
    def _logout(self):
        """Logout user"""
        self.user_manager.logout()
        self.session.clear_history()
        print_success("Anda telah logout!")
        pause()
        self._run_interactive()
    
    def _exit_program(self):
        """Exit program"""
        print()
        print_header("TERIMA KASIH!")
        cprint("  Terima kasih telah menggunakan BYMA TOOLS!", Colors.BGREEN)
        cprint("  Sampai jumpa! 👋", Colors.BYELLOW)
        print()
        sys.exit(0)
    
    def _ask_continue(self, tool_name=""):
        """Ask to continue"""
        choice = self.session.ask_continue_or_exit(tool_name)
        
        if choice == "1":
            return True  # Continue to main menu
        elif choice == "2":
            return True  # Go back
        elif choice == "3":
            return True  # Use another tool
        else:
            self._exit_program()
        return False
    
    # ==================== TOOL EXECUTION METHODS ====================
    
    def _execute_command(self, args):
        """Execute command from CLI"""
        try:
            if args.command == 'recon':
                self._handle_recon(args)
            elif args.command == 'scan':
                self._handle_scan(args)
            elif args.command == 'network':
                self._handle_network(args)
            elif args.command == 'password':
                self._handle_password(args)
            elif args.command == 'web':
                self._handle_web(args)
            elif args.command == 'exploit':
                self._handle_exploit(args)
            elif args.command == 'forensics':
                self._handle_forensics(args)
            elif args.command == 'auto':
                self._handle_auto(args)
            elif args.command == 'waf':
                self._handle_waf(args)
            elif args.command == 'credential':
                self._handle_credential(args)
            elif args.command == 'report':
                self._handle_report(args)
            elif args.command == 'stealth':
                self._handle_stealth(args)
            elif args.command == 'plugin':
                self._handle_plugin(args)
            elif args.command == 'api':
                self._handle_api(args)
            elif args.command == 'stats':
                self._show_stats()
            elif args.command == 'history':
                self._show_history()
            elif args.command == 'version':
                self._show_version()
            elif args.command == 'update':
                self._update_tools()
            elif args.command == 'clear':
                self._clear_screen(args)
            else:
                self.parser.print_help()
        except KeyboardInterrupt:
            print()
            print_warning("Operation cancelled by user")
        except ValidationError as e:
            print_error(str(e))
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            self.logger.error(f"Unexpected error: {e}")
    
    def _handle_recon(self, args):
        """Handle recon commands"""
        from tools.recon.subdomain import SubdomainEnumerator
        from tools.recon.port_scanner import PortScanner
        from tools.recon.whois_lookup import WhoisLookup
        from tools.recon.dns_lookup import DNSLookup
        from tools.recon.ip_lookup import IPLookup
        from tools.recon.email_harvest import EmailHarvester
        from tools.recon.tech_fingerprint import TechFingerprint
        
        if args.subdomain:
            enumerator = SubdomainEnumerator()
            enumerator.enumerate(args.subdomain, threads=args.threads, output=args.output)
        elif args.port:
            scanner = PortScanner()
            scanner.scan(args.port, ports=args.ports, threads=args.threads, output=args.output)
        elif args.whois:
            whois = WhoisLookup()
            whois.lookup(args.whois, output=args.output)
        elif args.dns:
            dns = DNSLookup()
            dns.lookup(args.dns, output=args.output)
        elif args.ip:
            ip = IPLookup()
            ip.lookup(args.ip, output=args.output)
        elif args.email:
            harvester = EmailHarvester()
            harvester.harvest(args.email, threads=args.threads, output=args.output)
        elif args.tech:
            tech = TechFingerprint()
            tech.fingerprint(args.tech, output=args.output)
        else:
            print_error("Please specify a recon tool to use")
    
    def _handle_scan(self, args):
        """Handle scan commands"""
        from tools.scanner.vuln_scanner import VulnScanner
        from tools.scanner.sql_injection import SQLInjectionScanner
        from tools.scanner.xss_scanner import XSSScanner
        from tools.scanner.dir_bruteforce import DirectoryBruteforcer
        from tools.scanner.ssl_checker import SSLChecker
        
        if args.vuln:
            scanner = VulnScanner()
            scanner.scan(args.vuln, threads=args.threads, output=args.output)
        elif args.sqli:
            scanner = SQLInjectionScanner()
            scanner.scan(args.sqli, threads=args.threads, output=args.output)
        elif args.xss:
            scanner = XSSScanner()
            scanner.scan(args.xss, threads=args.threads, output=args.output)
        elif args.dir:
            scanner = DirectoryBruteforcer()
            scanner.scan(args.dir, threads=args.threads, output=args.output)
        elif args.ssl:
            checker = SSLChecker()
            checker.check(args.ssl, output=args.output)
        else:
            print_error("Please specify a scan tool to use")
    
    def _handle_network(self, args):
        """Handle network commands"""
        from tools.network.network_scan import NetworkScanner
        from tools.network.arp_spoof import ARPSpoof
        from tools.network.packet_sniffer import PacketSniffer
        
        if args.scan:
            scanner = NetworkScanner()
            scanner.scan(args.scan, output=args.output)
        elif args.port:
            scanner = NetworkScanner()
            scanner.scan_ports(args.port, ports=args.ports, output=args.output)
        elif args.sniff:
            sniffer = PacketSniffer()
            sniffer.sniff(output=args.output)
        elif args.arp:
            if not args.target or not args.gateway:
                print_error("ARP spoofing requires --target and --gateway")
            else:
                spoofer = ARPSpoof()
                spoofer.spoof(args.target, args.gateway)
        else:
            print_error("Please specify a network tool to use")
    
    def _handle_password(self, args):
        """Handle password commands"""
        from tools.password.hash_cracker import HashCracker
        from tools.password.password_gen import PasswordGenerator
        from tools.password.brute_force import BruteForceAttacker
        
        if args.hash:
            generator = PasswordGenerator()
            generator.hash_password(args.hash, algorithm=args.algo)
        elif args.crack:
            cracker = HashCracker()
            cracker.crack(args.crack, algorithm=args.algo, 
                         wordlist=args.wordlist, output=args.output)
        elif args.generate:
            generator = PasswordGenerator()
            generator.generate(length=args.length, count=args.count)
        else:
            print_error("Please specify a password tool to use")
    
    def _handle_web(self, args):
        """Handle web commands"""
        from tools.web.crawler import WebCrawler
        from tools.web.header_analyzer import HeaderAnalyzer
        from tools.web.proxy_scraper import ProxyScraper
        
        if args.crawl:
            crawler = WebCrawler()
            crawler.crawl(args.crawl, output=args.output)
        elif args.headers:
            analyzer = HeaderAnalyzer()
            analyzer.analyze(args.headers, output=args.output)
        elif args.proxy:
            scraper = ProxyScraper()
            scraper.scrape(output=args.output)
        else:
            print_error("Please specify a web tool to use")
    
    def _handle_exploit(self, args):
        """Handle exploit commands"""
        from tools.exploit.reverse_shell import ReverseShellGenerator
        from tools.exploit.webshell_gen import WebshellGenerator
        
        if args.reverse:
            ip, port = args.reverse
            generator = ReverseShellGenerator()
            generator.generate(ip, int(port), shell_type=args.type or 'python')
        elif args.webshell:
            generator = WebshellGenerator()
            generator.generate(shell_type=args.type or 'php')
        else:
            print_error("Please specify an exploit tool to use")
    
    def _handle_forensics(self, args):
        """Handle forensics commands"""
        from tools.forensics.file_analyzer import FileAnalyzer
        from tools.forensics.strings_extractor import StringsExtractor
        from tools.forensics.hash_checker import HashChecker
        
        if args.analyze:
            analyzer = FileAnalyzer()
            analyzer.analyze(args.analyze, output=args.output)
        elif args.strings:
            extractor = StringsExtractor()
            extractor.extract(args.strings, min_length=args.min_length,
                            output=args.output)
        elif args.hash:
            checker = HashChecker()
            checker.check(args.hash, output=args.output)
        else:
            print_error("Please specify a forensics tool to use")
    
    def _handle_auto(self, args):
        """Handle auto scan"""
        from tools.scanner.auto_engine import AutoScanEngine
        engine = AutoScanEngine()
        engine.auto_scan(args.target, mode=args.mode, output=args.output)
    
    def _handle_waf(self, args):
        """Handle WAF detection"""
        from tools.scanner.waf_detect import WAFDetector
        detector = WAFDetector()
        detector.detect(args.target, output=args.output)
    
    def _handle_credential(self, args):
        """Handle credential harvesting"""
        from tools.exploit.credential_harvest import CredentialHarvester
        harvester = CredentialHarvester()
        harvester.harvest(args.target, output=args.output)
    
    def _handle_report(self, args):
        """Handle report generation"""
        from tools.utils.report_generator import ReportGenerator
        generator = ReportGenerator()
        generator.generate(scan_id=args.scan_id, output_dir=args.output_dir)
    
    def _handle_stealth(self, args):
        """Handle stealth commands"""
        from tools.utils.stealth import StealthMode
        stealth = StealthMode()
        
        if args.scan:
            stealth.stealth_scan(args.scan, ports=args.ports, delay=args.delay)
        elif args.decoy:
            stealth.decoy_scan(args.scan, ports=args.ports)
        elif args.slow:
            stealth.slow_scan(args.scan, ports=args.ports)
        else:
            print_error("Please specify a stealth mode option")
    
    def _handle_plugin(self, args):
        """Handle plugin commands"""
        from tools.utils.plugin_manager import PluginManager
        manager = PluginManager()
        manager.load_plugins()
        
        if args.list:
            manager.list_plugins()
        elif args.run:
            manager.run_plugin(args.run)
        elif args.create:
            manager.create_plugin_template(args.create, f"Custom plugin: {args.create}")
        elif args.uninstall:
            manager.uninstall_plugin(args.uninstall)
        else:
            manager.list_plugins()
    
    def _handle_api(self, args):
        """Handle API server"""
        from tools.utils.api_server import APIServer
        server = APIServer(host=args.host, port=args.port)
        server.start()
    
    def _show_version(self):
        """Show version info"""
        print_header("Version Information")
        print()
        print(f"  {Icons.COMPUTER} {Colors.BCYAN}Tool:{Colors.BWHITE}        {TOOL_NAME}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Version:{Colors.BWHITE}     {TOOL_VERSION}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Author:{Colors.BWHITE}      {TOOL_AUTHOR}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Description:{Colors.BWHITE} {TOOL_DESCRIPTION}")
        print()
        print_separator()
        print()
    
    def _show_stats(self):
        """Show database statistics"""
        print_header("Database Statistics")
        
        stats = self.db.get_statistics()
        
        print(f"  {Icons.DATABASE} {Colors.BCYAN}Total Scans:{Colors.BWHITE}         {stats.get('total_scans', 0)}")
        print(f"  {Icons.GLOBE} {Colors.BCYAN}Total Subdomains:{Colors.BWHITE}    {stats.get('total_subdomains', 0)}")
        print(f"  {Icons.NETWORK} {Colors.BCYAN}Total Ports:{Colors.BWHITE}         {stats.get('total_ports', 0)}")
        print(f"  {Icons.WARNING} {Colors.BCYAN}Total Vulnerabilities:{Colors.BWHITE} {stats.get('total_vulnerabilities', 0)}")
        print(f"  {Icons.KEY} {Colors.BCYAN}Cracked Hashes:{Colors.BWHITE}     {stats.get('cracked_hashes', 0)}")
        print(f"  {Icons.LOCK} {Colors.BCYAN}Total Credentials:{Colors.BWHITE}  {stats.get('total_credentials', 0)}")
        
        if stats.get('vulns_by_severity'):
            print_subsection("Vulnerabilities by Severity")
            for row in stats['vulns_by_severity']:
                severity = row['severity'] or 'Unknown'
                count = row['count']
                print(f"    {Colors.BYELLOW}{Icons.BULLET} {severity}: {Colors.BWHITE}{count}")
    
    def _show_history(self):
        """Show scan history"""
        print_header("Scan History")
        
        scans = self.db.get_scans(limit=20)
        
        if not scans:
            print_warning("No scan history found")
            return
        
        headers = ["ID", "Tool", "Target", "Status", "Time"]
        rows = []
        for scan in scans:
            rows.append([
                scan['id'],
                scan['tool_name'],
                scan['target'][:30] + ('...' if len(scan['target']) > 30 else ''),
                scan['status'],
                scan['start_time']
            ])
        
        print_table(headers, rows)
    
    def _clear_screen(self, args):
        """Clear screen or database"""
        if args.database:
            print_warning("This will clear all data in the database!")
            confirm = input("Are you sure? (y/N): ")
            if confirm.lower() == 'y':
                with self.db._cursor() as cursor:
                    for table in ['scans', 'subdomains', 'ports', 'vulnerabilities',
                                  'hashes', 'credentials', 'dns_records', 'network_hosts',
                                  'audit_log']:
                        cursor.execute(f"DELETE FROM {table}")
                print_success("Database cleared")
            else:
                print_info("Operation cancelled")
        else:
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
    
    def _update_tools(self):
        """Update BYMA TOOLS"""
        print_info("Checking for updates...")
        print_warning("Auto-update not yet implemented")
        print_info("Please visit the GitHub repository for updates")
    
    # ==================== INTERACTIVE TOOL RUNNERS ====================
    
    def _run_recon_subdomain(self):
        """Run subdomain enumeration interactively"""
        print_subsection("Subdomain Enumeration")
        target = input("  Masukkan target domain: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Subdomain Enumeration")
        
        try:
            from tools.recon.subdomain import SubdomainEnumerator
            enumerator = SubdomainEnumerator()
            enumerator.enumerate(target, threads=50)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Subdomain Enumeration")
        self._show_recon_menu()
    
    def _run_recon_port(self):
        """Run port scan interactively"""
        print_subsection("Port Scanning")
        target = input("  Masukkan target IP/hostname: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Port Scanning")
        
        try:
            from tools.recon.port_scanner import PortScanner
            scanner = PortScanner()
            scanner.scan(target, ports="1-1024", threads=50)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Port Scanning")
        self._show_recon_menu()
    
    def _run_recon_whois(self):
        """Run WHOIS lookup interactively"""
        print_subsection("WHOIS Lookup")
        target = input("  Masukkan domain: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "WHOIS Lookup")
        
        try:
            from tools.recon.whois_lookup import WhoisLookup
            whois = WhoisLookup()
            whois.lookup(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("WHOIS Lookup")
        self._show_recon_menu()
    
    def _run_recon_dns(self):
        """Run DNS lookup interactively"""
        print_subsection("DNS Lookup")
        target = input("  Masukkan domain: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "DNS Lookup")
        
        try:
            from tools.recon.dns_lookup import DNSLookup
            dns = DNSLookup()
            dns.lookup(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("DNS Lookup")
        self._show_recon_menu()
    
    def _run_recon_ip(self):
        """Run IP lookup interactively"""
        print_subsection("IP Geolocation")
        target = input("  Masukkan IP address: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "IP Geolocation")
        
        try:
            from tools.recon.ip_lookup import IPLookup
            ip = IPLookup()
            ip.lookup(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("IP Geolocation")
        self._show_recon_menu()
    
    def _run_recon_email(self):
        """Run email harvester interactively"""
        print_subsection("Email Harvesting")
        target = input("  Masukkan domain: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Email Harvesting")
        
        try:
            from tools.recon.email_harvest import EmailHarvester
            harvester = EmailHarvester()
            harvester.harvest(target, threads=50)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Email Harvesting")
        self._show_recon_menu()
    
    def _run_recon_tech(self):
        """Run tech fingerprint interactively"""
        print_subsection("Technology Fingerprint")
        target = input("  Masukkan URL: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Technology Fingerprint")
        
        try:
            from tools.recon.tech_fingerprint import TechFingerprint
            tech = TechFingerprint()
            tech.fingerprint(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Technology Fingerprint")
        self._show_recon_menu()
    
    def _run_scan_vuln(self):
        """Run vuln scan interactively"""
        print_subsection("Vulnerability Scan")
        target = input("  Masukkan URL target: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Vulnerability Scan")
        
        try:
            from tools.scanner.vuln_scanner import VulnScanner
            scanner = VulnScanner()
            scanner.scan(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Vulnerability Scan")
        self._show_scan_menu()
    
    def _run_scan_sqli(self):
        """Run SQLi scan interactively"""
        print_subsection("SQL Injection Test")
        target = input("  Masukkan URL dengan parameter: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "SQL Injection Test")
        
        try:
            from tools.scanner.sql_injection import SQLInjectionScanner
            scanner = SQLInjectionScanner()
            scanner.scan(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("SQL Injection Test")
        self._show_scan_menu()
    
    def _run_scan_xss(self):
        """Run XSS scan interactively"""
        print_subsection("XSS Scanner")
        target = input("  Masukkan URL dengan parameter: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "XSS Scanner")
        
        try:
            from tools.scanner.xss_scanner import XSSScanner
            scanner = XSSScanner()
            scanner.scan(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("XSS Scanner")
        self._show_scan_menu()
    
    def _run_scan_dir(self):
        """Run directory bruteforce interactively"""
        print_subsection("Directory Bruteforce")
        target = input("  Masukkan URL target: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Directory Bruteforce")
        
        try:
            from tools.scanner.dir_bruteforce import DirectoryBruteforcer
            scanner = DirectoryBruteforcer()
            scanner.scan(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Directory Bruteforce")
        self._show_scan_menu()
    
    def _run_scan_ssl(self):
        """Run SSL check interactively"""
        print_subsection("SSL/TLS Checker")
        target = input("  Masukkan hostname: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "SSL/TLS Check")
        
        try:
            from tools.scanner.ssl_checker import SSLChecker
            checker = SSLChecker()
            checker.check(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("SSL/TLS Check")
        self._show_scan_menu()
    
    def _run_scan_cors(self):
        """Run CORS scan interactively"""
        print_subsection("CORS Scanner")
        target = input("  Masukkan URL target: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "CORS Scan")
        
        try:
            from tools.scanner.cors_scanner import CORSScanner
            scanner = CORSScanner()
            scanner.scan(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("CORS Scan")
        self._show_scan_menu()
    
    def _run_scan_waf(self):
        """Run WAF detection interactively"""
        print_subsection("WAF Detection")
        target = input("  Masukkan URL target: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "WAF Detection")
        
        try:
            from tools.scanner.waf_detect import WAFDetector
            detector = WAFDetector()
            detector.detect(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("WAF Detection")
        self._show_scan_menu()
    
    def _run_network_scan(self):
        """Run network scan interactively"""
        print_subsection("Network Scan")
        target = input("  Masukkan network range (contoh: 192.168.1.0/24): ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Network Scan")
        
        try:
            from tools.network.network_scan import NetworkScanner
            scanner = NetworkScanner()
            scanner.scan(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Network Scan")
        self._show_network_menu()
    
    def _run_network_port(self):
        """Run port scan interactively"""
        print_subsection("Port Scan")
        target = input("  Masukkan target IP: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Port Scan")
        
        try:
            from tools.network.network_scan import NetworkScanner
            scanner = NetworkScanner()
            scanner.scan_ports(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Port Scan")
        self._show_network_menu()
    
    def _run_network_sniff(self):
        """Run packet sniffer interactively"""
        print_subsection("Packet Sniffer")
        print_warning("Fitur ini membutuhkan hak akses administrator!")
        
        confirm = input("  Lanjutkan? (y/N): ").strip()
        if confirm.lower() != 'y':
            return
        
        print_scan_start("Network", "Packet Sniffer")
        
        try:
            from tools.network.packet_sniffer import PacketSniffer
            sniffer = PacketSniffer()
            sniffer.sniff()
            print_scan_complete("Network", "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Packet Sniffer")
        self._show_network_menu()
    
    def _run_network_arp(self):
        """Run ARP spoof interactively"""
        print_subsection("ARP Spoofing")
        print_warning("Fitur ini membutuhkan hak akses administrator!")
        
        target = input("  Masukkan target IP: ").strip()
        gateway = input("  Masukkan gateway IP: ").strip()
        
        if not target or not gateway:
            print_error("Target dan gateway tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(f"{target} -> {gateway}", "ARP Spoofing")
        
        try:
            from tools.network.arp_spoof import ARPSpoof
            spoofer = ARPSpoof()
            spoofer.spoof(target, gateway)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("ARP Spoofing")
        self._show_network_menu()
    
    def _run_password_hash(self):
        """Run password hash interactively"""
        print_subsection("Generate Hash")
        text = input("  Masukkan teks: ").strip()
        
        if not text:
            print_error("Teks tidak boleh kosong!")
            pause()
            return
        
        from tools.password.password_gen import PasswordGenerator
        generator = PasswordGenerator()
        generator.hash_password(text)
        
        self._ask_continue("Hash Generator")
        self._show_password_menu()
    
    def _run_password_crack(self):
        """Run hash crack interactively"""
        print_subsection("Crack Hash")
        hash_value = input("  Masukkan hash: ").strip()
        algo = input("  Algoritma (md5/sha1/sha256) [md5]: ").strip() or "md5"
        
        if not hash_value:
            print_error("Hash tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(hash_value[:20] + "...", "Hash Cracking")
        
        try:
            from tools.password.hash_cracker import HashCracker
            cracker = HashCracker()
            cracker.crack(hash_value, algorithm=algo)
            print_scan_complete(hash_value[:20] + "...", "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Hash Cracker")
        self._show_password_menu()
    
    def _run_password_generate(self):
        """Run password generator interactively"""
        print_subsection("Generate Password")
        
        try:
            length = int(input("  Panjang password [12]: ").strip() or "12")
            count = int(input("  Jumlah password [5]: ").strip() or "5")
        except ValueError:
            length = 12
            count = 5
        
        from tools.password.password_gen import PasswordGenerator
        generator = PasswordGenerator()
        generator.generate(length=length, count=count)
        
        self._ask_continue("Password Generator")
        self._show_password_menu()
    
    def _run_password_brute(self):
        """Run brute force interactively"""
        print_subsection("Brute Force")
        print_warning("Brute force membutuhkan waktu lama!")
        
        target = input("  Masukkan target URL: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Brute Force")
        
        try:
            from tools.password.brute_force import BruteForceAttacker
            attacker = BruteForceAttacker()
            attacker.attack(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Brute Force")
        self._show_password_menu()
    
    def _run_web_crawl(self):
        """Run web crawler interactively"""
        print_subsection("Web Crawler")
        target = input("  Masukkan URL: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Web Crawler")
        
        try:
            from tools.web.crawler import WebCrawler
            crawler = WebCrawler()
            crawler.crawl(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Web Crawler")
        self._show_web_menu()
    
    def _run_web_headers(self):
        """Run header analyzer interactively"""
        print_subsection("HTTP Header Analyzer")
        target = input("  Masukkan URL: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Header Analysis")
        
        try:
            from tools.web.header_analyzer import HeaderAnalyzer
            analyzer = HeaderAnalyzer()
            analyzer.analyze(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Header Analyzer")
        self._show_web_menu()
    
    def _run_web_proxy(self):
        """Run proxy scraper interactively"""
        print_subsection("Proxy Scraper")
        
        print_scan_start("Proxy Lists", "Proxy Scraper")
        
        try:
            from tools.web.proxy_scraper import ProxyScraper
            scraper = ProxyScraper()
            scraper.scrape()
            print_scan_complete("Proxy Lists", "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Proxy Scraper")
        self._show_web_menu()
    
    def _run_exploit_reverse(self):
        """Run reverse shell generator interactively"""
        print_subsection("Reverse Shell Generator")
        ip = input("  Masukkan IP address: ").strip()
        port = input("  Masukkan port: ").strip()
        shell_type = input("  Tipe shell (python/php/bash/powershell) [python]: ").strip() or "python"
        
        if not ip or not port:
            print_error("IP dan port tidak boleh kosong!")
            pause()
            return
        
        from tools.exploit.reverse_shell import ReverseShellGenerator
        generator = ReverseShellGenerator()
        generator.generate(ip, int(port), shell_type=shell_type)
        
        self._ask_continue("Reverse Shell Generator")
        self._show_exploit_menu()
    
    def _run_exploit_webshell(self):
        """Run webshell generator interactively"""
        print_subsection("Webshell Generator")
        shell_type = input("  Tipe webshell (php/asp/jsp) [php]: ").strip() or "php"
        
        from tools.exploit.webshell_gen import WebshellGenerator
        generator = WebshellGenerator()
        generator.generate(shell_type=shell_type)
        
        self._ask_continue("Webshell Generator")
        self._show_exploit_menu()
    
    def _run_credential(self):
        """Run credential harvester interactively"""
        print_subsection("Credential Harvester")
        target = input("  Masukkan URL target: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Credential Harvesting")
        
        try:
            from tools.exploit.credential_harvest import CredentialHarvester
            harvester = CredentialHarvester()
            harvester.harvest(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Credential Harvester")
        self._show_exploit_menu()
    
    def _run_forensics_analyze(self):
        """Run file analyzer interactively"""
        print_subsection("File Analyzer")
        target = input("  Masukkan path file: ").strip()
        
        if not target:
            print_error("File tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "File Analysis")
        
        try:
            from tools.forensics.file_analyzer import FileAnalyzer
            analyzer = FileAnalyzer()
            analyzer.analyze(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("File Analyzer")
        self._show_forensics_menu()
    
    def _run_forensics_strings(self):
        """Run strings extractor interactively"""
        print_subsection("Strings Extractor")
        target = input("  Masukkan path file: ").strip()
        
        if not target:
            print_error("File tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Strings Extraction")
        
        try:
            from tools.forensics.strings_extractor import StringsExtractor
            extractor = StringsExtractor()
            extractor.extract(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Strings Extractor")
        self._show_forensics_menu()
    
    def _run_forensics_hash(self):
        """Run hash checker interactively"""
        print_subsection("Hash Checker")
        target = input("  Masukkan path file: ").strip()
        
        if not target:
            print_error("File tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Hash Check")
        
        try:
            from tools.forensics.hash_checker import HashChecker
            checker = HashChecker()
            checker.check(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Hash Checker")
        self._show_forensics_menu()
    
    def _run_plugin_list(self):
        """List plugins"""
        print_subsection("List Plugins")
        
        try:
            from tools.utils.plugin_manager import PluginManager
            manager = PluginManager()
            manager.load_plugins()
            manager.list_plugins()
        except Exception as e:
            print_error(f"Error: {e}")
        
        pause()
        self._show_plugin_menu()
    
    def _run_plugin_run(self):
        """Run plugin"""
        print_subsection("Run Plugin")
        plugin_name = input("  Masukkan nama plugin: ").strip()
        
        if not plugin_name:
            print_error("Nama plugin tidak boleh kosong!")
            pause()
            return
        
        try:
            from tools.utils.plugin_manager import PluginManager
            manager = PluginManager()
            manager.load_plugins()
            manager.run_plugin(plugin_name)
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue(f"Plugin {plugin_name}")
        self._show_plugin_menu()
    
    def _run_plugin_create(self):
        """Create plugin"""
        print_subsection("Create Plugin")
        plugin_name = input("  Masukkan nama plugin: ").strip()
        
        if not plugin_name:
            print_error("Nama plugin tidak boleh kosong!")
            pause()
            return
        
        try:
            from tools.utils.plugin_manager import PluginManager
            manager = PluginManager()
            manager.create_plugin_template(plugin_name, f"Custom plugin: {plugin_name}")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Create Plugin")
        self._show_plugin_menu()
    
    def _run_plugin_delete(self):
        """Delete plugin"""
        print_subsection("Delete Plugin")
        plugin_name = input("  Masukkan nama plugin: ").strip()
        
        if not plugin_name:
            print_error("Nama plugin tidak boleh kosong!")
            pause()
            return
        
        try:
            from tools.utils.plugin_manager import PluginManager
            manager = PluginManager()
            manager.uninstall_plugin(plugin_name)
        except Exception as e:
            print_error(f"Error: {e}")
        
        pause()
        self._show_plugin_menu()
    
    def _run_auto_scan(self):
        """Run auto scan"""
        print_subsection("Auto Scan (Cerdas)")
        target = input("  Masukkan URL target: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        mode = input("  Mode (passive/aggressive) [passive]: ").strip() or "passive"
        
        print_scan_start(target, f"Auto Scan ({mode})")
        
        try:
            from tools.scanner.auto_engine import AutoScanEngine
            engine = AutoScanEngine()
            engine.auto_scan(target, mode=mode)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Auto Scan")
        self._show_main_menu()
    
    def _run_report(self):
        """Run report generation"""
        print_subsection("Generate Report")
        
        scan_id = input("  Masukkan Scan ID (tekan Enter untuk semua): ").strip()
        scan_id = int(scan_id) if scan_id else None
        
        print_info("Generating report...")
        
        try:
            from tools.utils.report_generator import ReportGenerator
            generator = ReportGenerator()
            generator.generate(scan_id=scan_id)
            print_success("Report generated!")
        except Exception as e:
            print_error(f"Error: {e}")
        
        pause()
        self._show_main_menu()
    
    def _run_stealth(self):
        """Run stealth scan"""
        print_subsection("Stealth Scan")
        target = input("  Masukkan target: ").strip()
        
        if not target:
            print_error("Target tidak boleh kosong!")
            pause()
            return
        
        print_scan_start(target, "Stealth Scan")
        
        try:
            from tools.utils.stealth import StealthMode
            stealth = StealthMode()
            stealth.stealth_scan(target)
            print_scan_complete(target, "Completed")
        except Exception as e:
            print_error(f"Error: {e}")
        
        self._ask_continue("Stealth Scan")
        self._show_network_menu()
    
    def _clear_database(self):
        """Clear database"""
        print_warning("PERINGATAN: Ini akan menghapus SEMUA data!")
        confirm = input("  Ketik 'YA' untuk konfirmasi: ").strip()
        
        if confirm == "YA":
            with self.db._cursor() as cursor:
                for table in ['scans', 'subdomains', 'ports', 'vulnerabilities',
                              'hashes', 'credentials', 'dns_records', 'network_hosts']:
                    cursor.execute(f"DELETE FROM {table}")
            print_success("Database berhasil dihapus!")
        else:
            print_info("Dibatalkan.")
        
        pause()
        self._show_database_menu()


def main():
    """Main entry point"""
    try:
        tools = BYMATools()
        tools.run()
    except KeyboardInterrupt:
        print()
        print_warning("Operation cancelled by user")
    except Exception as e:
        print_error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
