"""
BYMA TOOLS - Main Entry Point
Point of entry untuk semua operasi BYMA TOOLS
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
    print_result, print_separator, print_subsection, Icons
)
from core.logger import get_logger
from core.database import get_database
from core.validator import get_validator, ValidationError
from config.settings import (
    TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR, TOOL_DESCRIPTION
)


class BYMATools:
    """Main class untuk BYMA TOOLS"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.validator = get_validator()
        self.parser = self._create_parser()
    
    def _create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            prog='byma',
            description=f'{TOOL_NAME} - {TOOL_DESCRIPTION}',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  byma auto http://target.com          # Intelligent auto-scan
  byma recon subdomain example.com
  byma recon port 192.168.1.1 --ports 1-1000
  byma recon whois example.com
  byma recon dns example.com
  byma recon ip 8.8.8.8
  
  byma scan vuln http://target.com
  byma scan sqli http://target.com/?id=1
  byma scan xss http://target.com/search?q=test
  byma scan dir http://target.com
  byma scan ssl target.com
  
  byma network scan 192.168.1.0/24
  byma network sniff
  byma network arp --target 192.168.1.100 --gateway 192.168.1.1
  
  byma password hash md5 "password123"
  byma password crack hash.txt md5 --wordlist passwords.txt
  byma password generate --length 16 --count 10
  
  byma web crawl http://target.com
  byma web headers http://target.com
  byma web proxy
  
  byma exploit reverse 192.168.1.100 4444 --type python
  byma exploit webshell --type php
  
  byma forensics analyze suspicious.exe
  byma forensics strings malware.bin
  byma forensics hash suspicious.exe
  
  byma stats
  byma history
  byma clear
"""
        )
        
        # Main subcommands
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # ==================== RECON COMMANDS ====================
        recon_parser = subparsers.add_parser('recon', help='Reconnaissance tools')
        recon_parser.add_argument('--subdomain', '-s', help='Enumerate subdomains for domain')
        recon_parser.add_argument('--port', '-p', help='Scan ports on target')
        recon_parser.add_argument('--ports', default='1-1024', help='Port range (default: 1-1024)')
        recon_parser.add_argument('--whois', '-w', help='WHOIS lookup for domain')
        recon_parser.add_argument('--dns', '-d', help='DNS lookup for domain')
        recon_parser.add_argument('--ip', '-i', help='IP geolocation lookup')
        recon_parser.add_argument('--email', '-e', help='Email harvester for domain')
        recon_parser.add_argument('--tech', '-t', help='Technology fingerprint for URL')
        recon_parser.add_argument('--threads', type=int, default=50, help='Number of threads')
        recon_parser.add_argument('--output', '-o', help='Output file')
        recon_parser.add_argument('--format', choices=['text', 'json', 'csv'], default='json')
        
        # ==================== SCAN COMMANDS ====================
        scan_parser = subparsers.add_parser('scan', help='Vulnerability scanning tools')
        scan_parser.add_argument('--vuln', '-v', help='General vulnerability scan on target')
        scan_parser.add_argument('--sqli', help='SQL injection test on URL')
        scan_parser.add_argument('--xss', help='XSS test on URL')
        scan_parser.add_argument('--dir', '-D', help='Directory bruteforce on URL')
        scan_parser.add_argument('--ssl', '-S', help='SSL/TLS check on hostname')
        scan_parser.add_argument('--cors', help='CORS misconfiguration check on URL')
        scan_parser.add_argument('--wordlist', '-w', help='Wordlist for directory bruteforce')
        scan_parser.add_argument('--extensions', help='Extensions for directory bruteforce')
        scan_parser.add_argument('--threads', type=int, default=50, help='Number of threads')
        scan_parser.add_argument('--output', '-o', help='Output file')
        scan_parser.add_argument('--format', choices=['text', 'json', 'csv'], default='json')
        
        # ==================== NETWORK COMMANDS ====================
        network_parser = subparsers.add_parser('network', help='Network attack tools')
        network_parser.add_argument('--scan', '-s', help='Scan network (CIDR notation)')
        network_parser.add_argument('--sniff', action='store_true', help='Sniff network packets')
        network_parser.add_argument('--interface', '-i', help='Network interface for sniffing')
        network_parser.add_argument('--arp', action='store_true', help='ARP spoof attack')
        network_parser.add_argument('--target', '-t', help='Target IP for ARP spoof')
        network_parser.add_argument('--gateway', '-g', help='Gateway IP for ARP spoof')
        network_parser.add_argument('--count', '-c', type=int, default=100, help='Packet count')
        network_parser.add_argument('--output', '-o', help='Output file')
        
        # ==================== PASSWORD COMMANDS ====================
        password_parser = subparsers.add_parser('password', help='Password attack tools')
        password_parser.add_argument('--hash', help='Generate hash from text')
        password_parser.add_argument('--algo', choices=['md5', 'sha1', 'sha256', 'sha512', 'bcrypt'],
                                     default='md5', help='Hash algorithm')
        password_parser.add_argument('--crack', nargs=2, metavar=('HASH', 'ALGO'),
                                     help='Crack hash with wordlist')
        password_parser.add_argument('--wordlist', '-w', help='Wordlist for cracking')
        password_parser.add_argument('--generate', type=int, metavar='LENGTH',
                                     help='Generate random password')
        password_parser.add_argument('--count', '-c', type=int, default=1,
                                     help='Number of passwords to generate')
        password_parser.add_argument('--brute', help='Brute force login URL')
        password_parser.add_argument('--username', '-u', help='Username for brute force')
        password_parser.add_argument('--passlist', help='Password list for brute force')
        password_parser.add_argument('--output', '-o', help='Output file')
        
        # ==================== WEB COMMANDS ====================
        web_parser = subparsers.add_parser('web', help='Web analysis tools')
        web_parser.add_argument('--crawl', '-c', help='Crawl website URL')
        web_parser.add_argument('--headers', '-H', help='Analyze HTTP headers for URL')
        web_parser.add_argument('--proxy', action='store_true', help='Test proxy list')
        web_parser.add_argument('--depth', type=int, default=3, help='Crawl depth')
        web_parser.add_argument('--output', '-o', help='Output file')
        web_parser.add_argument('--format', choices=['text', 'json', 'csv'], default='json')
        
        # ==================== EXPLOIT COMMANDS ====================
        exploit_parser = subparsers.add_parser('exploit', help='Exploit generation tools')
        exploit_parser.add_argument('--reverse', nargs=2, metavar=('IP', 'PORT'),
                                    help='Generate reverse shell payload')
        exploit_parser.add_argument('--type', choices=['python', 'bash', 'php', 'netcat',
                                                        'powershell', 'ruby', 'java', 'perl'],
                                    default='python', help='Payload type')
        exploit_parser.add_argument('--webshell', action='store_true',
                                    help='Generate webshell')
        exploit_parser.add_argument('--webshell-type', choices=['php', 'asp', 'jsp'],
                                    default='php', help='Webshell type')
        exploit_parser.add_argument('--output', '-o', help='Output file')
        
        # ==================== FORENSICS COMMANDS ====================
        forensics_parser = subparsers.add_parser('forensics', help='Forensics tools')
        forensics_parser.add_argument('--analyze', '-a', help='Analyze file')
        forensics_parser.add_argument('--strings', '-s', help='Extract strings from file')
        forensics_parser.add_argument('--hash', help='Calculate file hashes')
        forensics_parser.add_argument('--min-length', type=int, default=4,
                                      help='Minimum string length')
        forensics_parser.add_argument('--output', '-o', help='Output file')
        
        # ==================== AUTO SCAN COMMAND ====================
        auto_parser = subparsers.add_parser('auto', help='Intelligent auto-scan')
        auto_parser.add_argument('target', help='Target to scan')
        auto_parser.add_argument('--mode', choices=['smart', 'aggressive', 'stealth'],
                                 default='smart', help='Scan mode')
        auto_parser.add_argument('--output', '-o', help='Output file')
        
        # ==================== WAF COMMAND ====================
        waf_parser = subparsers.add_parser('waf', help='WAF detection and bypass')
        waf_parser.add_argument('target', help='Target URL')
        waf_parser.add_argument('--output', '-o', help='Output file')
        
        # ==================== CREDENTIAL COMMAND ====================
        cred_parser = subparsers.add_parser('credential', help='Credential harvesting')
        cred_parser.add_argument('target', help='Target URL')
        cred_parser.add_argument('--output', '-o', help='Output file')
        
        # ==================== REPORT COMMAND ====================
        report_parser = subparsers.add_parser('report', help='Generate HTML report')
        report_parser.add_argument('--scan-id', type=int, help='Scan ID to report')
        report_parser.add_argument('--output-dir', help='Output directory')
        
        # ==================== STEALTH COMMAND ====================
        stealth_parser = subparsers.add_parser('stealth', help='Stealth mode tools')
        stealth_parser.add_argument('--scan', '-s', help='Stealth port scan')
        stealth_parser.add_argument('--ports', default='80,443,22,21,25', help='Ports to scan')
        stealth_parser.add_argument('--delay', type=float, default=1, help='Delay between requests')
        stealth_parser.add_argument('--decoy', action='store_true', help='Use decoy IPs')
        stealth_parser.add_argument('--slow', action='store_true', help='Ultra slow scan')
        
        # ==================== PLUGIN COMMAND ====================
        plugin_parser = subparsers.add_parser('plugin', help='Plugin management')
        plugin_parser.add_argument('--list', action='store_true', help='List plugins')
        plugin_parser.add_argument('--run', help='Run plugin by name')
        plugin_parser.add_argument('--create', help='Create new plugin template')
        plugin_parser.add_argument('--install', help='Install plugin from file')
        plugin_parser.add_argument('--uninstall', help='Uninstall plugin')
        
        # ==================== API COMMAND ====================
        api_parser = subparsers.add_parser('api', help='Start REST API server')
        api_parser.add_argument('--host', default='0.0.0.0', help='Bind host')
        api_parser.add_argument('--port', type=int, default=8080, help='Bind port')
        
        # ==================== UTILITY COMMANDS ====================
        subparsers.add_parser('stats', help='Show database statistics')
        subparsers.add_parser('history', help='Show scan history')
        
        clear_parser = subparsers.add_parser('clear', help='Clear screen')
        clear_parser.add_argument('--database', action='store_true',
                                  help='Clear database')
        
        subparsers.add_parser('version', help='Show version info')
        subparsers.add_parser('update', help='Update BYMA TOOLS')
        
        return parser
    
    def run(self, args=None):
        """Run BYMA TOOLS"""
        # Print banner
        print_banner()
        
        # Parse arguments
        parsed_args = self.parser.parse_args(args)
        
        if not parsed_args.command:
            self.parser.print_help()
            return
        
        # Log action
        self.logger.action(parsed_args.command)
        
        try:
            # Route to appropriate handler
            if parsed_args.command == 'recon':
                self._handle_recon(parsed_args)
            elif parsed_args.command == 'scan':
                self._handle_scan(parsed_args)
            elif parsed_args.command == 'network':
                self._handle_network(parsed_args)
            elif parsed_args.command == 'password':
                self._handle_password(parsed_args)
            elif parsed_args.command == 'web':
                self._handle_web(parsed_args)
            elif parsed_args.command == 'exploit':
                self._handle_exploit(parsed_args)
            elif parsed_args.command == 'forensics':
                self._handle_forensics(parsed_args)
            elif parsed_args.command == 'auto':
                self._handle_auto(parsed_args)
            elif parsed_args.command == 'waf':
                self._handle_waf(parsed_args)
            elif parsed_args.command == 'credential':
                self._handle_credential(parsed_args)
            elif parsed_args.command == 'report':
                self._handle_report(parsed_args)
            elif parsed_args.command == 'stealth':
                self._handle_stealth(parsed_args)
            elif parsed_args.command == 'plugin':
                self._handle_plugin(parsed_args)
            elif parsed_args.command == 'api':
                self._handle_api(parsed_args)
            elif parsed_args.command == 'stats':
                self._show_stats()
            elif parsed_args.command == 'history':
                self._show_history()
            elif parsed_args.command == 'clear':
                self._clear_screen(parsed_args)
            elif parsed_args.command == 'version':
                self._show_version()
            elif parsed_args.command == 'update':
                self._update_tools()
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
            scanner.scan(args.target if hasattr(args, 'target') else args.port,
                        ports=args.ports, threads=args.threads, output=args.output)
        
        elif args.whois:
            whois = WhoisLookup()
            whois.lookup(args.whois, output=args.output)
        
        elif args.dns:
            dns = DNSLookup()
            dns.lookup(args.dns, output=args.output)
        
        elif args.ip:
            iplookup = IPLookup()
            iplookup.lookup(args.ip, output=args.output)
        
        elif args.email:
            harvester = EmailHarvester()
            harvester.harvest(args.email, output=args.output)
        
        elif args.tech:
            fingerprint = TechFingerprint()
            fingerprint.detect(args.tech, output=args.output)
        
        else:
            print_error("Please specify a recon tool to use")
    
    def _handle_scan(self, args):
        """Handle scan commands"""
        from tools.scanner.vuln_scanner import VulnScanner
        from tools.scanner.sql_injection import SQLInjectionScanner
        from tools.scanner.xss_scanner import XSSScanner
        from tools.scanner.dir_bruteforce import DirBruteforcer
        from tools.scanner.ssl_checker import SSLChecker
        from tools.scanner.cors_scanner import CORSScanner
        
        if args.vuln:
            scanner = VulnScanner()
            scanner.scan(args.vuln, output=args.output)
        
        elif args.sqli:
            scanner = SQLInjectionScanner()
            scanner.scan(args.sqli, output=args.output)
        
        elif args.xss:
            scanner = XSSScanner()
            scanner.scan(args.xss, output=args.output)
        
        elif args.dir:
            bruteforcer = DirBruteforcer()
            bruteforcer.bruteforce(args.dir, wordlist=args.wordlist,
                                   extensions=args.extensions, threads=args.threads,
                                   output=args.output)
        
        elif args.ssl:
            checker = SSLChecker()
            checker.check(args.ssl, output=args.output)
        
        elif args.cors:
            scanner = CORSScanner()
            scanner.scan(args.cors, output=args.output)
        
        else:
            print_error("Please specify a scan tool to use")
    
    def _handle_network(self, args):
        """Handle network commands"""
        from tools.network.network_scan import NetworkScanner
        from tools.network.packet_sniffer import PacketSniffer
        from tools.network.arp_spoof import ARPSpoof
        
        if args.scan:
            scanner = NetworkScanner()
            scanner.scan(args.scan, output=args.output)
        
        elif args.sniff:
            sniffer = PacketSniffer()
            sniffer.sniff(interface=args.interface, count=args.count,
                         output=args.output)
        
        elif args.arp:
            if not args.target or not args.gateway:
                print_error("ARP spoof requires --target and --gateway")
                return
            spoofer = ARPSpoof()
            spoofer.spoof(args.target, args.gateway)
        
        else:
            print_error("Please specify a network tool to use")
    
    def _handle_password(self, args):
        """Handle password commands"""
        from tools.password.hash_cracker import HashCracker
        from tools.password.password_gen import PasswordGenerator
        from tools.password.brute_force import BruteForcer
        
        if args.hash:
            cracker = HashCracker()
            cracker.hash_text(args.hash, args.algo)
        
        elif args.crack:
            cracker = HashCracker()
            cracker.crack(args.crack[0], args.crack[1], wordlist=args.wordlist,
                         output=args.output)
        
        elif args.generate:
            generator = PasswordGenerator()
            generator.generate(length=args.generate, count=args.count,
                             output=args.output)
        
        elif args.brute:
            if not args.username or not args.passlist:
                print_error("Brute force requires --username and --passlist")
                return
            brute = BruteForcer()
            brute.bruteforce(args.brute, args.username, args.passlist,
                           output=args.output)
        
        else:
            print_error("Please specify a password tool to use")
    
    def _handle_web(self, args):
        """Handle web commands"""
        from tools.web.crawler import WebCrawler
        from tools.web.header_analyzer import HeaderAnalyzer
        from tools.web.proxy_scraper import ProxyScraper
        
        if args.crawl:
            crawler = WebCrawler()
            crawler.crawl(args.crawl, depth=args.depth, output=args.output)
        
        elif args.headers:
            analyzer = HeaderAnalyzer()
            analyzer.analyze(args.headers, output=args.output)
        
        elif args.proxy:
            scraper = ProxyScraper()
            scraper.test_proxies(output=args.output)
        
        else:
            print_error("Please specify a web tool to use")
    
    def _handle_exploit(self, args):
        """Handle exploit commands"""
        from tools.exploit.reverse_shell import ReverseShellGenerator
        from tools.exploit.webshell_gen import WebshellGenerator
        
        if args.reverse:
            generator = ReverseShellGenerator()
            generator.generate(args.reverse[0], int(args.reverse[1]),
                             shell_type=args.type, output=args.output)
        
        elif args.webshell:
            generator = WebshellGenerator()
            generator.generate(shell_type=args.webshell_type, output=args.output)
        
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
        """Handle auto scan command"""
        from tools.scanner.auto_engine import AutoScanEngine
        
        engine = AutoScanEngine()
        engine.auto_scan(args.target, mode=args.mode, output=args.output)
    
    def _handle_waf(self, args):
        """Handle WAF detection command"""
        from tools.scanner.waf_detect import WAFDetector
        
        detector = WAFDetector()
        detector.detect(args.target, output=args.output)
    
    def _handle_credential(self, args):
        """Handle credential harvesting command"""
        from tools.exploit.credential_harvest import CredentialHarvester
        
        harvester = CredentialHarvester()
        harvester.harvest(args.target, output=args.output)
    
    def _handle_report(self, args):
        """Handle report generation command"""
        from tools.utils.report_generator import ReportGenerator
        
        generator = ReportGenerator()
        generator.generate(scan_id=args.scan_id, output_dir=args.output_dir)
    
    def _handle_stealth(self, args):
        """Handle stealth mode commands"""
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
        """Handle plugin management commands"""
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
        """Handle API server command"""
        from tools.utils.api_server import APIServer
        
        server = APIServer(host=args.host, port=args.port)
        server.start()
    
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
                # Clear database
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
    
    def _update_tools(self):
        """Update BYMA TOOLS"""
        print_info("Checking for updates...")
        print_warning("Auto-update not yet implemented")
        print_info("Please visit the GitHub repository for updates")


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
