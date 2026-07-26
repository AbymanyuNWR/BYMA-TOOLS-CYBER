"""
BYMA TOOLS - Basic Tests
Simple tests for core functionality
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestColors:
    """Test color system"""
    
    def test_import_colors(self):
        from core.colors import Colors, cprint, print_banner
        assert Colors is not None
    
    def test_color_values(self):
        from core.colors import Colors
        assert Colors.RED != ""
        assert Colors.GREEN != ""
        assert Colors.CYAN != ""
    
    def test_cprint(self, capsys):
        from core.colors import cprint, Colors
        cprint("test message", Colors.GREEN)
        captured = capsys.readouterr()
        assert "test message" in captured.out


class TestIcons:
    """Test icon system"""
    
    def test_import_icons(self):
        from core.colors import Icons
        assert Icons.SUCCESS == "[+]"
        assert Icons.ERROR == "[-]"
        assert Icons.WARNING == "[*]"


class TestDatabase:
    """Test database functionality"""
    
    def test_import_database(self):
        from core.database import DatabaseManager
        assert DatabaseManager is not None
    
    def test_singleton(self):
        from core.database import get_database
        db1 = get_database()
        db2 = get_database()
        assert db1 is db2


class TestLogger:
    """Test logger functionality"""
    
    def test_import_logger(self):
        from core.logger import get_logger
        logger = get_logger()
        assert logger is not None
    
    def test_logger_methods(self):
        from core.logger import get_logger
        logger = get_logger()
        logger.info("Test message")
        logger.debug("Debug message")
        logger.warning("Warning message")


class TestValidator:
    """Test validator functionality"""
    
    def test_import_validator(self):
        from core.validator import get_validator
        validator = get_validator()
        assert validator is not None
    
    def test_validate_url(self):
        from core.validator import get_validator
        validator = get_validator()
        result = validator.validate_url("http://example.com")
        assert result is True
    
    def test_validate_domain(self):
        from core.validator import get_validator
        validator = get_validator()
        result = validator.validate_domain("example.com")
        assert result is True


class TestSettings:
    """Test settings"""
    
    def test_import_settings(self):
        from config.settings import TOOL_NAME, TOOL_VERSION
        assert TOOL_NAME == "BYMA TOOLS"
        assert TOOL_VERSION == "1.0.0"


class TestMainModule:
    """Test main entry point"""
    
    def test_import_main(self):
        import main
        assert main.BYMATools is not None
    
    def test_parser_creation(self):
        from main import BYMATools
        tools = BYMATools()
        assert tools.parser is not None


class TestToolsModules:
    """Test tool modules import"""
    
    def test_recon_modules(self):
        from tools.recon.subdomain import SubdomainEnumerator
        from tools.recon.port_scanner import PortScanner
        from tools.recon.whois_lookup import WhoisLookup
        from tools.recon.dns_lookup import DNSLookup
        from tools.recon.ip_lookup import IPLookup
        from tools.recon.email_harvest import EmailHarvester
        from tools.recon.tech_fingerprint import TechFingerprint
        assert all([SubdomainEnumerator, PortScanner, WhoisLookup,
                   DNSLookup, IPLookup, EmailHarvester, TechFingerprint])
    
    def test_scanner_modules(self):
        from tools.scanner.vuln_scanner import VulnScanner
        from tools.scanner.sql_injection import SQLInjectionScanner
        from tools.scanner.xss_scanner import XSSScanner
        from tools.scanner.dir_bruteforce import DirectoryBruteforcer
        from tools.scanner.ssl_checker import SSLChecker
        from tools.scanner.cors_scanner import CORSScanner
        assert all([VulnScanner, SQLInjectionScanner, XSSScanner,
                   DirectoryBruteforcer, SSLChecker, CORSScanner])
    
    def test_password_modules(self):
        from tools.password.hash_cracker import HashCracker
        from tools.password.password_gen import PasswordGenerator
        from tools.password.brute_force import BruteForceAttacker
        assert all([HashCracker, PasswordGenerator, BruteForceAttacker])
    
    def test_exploit_modules(self):
        from tools.exploit.reverse_shell import ReverseShellGenerator
        from tools.exploit.webshell_gen import WebshellGenerator
        from tools.exploit.credential_harvest import CredentialHarvester
        assert all([ReverseShellGenerator, WebshellGenerator, CredentialHarvester])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
