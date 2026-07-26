"""
BYMA TOOLS - Database Manager
SQLite database untuk menyimpan semua hasil scan dan konfigurasi
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager


class DatabaseManager:
    """Manager untuk SQLite database"""
    
    _instance = None
    _db_path = None
    _connection = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._db_path is None:
            self._db_path = Path(__file__).resolve().parent.parent / "database" / "byma.db"
            self._db_path.parent.mkdir(exist_ok=True)
            self._create_tables()
    
    def _get_connection(self):
        """Get database connection"""
        if self._connection is None:
            self._connection = sqlite3.connect(str(self._db_path))
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
        return self._connection
    
    @contextmanager
    def _cursor(self):
        """Context manager untuk database cursor"""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
    
    def _create_tables(self):
        """Buat semua tabel database"""
        with self._cursor() as cursor:
            # Tabel scans -记录所有扫描
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scan_type TEXT,
                    status TEXT DEFAULT 'running',
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    results_count INTEGER DEFAULT 0,
                    output_file TEXT,
                    created_by TEXT DEFAULT 'system'
                )
            """)
            
            # Tabel subdomains
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    subdomain TEXT NOT NULL,
                    ip_address TEXT,
                    status TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)
            
            # Tabel ports
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    state TEXT,
                    service TEXT,
                    version TEXT,
                    banner TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)
            
            # Tabel vulnerabilities
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    target TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity TEXT,
                    title TEXT,
                    description TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    cvss_score REAL,
                    cve_id TEXT,
                    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)
            
            # Tabel hashes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    algorithm TEXT NOT NULL,
                    hash_value TEXT NOT NULL,
                    cracked_password TEXT,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Tabel credentials
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    service TEXT,
                    username TEXT,
                    password TEXT,
                    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Tabel dns_records
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    domain TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_value TEXT NOT NULL,
                    ttl INTEGER,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)
            
            # Tabel whois_info
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS whois_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    registrar TEXT,
                    creation_date TEXT,
                    expiration_date TEXT,
                    updated_date TEXT,
                    name_servers TEXT,
                    status TEXT,
                    registrant_name TEXT,
                    registrant_org TEXT,
                    registrant_country TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Tabel network_hosts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    os_guess TEXT,
                    open_ports TEXT,
                    status TEXT DEFAULT 'alive',
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)
            
            # Tabel settings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    category TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Tabel audit_log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    module TEXT,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    
    # ==================== SCAN OPERATIONS ====================
    
    def create_scan(self, tool_name, target, scan_type=None):
        """Create new scan record"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO scans (tool_name, target, scan_type)
                VALUES (?, ?, ?)
            """, (tool_name, target, scan_type))
            return cursor.lastrowid
    
    def update_scan(self, scan_id, status=None, results_count=None, output_file=None):
        """Update scan record"""
        updates = []
        params = []
        
        if status:
            updates.append("status = ?")
            params.append(status)
            if status in ('completed', 'failed'):
                updates.append("end_time = CURRENT_TIMESTAMP")
        
        if results_count is not None:
            updates.append("results_count = ?")
            params.append(results_count)
        
        if output_file:
            updates.append("output_file = ?")
            params.append(output_file)
        
        if updates:
            params.append(scan_id)
            with self._cursor() as cursor:
                cursor.execute(f"""
                    UPDATE scans SET {', '.join(updates)}
                    WHERE id = ?
                """, params)
    
    def get_scan(self, scan_id):
        """Get scan by ID"""
        with self._cursor() as cursor:
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            return cursor.fetchone()
    
    def get_scans(self, limit=50, offset=0, tool_name=None, target=None):
        """Get scans list"""
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        
        if tool_name:
            query += " AND tool_name = ?"
            params.append(tool_name)
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        query += " ORDER BY start_time DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with self._cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    
    # ==================== SUBDOMAIN OPERATIONS ====================
    
    def add_subdomain(self, scan_id, subdomain, ip_address=None, status=None):
        """Add subdomain record"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO subdomains (scan_id, subdomain, ip_address, status)
                VALUES (?, ?, ?, ?)
            """, (scan_id, subdomain, ip_address, status))
            return cursor.lastrowid
    
    def get_subdomains(self, scan_id):
        """Get subdomains for a scan"""
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT * FROM subdomains WHERE scan_id = ?
                ORDER BY subdomain
            """, (scan_id,))
            return cursor.fetchall()
    
    def get_all_subdomains(self, domain):
        """Get all subdomains for a domain"""
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT DISTINCT subdomain, ip_address, status
                FROM subdomains
                WHERE subdomain LIKE ?
                ORDER BY subdomain
            """, (f"%.{domain}",))
            return cursor.fetchall()
    
    # ==================== PORT OPERATIONS ====================
    
    def add_port(self, scan_id, host, port, state='open', service=None, version=None, banner=None):
        """Add port record"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO ports (scan_id, host, port, state, service, version, banner)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, host, port, state, service, version, banner))
            return cursor.lastrowid
    
    def get_ports(self, scan_id):
        """Get ports for a scan"""
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT * FROM ports WHERE scan_id = ?
                ORDER BY port
            """, (scan_id,))
            return cursor.fetchall()
    
    def get_host_ports(self, host):
        """Get all ports for a host"""
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT DISTINCT port, state, service, version
                FROM ports
                WHERE host = ?
                ORDER BY port
            """, (host,))
            return cursor.fetchall()
    
    # ==================== VULNERABILITY OPERATIONS ====================
    
    def add_vulnerability(self, scan_id, target, vuln_type, severity=None,
                          title=None, description=None, evidence=None,
                          remediation=None, cvss_score=None, cve_id=None):
        """Add vulnerability record"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO vulnerabilities (scan_id, target, vuln_type, severity,
                    title, description, evidence, remediation, cvss_score, cve_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, target, vuln_type, severity, title,
                  description, evidence, remediation, cvss_score, cve_id))
            return cursor.lastrowid
    
    def get_vulnerabilities(self, scan_id=None, target=None, severity=None):
        """Get vulnerabilities"""
        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params = []
        
        if scan_id:
            query += " AND scan_id = ?"
            params.append(scan_id)
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY found_at DESC"
        
        with self._cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    
    # ==================== HASH OPERATIONS ====================
    
    def add_hash(self, algorithm, hash_value, cracked_password=None, source=None):
        """Add hash record"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO hashes (algorithm, hash_value, cracked_password, source)
                VALUES (?, ?, ?, ?)
            """, (algorithm, hash_value, cracked_password, source))
            return cursor.lastrowid
    
    def update_hash_cracked(self, hash_value, cracked_password):
        """Update hash with cracked password"""
        with self._cursor() as cursor:
            cursor.execute("""
                UPDATE hashes SET cracked_password = ?
                WHERE hash_value = ?
            """, (cracked_password, hash_value))
    
    def get_hash(self, hash_value):
        """Get hash record"""
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT * FROM hashes WHERE hash_value = ?
            """, (hash_value,))
            return cursor.fetchone()
    
    # ==================== CREDENTIAL OPERATIONS ====================
    
    def add_credential(self, target, service, username, password):
        """Add credential record"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO credentials (target, service, username, password)
                VALUES (?, ?, ?, ?)
            """, (target, service, username, password))
            return cursor.lastrowid
    
    def get_credentials(self, target=None, service=None):
        """Get credentials"""
        query = "SELECT * FROM credentials WHERE 1=1"
        params = []
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        if service:
            query += " AND service = ?"
            params.append(service)
        
        with self._cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    
    # ==================== DNS OPERATIONS ====================
    
    def add_dns_record(self, scan_id, domain, record_type, record_value, ttl=None):
        """Add DNS record"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO dns_records (scan_id, domain, record_type, record_value, ttl)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, domain, record_type, record_value, ttl))
            return cursor.lastrowid
    
    def get_dns_records(self, scan_id):
        """Get DNS records for a scan"""
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT * FROM dns_records WHERE scan_id = ?
                ORDER BY record_type, record_value
            """, (scan_id,))
            return cursor.fetchall()
    
    # ==================== NETWORK HOST OPERATIONS ====================
    
    def add_network_host(self, scan_id, ip_address, mac_address=None,
                         hostname=None, vendor=None, os_guess=None):
        """Add network host record"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO network_hosts (scan_id, ip_address, mac_address,
                    hostname, vendor, os_guess)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, ip_address, mac_address, hostname, vendor, os_guess))
            return cursor.lastrowid
    
    def get_network_hosts(self, scan_id):
        """Get network hosts for a scan"""
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT * FROM network_hosts WHERE scan_id = ?
                ORDER BY ip_address
            """, (scan_id,))
            return cursor.fetchall()
    
    # ==================== SETTINGS OPERATIONS ====================
    
    def get_setting(self, key, default=None):
        """Get setting value"""
        with self._cursor() as cursor:
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row['value'] if row else default
    
    def set_setting(self, key, value, category=None):
        """Set setting value"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO settings (key, value, category, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            """, (key, value, category))
    
    def get_all_settings(self, category=None):
        """Get all settings"""
        query = "SELECT * FROM settings"
        params = []
        
        if category:
            query += " WHERE category = ?"
            params.append(category)
        
        with self._cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    
    # ==================== AUDIT LOG OPERATIONS ====================
    
    def add_audit_log(self, action, module=None, details=None, ip_address=None):
        """Add audit log entry"""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO audit_log (action, module, details, ip_address)
                VALUES (?, ?, ?, ?)
            """, (action, module, details, ip_address))
    
    def get_audit_logs(self, limit=100, module=None):
        """Get audit logs"""
        query = "SELECT * FROM audit_log"
        params = []
        
        if module:
            query += " WHERE module = ?"
            params.append(module)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self._cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    
    # ==================== STATISTICS ====================
    
    def get_statistics(self):
        """Get database statistics"""
        stats = {}
        
        with self._cursor() as cursor:
            # Total scans
            cursor.execute("SELECT COUNT(*) as count FROM scans")
            stats['total_scans'] = cursor.fetchone()['count']
            
            # Scans by tool
            cursor.execute("""
                SELECT tool_name, COUNT(*) as count
                FROM scans
                GROUP BY tool_name
                ORDER BY count DESC
            """)
            stats['scans_by_tool'] = cursor.fetchall()
            
            # Total subdomains
            cursor.execute("SELECT COUNT(*) as count FROM subdomains")
            stats['total_subdomains'] = cursor.fetchone()['count']
            
            # Total ports
            cursor.execute("SELECT COUNT(*) as count FROM ports")
            stats['total_ports'] = cursor.fetchone()['count']
            
            # Total vulnerabilities
            cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities")
            stats['total_vulnerabilities'] = cursor.fetchone()['count']
            
            # Vulnerabilities by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                GROUP BY severity
                ORDER BY count DESC
            """)
            stats['vulns_by_severity'] = cursor.fetchall()
            
            # Total cracked hashes
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM hashes
                WHERE cracked_password IS NOT NULL
            """)
            stats['cracked_hashes'] = cursor.fetchone()['count']
            
            # Total credentials
            cursor.execute("SELECT COUNT(*) as count FROM credentials")
            stats['total_credentials'] = cursor.fetchone()['count']
        
        return stats
    
    def close(self):
        """Close database connection"""
        if self._connection:
            self._connection.close()
            self._connection = None


# Singleton instance
db = DatabaseManager()


def get_database():
    """Get database manager instance"""
    return db
