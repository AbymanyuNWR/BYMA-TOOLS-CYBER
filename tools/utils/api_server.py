"""
BYMA TOOLS - Advanced API Server
Professional REST API server for tool integration
"""
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class APIServer:
    """Professional API server for BYMA TOOLS"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
        self.endpoints = {}
    
    # API endpoints
    API_ENDPOINTS = {
        '/api/v1/scan': {
            'method': 'POST',
            'description': 'Start a new scan',
            'parameters': ['target', 'scan_type', 'options'],
        },
        '/api/v1/scan/{id}': {
            'method': 'GET',
            'description': 'Get scan status',
            'parameters': ['id'],
        },
        '/api/v1/scan/{id}/results': {
            'method': 'GET',
            'description': 'Get scan results',
            'parameters': ['id'],
        },
        '/api/v1/vulnerabilities': {
            'method': 'GET',
            'description': 'List all vulnerabilities',
            'parameters': ['severity', 'type'],
        },
        '/api/v1/tools': {
            'method': 'GET',
            'description': 'List available tools',
            'parameters': [],
        },
        '/api/v1/tools/{tool}': {
            'method': 'GET',
            'description': 'Get tool information',
            'parameters': ['tool'],
        },
        '/api/v1/report/{id}': {
            'method': 'GET',
            'description': 'Generate report',
            'parameters': ['id', 'format'],
        },
        '/api/v1/health': {
            'method': 'GET',
            'description': 'Health check',
            'parameters': [],
        },
    }
    
    def start(self, host='127.0.0.1', port=8080, output=None):
        """Main start function"""
        print_section("API SERVER")
        print()
        
        try:
            print(f"  {Icons.INFO} {Colors.BCYAN}Host:{Colors.BWHITE}         {host}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Port:{Colors.BWHITE}         {port}")
            print_separator("-", 50)
            print()
            
            # Display endpoints
            print_subsection("Available Endpoints")
            self._display_endpoints()
            
            # Check if Flask is available
            try:
                from flask import Flask, request, jsonify
                
                app = Flask(__name__)
                
                # Register routes
                self._register_routes(app)
                
                print()
                print_info(f"Starting API server on {host}:{port}")
                print_warning("Press Ctrl+C to stop")
                print()
                
                # Start server
                app.run(host=host, port=port, debug=False)
            
            except ImportError:
                print_error("Flask is required for API server")
                print_info("Install with: pip install flask")
                print()
                print_info("Running in demo mode...")
                self._run_demo()
        
        except KeyboardInterrupt:
            print_warning("\nServer stopped")
        except Exception as e:
            print_error(f"Server failed: {e}")
    
    def _register_routes(self, app):
        """Register Flask routes"""
        from flask import request, jsonify
        
        @app.route('/api/v1/health', methods=['GET'])
        def health():
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'version': '1.0.0',
            })
        
        @app.route('/api/v1/tools', methods=['GET'])
        def list_tools():
            tools = self._get_available_tools()
            return jsonify({'tools': tools})
        
        @app.route('/api/v1/tools/<tool>', methods=['GET'])
        def get_tool(tool):
            tool_info = self._get_tool_info(tool)
            if tool_info:
                return jsonify(tool_info)
            return jsonify({'error': 'Tool not found'}), 404
        
        @app.route('/api/v1/scan', methods=['POST'])
        def start_scan():
            data = request.get_json()
            if not data or 'target' not in data:
                return jsonify({'error': 'Target required'}), 400
            
            scan_id = self._start_scan(data)
            return jsonify({'scan_id': scan_id, 'status': 'started'}), 201
        
        @app.route('/api/v1/scan/<scan_id>', methods=['GET'])
        def get_scan(scan_id):
            scan = self._get_scan(scan_id)
            if scan:
                return jsonify(scan)
            return jsonify({'error': 'Scan not found'}), 404
        
        @app.route('/api/v1/scan/<scan_id>/results', methods=['GET'])
        def get_results(scan_id):
            results = self._get_scan_results(scan_id)
            if results:
                return jsonify({'results': results})
            return jsonify({'error': 'Results not found'}), 404
        
        @app.route('/api/v1/vulnerabilities', methods=['GET'])
        def list_vulnerabilities():
            severity = request.args.get('severity')
            vulns = self._get_vulnerabilities(severity)
            return jsonify({'vulnerabilities': vulns})
    
    def _display_endpoints(self):
        """Display API endpoints"""
        table_data = [["Method", "Endpoint", "Description"]]
        
        for endpoint, info in self.API_ENDPOINTS.items():
            table_data.append([
                info['method'],
                endpoint,
                info['description'][:40],
            ])
        
        print_table(table_data)
        print()
    
    def _get_available_tools(self):
        """Get list of available tools"""
        tools = [
            {'name': 'recon', 'category': 'Reconnaissance'},
            {'name': 'scanner', 'category': 'Scanning'},
            {'name': 'network', 'category': 'Network'},
            {'name': 'password', 'category': 'Password'},
            {'name': 'web', 'category': 'Web'},
            {'name': 'exploit', 'category': 'Exploit'},
            {'name': 'forensics', 'category': 'Forensics'},
        ]
        return tools
    
    def _get_tool_info(self, tool):
        """Get tool information"""
        tools = {
            'recon': {'name': 'recon', 'tools': ['subdomain', 'port_scanner', 'whois', 'dns', 'ip_lookup']},
            'scanner': {'name': 'scanner', 'tools': ['sql_injection', 'xss', 'dir_bruteforce', 'ssl', 'cors', 'waf']},
            'network': {'name': 'network', 'tools': ['network_scan', 'packet_sniffer', 'arp_spoof']},
            'password': {'name': 'password', 'tools': ['brute_force', 'hash_cracker', 'password_gen']},
            'web': {'name': 'web', 'tools': ['crawler', 'header_analyzer', 'proxy_scraper']},
            'exploit': {'name': 'exploit', 'tools': ['reverse_shell', 'credential_harvest', 'webshell_gen']},
            'forensics': {'name': 'forensics', 'tools': ['file_analyzer', 'hash_checker', 'strings_extractor']},
        }
        return tools.get(tool)
    
    def _start_scan(self, data):
        """Start a new scan"""
        import uuid
        
        scan_id = str(uuid.uuid4())[:8]
        
        # Store scan in database
        db = get_database()
        db.create_scan(data.get('scan_type', 'unknown'), data['target'], 'api')
        
        return scan_id
    
    def _get_scan(self, scan_id):
        """Get scan information"""
        db = get_database()
        with db._cursor() as cursor:
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            scan = cursor.fetchone()
            return dict(scan) if scan else None
    
    def _get_scan_results(self, scan_id):
        """Get scan results"""
        db = get_database()
        with db._cursor() as cursor:
            cursor.execute("SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,))
            results = cursor.fetchall()
            return [dict(r) for r in results]
    
    def _get_vulnerabilities(self, severity=None):
        """Get vulnerabilities"""
        db = get_database()
        with db._cursor() as cursor:
            if severity:
                cursor.execute("SELECT * FROM vulnerabilities WHERE severity = ?", (severity,))
            else:
                cursor.execute("SELECT * FROM vulnerabilities")
            vulns = cursor.fetchall()
            return [dict(v) for v in vulns]
    
    def _run_demo(self):
        """Run demo mode"""
        print_subsection("Demo Mode")
        print_info("API endpoints available:")
        print()
        
        for endpoint, info in self.API_ENDPOINTS.items():
            print(f"  {Colors.BCYAN}{info['method']}{Colors.BWHITE} {endpoint}")
            print(f"       {Colors.BYELLOW}{info['description']}")
        
        print()
        print_info("Example curl commands:")
        print()
        print(f"  {Colors.BGREEN}curl http://127.0.0.1:8080/api/v1/health{Colors.RESET}")
        print(f"  {Colors.BGREEN}curl http://127.0.0.1:8080/api/v1/tools{Colors.RESET}")
        print(f"  {Colors.BGREEN}curl -X POST -H 'Content-Type: application/json' -d '{{\"target\": \"example.com\", \"scan_type\": \"recon\"}}' http://127.0.0.1:8080/api/v1/scan{Colors.RESET}")
        print()
