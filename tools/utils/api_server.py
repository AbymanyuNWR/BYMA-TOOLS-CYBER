"""
BYMA TOOLS - API Mode
REST API server untuk integrasi dengan tools lain
"""
import json
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class APIServer:
    """REST API Server for BYMA TOOLS"""
    
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.logger = get_logger()
        self.db = get_database()
        self.app = None
    
    def start(self):
        """Start API server"""
        print_section("Starting BYMA TOOLS API Server")
        
        try:
            from flask import Flask, request, jsonify
            
            self.app = Flask(__name__)
            
            # Register routes
            self._register_routes()
            
            print_info(f"Server starting on {self.host}:{self.port}")
            print_info("Endpoints:")
            cprint("    GET  /api/health", Colors.BCYAN)
            cprint("    GET  /api/scans", Colors.BCYAN)
            cprint("    GET  /api/scans/<id>", Colors.BCYAN)
            cprint("    POST /api/scan/recon", Colors.BCYAN)
            cprint("    POST /api/scan/vuln", Colors.BCYAN)
            cprint("    POST /api/scan/port", Colors.BCYAN)
            cprint("    GET  /api/stats", Colors.BCYAN)
            cprint("    GET  /api/vulnerabilities", Colors.BCYAN)
            print()
            
            self.app.run(host=self.host, port=self.port, debug=False)
        
        except ImportError:
            print_error("Flask is required for API mode")
            print_info("Install with: pip install flask")
        except Exception as e:
            print_error(f"API server failed: {e}")
    
    def _register_routes(self):
        """Register API routes"""
        from flask import request, jsonify
        
        @self.app.route('/api/health')
        def health():
            return jsonify({
                'status': 'healthy',
                'tool': 'BYMA TOOLS',
                'version': '1.0.0'
            })
        
        @self.app.route('/api/scans')
        def get_scans():
            scans = self.db.get_scans(limit=50)
            return jsonify({
                'scans': [dict(s) for s in scans],
                'total': len(scans)
            })
        
        @self.app.route('/api/scans/<int:scan_id>')
        def get_scan(scan_id):
            scan = self.db.get_scan(scan_id)
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            return jsonify({
                'scan': dict(scan),
                'vulnerabilities': [dict(v) for v in self.db.get_vulnerabilities(scan_id=scan_id)],
                'ports': [dict(p) for p in self.db.get_ports(scan_id)]
            })
        
        @self.app.route('/api/scan/recon', methods=['POST'])
        def scan_recon():
            data = request.json
            target = data.get('target')
            
            if not target:
                return jsonify({'error': 'Target is required'}), 400
            
            try:
                from tools.recon.subdomain import SubdomainEnumerator
                scanner = SubdomainEnumerator()
                result = scanner.enumerate(target)
                
                return jsonify({
                    'status': 'success',
                    'target': target,
                    'subdomains': list(result) if result else []
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan/vuln', methods=['POST'])
        def scan_vuln():
            data = request.json
            target = data.get('target')
            
            if not target:
                return jsonify({'error': 'Target is required'}), 400
            
            try:
                from tools.scanner.vuln_scanner import VulnScanner
                scanner = VulnScanner()
                result = scanner.scan(target)
                
                return jsonify({
                    'status': 'success',
                    'target': target,
                    'vulnerabilities': result
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan/port', methods=['POST'])
        def scan_port():
            data = request.json
            target = data.get('target')
            ports = data.get('ports', '1-1024')
            
            if not target:
                return jsonify({'error': 'Target is required'}), 400
            
            try:
                from tools.recon.port_scanner import PortScanner
                scanner = PortScanner()
                result = scanner.scan(target, ports=ports)
                
                return jsonify({
                    'status': 'success',
                    'target': target,
                    'open_ports': result
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/stats')
        def get_stats():
            stats = self.db.get_statistics()
            return jsonify(stats)
        
        @self.app.route('/api/vulnerabilities')
        def get_vulnerabilities():
            vulns = self.db.get_vulnerabilities()
            return jsonify({
                'vulnerabilities': [dict(v) for v in vulns],
                'total': len(vulns)
            })
