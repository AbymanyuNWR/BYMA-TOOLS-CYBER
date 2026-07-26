"""
BYMA TOOLS - Advanced Report Generator
Tools untuk generate laporan scan dalam format HTML
"""
import json
from datetime import datetime
from pathlib import Path
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_section, cprint, Colors
)
from core.logger import get_logger
from core.database import get_database


class ReportGenerator:
    """Advanced report generator"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    def generate(self, scan_id=None, output_dir=None):
        """Generate HTML report"""
        print_section("Report Generator")
        
        try:
            # Get scan data
            if scan_id:
                scan_data = self._get_scan_data(scan_id)
            else:
                scan_data = self._get_latest_scan_data()
            
            if not scan_data:
                print_warning("No scan data found")
                return None
            
            # Generate HTML report
            print_info("Generating HTML report...")
            html = self._generate_html(scan_data)
            
            # Save report
            if output_dir:
                output_path = Path(output_dir)
            else:
                output_path = Path("output/reports")
            
            output_path.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = output_path / f"byma_report_{timestamp}.html"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html)
            
            print_success(f"Report generated: {report_file}")
            return report_file
        
        except Exception as e:
            print_error(f"Report generation failed: {e}")
            return None
    
    def _get_scan_data(self, scan_id):
        """Get scan data from database"""
        scan = self.db.get_scan(scan_id)
        if not scan:
            return None
        
        return {
            'scan': dict(scan),
            'vulnerabilities': [dict(v) for v in self.db.get_vulnerabilities(scan_id=scan_id)],
            'ports': [dict(p) for p in self.db.get_ports(scan_id)],
            'subdomains': [dict(s) for s in self.db.get_subdomains(scan_id)]
        }
    
    def _get_latest_scan_data(self):
        """Get latest scan data"""
        scans = self.db.get_scans(limit=1)
        if not scans:
            return None
        
        return self._get_scan_data(scans[0]['id'])
    
    def _generate_html(self, scan_data):
        """Generate HTML report"""
        scan = scan_data['scan']
        vulns = scan_data.get('vulnerabilities', [])
        ports = scan_data.get('ports', [])
        subdomains = scan_data.get('subdomains', [])
        
        # Calculate statistics
        total_vulns = len(vulns)
        critical = len([v for v in vulns if v.get('severity') == 'CRITICAL'])
        high = len([v for v in vulns if v.get('severity') == 'HIGH'])
        medium = len([v for v in vulns if v.get('severity') == 'MEDIUM'])
        low = len([v for v in vulns if v.get('severity') == 'LOW'])
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BYMA TOOLS - Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #eaeaea;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #16213e 0%, #0f3460 100%);
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            color: #00d4ff;
            margin-bottom: 10px;
        }}
        .header p {{
            color: #a0a0a0;
            font-size: 1.1em;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #16213e;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #00d4ff;
        }}
        .stat-card.critical {{ border-left-color: #ff4757; }}
        .stat-card.high {{ border-left-color: #ff6b6b; }}
        .stat-card.medium {{ border-left-color: #ffa502; }}
        .stat-card.low {{ border-left-color: #2ed573; }}
        .stat-card h3 {{
            font-size: 2em;
            color: #00d4ff;
            margin-bottom: 10px;
        }}
        .stat-card.critical h3 {{ color: #ff4757; }}
        .stat-card.high h3 {{ color: #ff6b6b; }}
        .stat-card.medium h3 {{ color: #ffa502; }}
        .stat-card.low h3 {{ color: #2ed573; }}
        .section {{
            background: #16213e;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .section h2 {{
            color: #00d4ff;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #0f3460;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #0f3460;
        }}
        th {{
            background: #0f3460;
            color: #00d4ff;
            font-weight: 600;
        }}
        tr:hover {{
            background: #1a1a4e;
        }}
        .severity {{
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: 600;
            font-size: 0.85em;
        }}
        .severity.critical {{ background: #ff4757; color: white; }}
        .severity.high {{ background: #ff6b6b; color: white; }}
        .severity.medium {{ background: #ffa502; color: white; }}
        .severity.low {{ background: #2ed573; color: white; }}
        .severity.info {{ background: #3498db; color: white; }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #a0a0a0;
            font-size: 0.9em;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }}
        .info-item {{
            padding: 10px;
            background: #1a1a2e;
            border-radius: 5px;
        }}
        .info-item label {{
            color: #00d4ff;
            display: block;
            margin-bottom: 5px;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BYMA TOOLS</h1>
            <p>Security Assessment Report</p>
        </div>
        
        <div class="section">
            <h2>Scan Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <label>Target</label>
                    <span>{scan.get('target', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <label>Scan Type</label>
                    <span>{scan.get('scan_type', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <label>Tool Used</label>
                    <span>{scan.get('tool_name', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <label>Status</label>
                    <span>{scan.get('status', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <label>Start Time</label>
                    <span>{scan.get('start_time', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <label>End Time</label>
                    <span>{scan.get('end_time', 'N/A')}</span>
                </div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>{total_vulns}</h3>
                <p>Total Findings</p>
            </div>
            <div class="stat-card critical">
                <h3>{critical}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card high">
                <h3>{high}</h3>
                <p>High</p>
            </div>
            <div class="stat-card medium">
                <h3>{medium}</h3>
                <p>Medium</p>
            </div>
            <div class="stat-card low">
                <h3>{low}</h3>
                <p>Low</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Title</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for vuln in vulns:
            severity_class = (vuln.get('severity', 'info')).lower()
            html += f"""                    <tr>
                        <td><span class="severity {severity_class}">{vuln.get('severity', 'N/A')}</span></td>
                        <td>{vuln.get('vuln_type', 'N/A')}</td>
                        <td>{vuln.get('title', 'N/A')}</td>
                        <td>{vuln.get('description', 'N/A')}</td>
                    </tr>
"""
        
        html += """                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Open Ports</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for port in ports:
            html += f"""                    <tr>
                        <td>{port.get('port', 'N/A')}/tcp</td>
                        <td>{port.get('state', 'N/A')}</td>
                        <td>{port.get('service', 'N/A')}</td>
                        <td>{port.get('version', 'N/A')}</td>
                    </tr>
"""
        
        html += """                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Subdomains</h2>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for sub in subdomains:
            html += f"""                    <tr>
                        <td>{sub.get('subdomain', 'N/A')}</td>
                        <td>{sub.get('ip_address', 'N/A')}</td>
                        <td>{sub.get('status', 'N/A')}</td>
                    </tr>
"""
        
        html += f"""                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by BYMA TOOLS | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Multi-Purpose Cybersecurity Toolkit</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
