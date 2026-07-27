"""
BYMA TOOLS - Advanced Report Generator
Professional security report generation
"""
import json
import os
from pathlib import Path
from datetime import datetime
from core.colors import (
    print_success, print_error, print_warning, print_info,
    print_result, print_section, print_subsection, print_table,
    cprint, Colors, print_separator, Icons
)
from core.logger import get_database, get_logger


class ReportGenerator:
    """Professional security report generator"""
    
    def __init__(self):
        self.logger = get_logger()
        self.db = get_database()
    
    def generate(self, scan_id=None, format_type='json', output=None, 
                 include_raw=False, template='standard'):
        """Main generate function"""
        print_section("REPORT GENERATOR")
        print()
        
        try:
            print(f"  {Icons.INFO} {Colors.BCYAN}Scan ID:{Colors.BWHITE}     {scan_id or 'All scans'}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Format:{Colors.BWHITE}      {format_type.upper()}")
            print(f"  {Icons.INFO} {Colors.BCYAN}Template:{Colors.BWHITE}    {template}")
            print_separator("-", 50)
            print()
            
            # Get scan data
            if scan_id:
                scan_data = self._get_scan_data(scan_id)
            else:
                scan_data = self._get_all_scans()
            
            if not scan_data:
                print_error("No scan data found")
                return None
            
            # Generate report
            print_subsection("Generating Report")
            
            if format_type == 'json':
                report = self._generate_json(scan_data, include_raw)
            elif format_type == 'html':
                report = self._generate_html(scan_data, template)
            elif format_type == 'text':
                report = self._generate_text(scan_data)
            elif format_type == 'csv':
                report = self._generate_csv(scan_data)
            else:
                report = self._generate_json(scan_data, include_raw)
            
            # Save report
            if output:
                self._save_report(report, output, format_type)
            else:
                # Default output
                output = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_type}"
                self._save_report(report, output, format_type)
            
            # Display summary
            self._display_summary(scan_data)
            
            return report
        
        except Exception as e:
            print_error(f"Report generation failed: {e}")
            return None
    
    def _get_scan_data(self, scan_id):
        """Get scan data from database"""
        try:
            db = get_database()
            with db._cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM scans WHERE id = ?
                """, (scan_id,))
                scan = cursor.fetchone()
                
                if not scan:
                    return None
                
                cursor.execute("""
                    SELECT * FROM vulnerabilities WHERE scan_id = ?
                """, (scan_id,))
                vulns = cursor.fetchall()
                
                cursor.execute("""
                    SELECT * FROM scan_results WHERE scan_id = ?
                """, (scan_id,))
                results = cursor.fetchall()
                
                return {
                    'scan': dict(scan) if scan else None,
                    'vulnerabilities': [dict(v) for v in vulns],
                    'results': [dict(r) for r in results],
                }
        except Exception as e:
            print_warning(f"Could not fetch scan data: {e}")
            return None
    
    def _get_all_scans(self):
        """Get all scan data"""
        try:
            db = get_database()
            with db._cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM scans ORDER BY start_time DESC LIMIT 100
                """)
                scans = cursor.fetchall()
                
                all_data = []
                for scan in scans:
                    scan_id = scan['id']
                    
                    cursor.execute("""
                        SELECT * FROM vulnerabilities WHERE scan_id = ?
                    """, (scan_id,))
                    vulns = cursor.fetchall()
                    
                    cursor.execute("""
                        SELECT * FROM scan_results WHERE scan_id = ?
                    """, (scan_id,))
                    results = cursor.fetchall()
                    
                    all_data.append({
                        'scan': dict(scan),
                        'vulnerabilities': [dict(v) for v in vulns],
                        'results': [dict(r) for r in results],
                    })
                
                return all_data
        except Exception as e:
            print_warning(f"Could not fetch scan data: {e}")
            return []
    
    def _generate_json(self, scan_data, include_raw=False):
        """Generate JSON report"""
        report = {
            'report_info': {
                'generated': datetime.now().isoformat(),
                'tool': 'BYMA TOOLS',
                'version': '1.0.0',
            },
            'scans': scan_data if isinstance(scan_data, list) else [scan_data],
        }
        
        if not include_raw:
            # Simplify results
            for scan in report['scans']:
                if 'results' in scan:
                    scan['results_count'] = len(scan['results'])
                    scan['results'] = 'See full report for details'
        
        return json.dumps(report, indent=2, default=str)
    
    def _generate_html(self, scan_data, template='standard'):
        """Generate HTML report"""
        scans = scan_data if isinstance(scan_data, list) else [scan_data]
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>BYMA TOOLS Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .vuln {{ background: #fee; border-left: 4px solid red; padding: 10px; margin: 5px 0; }}
        .info {{ background: #efe; border-left: 4px solid green; padding: 10px; margin: 5px 0; }}
        .warning {{ background: #ffa; border-left: 4px solid orange; padding: 10px; margin: 5px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>BYMA TOOLS Security Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
"""
        
        for scan in scans:
            scan_info = scan.get('scan', {})
            vulns = scan.get('vulnerabilities', [])
            
            html += f"""
    <div class="section">
        <h2>Scan: {scan_info.get('scan_type', 'Unknown')}</h2>
        <p><strong>Target:</strong> {scan_info.get('target', 'N/A')}</p>
        <p><strong>Status:</strong> {scan_info.get('status', 'N/A')}</p>
        <p><strong>Start Time:</strong> {scan_info.get('start_time', 'N/A')}</p>
        
        <h3>Vulnerabilities ({len(vulns)})</h3>
"""
            
            for vuln in vulns:
                severity = vuln.get('severity', 'UNKNOWN').lower()
                css_class = 'vuln' if severity in ['critical', 'high'] else 'warning' if severity == 'medium' else 'info'
                
                html += f"""
        <div class="{css_class}">
            <strong>{vuln.get('vuln_type', 'Unknown')}</strong> - {vuln.get('severity', 'Unknown')}<br>
            Location: {vuln.get('location', 'N/A')}<br>
            Evidence: {vuln.get('evidence', 'N/A')}
        </div>
"""
            
            html += "    </div>\n"
        
        html += """
</body>
</html>
"""
        
        return html
    
    def _generate_text(self, scan_data):
        """Generate text report"""
        scans = scan_data if isinstance(scan_data, list) else [scan_data]
        
        text = "=" * 60 + "\n"
        text += "BYMA TOOLS SECURITY REPORT\n"
        text += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        text += "=" * 60 + "\n\n"
        
        for scan in scans:
            scan_info = scan.get('scan', {})
            vulns = scan.get('vulnerabilities', [])
            
            text += f"Scan: {scan_info.get('scan_type', 'Unknown')}\n"
            text += f"Target: {scan_info.get('target', 'N/A')}\n"
            text += f"Status: {scan_info.get('status', 'N/A')}\n"
            text += f"Start Time: {scan_info.get('start_time', 'N/A')}\n"
            text += "-" * 40 + "\n"
            text += f"Vulnerabilities: {len(vulns)}\n\n"
            
            for i, vuln in enumerate(vulns, 1):
                text += f"  #{i} {vuln.get('vuln_type', 'Unknown')}\n"
                text += f"     Severity: {vuln.get('severity', 'Unknown')}\n"
                text += f"     Location: {vuln.get('location', 'N/A')}\n"
                text += f"     Evidence: {vuln.get('evidence', 'N/A')}\n\n"
        
        return text
    
    def _generate_csv(self, scan_data):
        """Generate CSV report"""
        scans = scan_data if isinstance(scan_data, list) else [scan_data]
        
        csv = "Scan Type,Target,Status,Start Time,Vulnerability Type,Severity,Location,Evidence\n"
        
        for scan in scans:
            scan_info = scan.get('scan', {})
            vulns = scan.get('vulnerabilities', [])
            
            for vuln in vulns:
                csv += f'"{scan_info.get("scan_type", "")}","{scan_info.get("target", "")}","{scan_info.get("status", "")}","{scan_info.get("start_time", "")}","{vuln.get("vuln_type", "")}","{vuln.get("severity", "")}","{vuln.get("location", "")}","{vuln.get("evidence", "")}"\n'
        
        return csv
    
    def _save_report(self, report, output_file, format_type):
        """Save report to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            
            print_success(f"Report saved to {output_file}")
        except Exception as e:
            print_error(f"Failed to save report: {e}")
    
    def _display_summary(self, scan_data):
        """Display report summary"""
        scans = scan_data if isinstance(scan_data, list) else [scan_data]
        
        total_vulns = 0
        severity_counts = {}
        
        for scan in scans:
            vulns = scan.get('vulnerabilities', [])
            total_vulns += len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print()
        print_subsection("Report Summary")
        print(f"  {Icons.INFO} {Colors.BCYAN}Total Scans:{Colors.BWHITE}      {len(scans)}")
        print(f"  {Icons.INFO} {Colors.BCYAN}Total Vulnerabilities:{Colors.BWHITE} {total_vulns}")
        
        if severity_counts:
            print(f"  {Icons.INFO} {Colors.BCYAN}By Severity:{Colors.BWHITE}")
            for severity, count in sorted(severity_counts.items()):
                print(f"       {severity}: {count}")
        
        print()
