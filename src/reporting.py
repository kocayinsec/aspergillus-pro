import json
import csv
import time
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
from dataclasses import asdict

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from .threat_detector import ThreatAlert, ThreatLevel
from .database import ThreatDatabase

class ConsoleReporter:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.use_colors = COLORAMA_AVAILABLE and config.get('reporting', {}).get('console_output', True)
        
        # Color mapping for threat levels
        self.severity_colors = {
            ThreatLevel.LOW: Fore.GREEN if self.use_colors else '',
            ThreatLevel.MEDIUM: Fore.YELLOW if self.use_colors else '',
            ThreatLevel.HIGH: Fore.RED if self.use_colors else '',
            ThreatLevel.CRITICAL: Fore.RED + Back.WHITE if self.use_colors else ''
        }

    def print_threat_alert(self, alert: ThreatAlert):
        """Print a threat alert to console with color coding"""
        if not self.config.get('reporting', {}).get('console_output', True):
            return
        
        timestamp_str = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        severity_color = self.severity_colors.get(alert.severity, '')
        reset = Style.RESET_ALL if self.use_colors else ''
        
        print(f"\n{severity_color}=¨ THREAT DETECTED {reset}")
        print(f"Time: {timestamp_str}")
        print(f"Type: {alert.threat_type.upper()}")
        print(f"Severity: {severity_color}{alert.severity.value.upper()}{reset}")
        print(f"Source: {alert.source_ip}")
        if alert.target_ip:
            print(f"Target: {alert.target_ip}")
        print(f"Description: {alert.description}")
        print(f"Action: {alert.recommended_action}")
        
        if alert.details:
            print("Details:")
            for key, value in alert.details.items():
                print(f"  {key}: {value}")
        
        print("-" * 60)

    def print_threat_summary(self, alerts: List[ThreatAlert]):
        """Print a summary of threat alerts"""
        if not alerts:
            print("No threats detected.")
            return
        
        # Group by severity
        by_severity = {}
        by_type = {}
        
        for alert in alerts:
            severity = alert.severity.value
            threat_type = alert.threat_type
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[threat_type] = by_type.get(threat_type, 0) + 1
        
        print(f"\n=Ê THREAT SUMMARY ({len(alerts)} total alerts)")
        print("=" * 50)
        
        print("\nBy Severity:")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = by_severity.get(severity, 0)
            if count > 0:
                color = self.severity_colors.get(ThreatLevel(severity), '')
                reset = Style.RESET_ALL if self.use_colors else ''
                print(f"  {color}{severity.upper()}: {count}{reset}")
        
        print("\nBy Type:")
        for threat_type, count in sorted(by_type.items()):
            print(f"  {threat_type.replace('_', ' ').title()}: {count}")

    def print_statistics_table(self, stats: Dict[str, Any]):
        """Print statistics in a formatted table"""
        if not TABULATE_AVAILABLE:
            self._print_statistics_simple(stats)
            return
        
        print(f"\n=È NETWORK STATISTICS")
        print("=" * 50)
        
        # Threat statistics
        if 'threats_by_type' in stats:
            threat_data = []
            for threat_type, count in stats['threats_by_type'].items():
                threat_data.append([threat_type.replace('_', ' ').title(), count])
            
            if threat_data:
                print("\nThreats by Type:")
                print(tabulate(threat_data, headers=['Type', 'Count'], tablefmt='grid'))
        
        # Top source IPs
        if 'top_source_ips' in stats:
            ip_data = []
            for ip, count in list(stats['top_source_ips'].items())[:10]:
                ip_data.append([ip, count])
            
            if ip_data:
                print("\nTop Source IPs:")
                print(tabulate(ip_data, headers=['IP Address', 'Alerts'], tablefmt='grid'))

    def _print_statistics_simple(self, stats: Dict[str, Any]):
        """Print statistics without tabulate library"""
        print(f"\n=È NETWORK STATISTICS")
        print("=" * 50)
        
        if 'threats_by_type' in stats:
            print("\nThreats by Type:")
            for threat_type, count in stats['threats_by_type'].items():
                print(f"  {threat_type.replace('_', ' ').title()}: {count}")
        
        if 'top_source_ips' in stats:
            print("\nTop Source IPs:")
            for ip, count in list(stats['top_source_ips'].items())[:10]:
                print(f"  {ip}: {count}")

class FileReporter:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def export_threats_json(self, alerts: List[ThreatAlert], output_file: str) -> bool:
        """Export threats to JSON file"""
        try:
            data = []
            for alert in alerts:
                alert_dict = asdict(alert)
                alert_dict['severity'] = alert.severity.value
                alert_dict['timestamp_readable'] = datetime.fromtimestamp(alert.timestamp).isoformat()
                data.append(alert_dict)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            
            self.logger.info(f"Exported {len(alerts)} threats to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {e}")
            return False

    def export_threats_csv(self, alerts: List[ThreatAlert], output_file: str) -> bool:
        """Export threats to CSV file"""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['alert_id', 'timestamp', 'timestamp_readable', 'threat_type', 
                             'severity', 'source_ip', 'target_ip', 'description', 
                             'recommended_action', 'details']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for alert in alerts:
                    row = asdict(alert)
                    row['severity'] = alert.severity.value
                    row['timestamp_readable'] = datetime.fromtimestamp(alert.timestamp).isoformat()
                    row['details'] = json.dumps(alert.details) if alert.details else ''
                    writer.writerow(row)
            
            self.logger.info(f"Exported {len(alerts)} threats to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {e}")
            return False

class HTMLReporter:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def generate_dashboard(self, db: ThreatDatabase, output_file: str = "dashboard.html") -> bool:
        """Generate HTML dashboard"""
        try:
            # Get data
            recent_threats = db.get_threats(limit=50)
            threat_stats = db.get_threat_statistics(days=7)
            packet_stats = db.get_packet_statistics(hours=24)
            
            html_content = self._generate_html_template(recent_threats, threat_stats, packet_stats)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Dashboard generated: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating dashboard: {e}")
            return False

    def _generate_html_template(self, threats: List[Dict], threat_stats: Dict, packet_stats: Dict) -> str:
        """Generate HTML template for dashboard"""
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Generate threat cards
        threat_cards = ""
        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }
        
        for threat in threats[:10]:  # Show latest 10
            timestamp = datetime.fromtimestamp(threat['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            color = severity_colors.get(threat['severity'], '#6c757d')
            
            threat_cards += f"""
            <div class="col-md-6 mb-3">
                <div class="card border-left" style="border-left: 4px solid {color};">
                    <div class="card-body">
                        <h6 class="card-title">{threat['threat_type'].replace('_', ' ').title()}</h6>
                        <p class="card-text">{threat['description']}</p>
                        <small class="text-muted">
                            <strong>Source:</strong> {threat['source_ip']}<br>
                            <strong>Time:</strong> {timestamp}<br>
                            <strong>Severity:</strong> <span class="badge" style="background-color: {color};">{threat['severity'].upper()}</span>
                        </small>
                    </div>
                </div>
            </div>
            """
        
        # Generate statistics
        total_threats = threat_stats.get('total_threats', 0)
        threats_by_severity = threat_stats.get('threats_by_severity', {})
        
        severity_stats = ""
        for severity, color in severity_colors.items():
            count = threats_by_severity.get(severity, 0)
            severity_stats += f"""
            <div class="col-md-3">
                <div class="card text-center" style="border-top: 3px solid {color};">
                    <div class="card-body">
                        <h3 class="card-title">{count}</h3>
                        <p class="card-text">{severity.upper()}</p>
                    </div>
                </div>
            </div>
            """
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Network Threat Analyzer Dashboard</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                .border-left {{ border-left: 4px solid #007bff !important; }}
                .card {{ margin-bottom: 1rem; }}
                .metric-card {{ text-align: center; padding: 1rem; }}
            </style>
        </head>
        <body>
            <nav class="navbar navbar-dark bg-dark">
                <div class="container-fluid">
                    <span class="navbar-brand mb-0 h1">
                        <i class="fas fa-shield-alt"></i> Network Threat Analyzer
                    </span>
                    <span class="navbar-text">
                        Last updated: {current_time}
                    </span>
                </div>
            </nav>
            
            <div class="container-fluid mt-4">
                <!-- Summary Cards -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card bg-primary text-white">
                            <div class="card-body text-center">
                                <h3>{total_threats}</h3>
                                <p>Total Threats (7 days)</p>
                            </div>
                        </div>
                    </div>
                    {severity_stats}
                </div>
                
                <!-- Recent Threats -->
                <div class="row">
                    <div class="col-12">
                        <h4><i class="fas fa-exclamation-triangle"></i> Recent Threats</h4>
                        <div class="row">
                            {threat_cards}
                        </div>
                    </div>
                </div>
                
                <!-- Charts -->
                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5>Threats by Type</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="threatTypeChart"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5>Threat Severity Distribution</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="severityChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Threat Type Chart
                const threatTypeData = {json.dumps(threat_stats.get('threats_by_type', {}))};
                const threatTypeChart = new Chart(document.getElementById('threatTypeChart'), {{
                    type: 'doughnut',
                    data: {{
                        labels: Object.keys(threatTypeData).map(key => key.replace('_', ' ')),
                        datasets: [{{
                            data: Object.values(threatTypeData),
                            backgroundColor: ['#ff6384', '#36a2eb', '#ffce56', '#4bc0c0', '#9966ff']
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false
                    }}
                }});
                
                // Severity Chart
                const severityData = {json.dumps(threats_by_severity)};
                const severityChart = new Chart(document.getElementById('severityChart'), {{
                    type: 'bar',
                    data: {{
                        labels: Object.keys(severityData),
                        datasets: [{{
                            label: 'Count',
                            data: Object.values(severityData),
                            backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {{
                            y: {{
                                beginAtZero: true
                            }}
                        }}
                    }}
                }});
                
                // Auto-refresh every 30 seconds
                setTimeout(() => {{
                    location.reload();
                }}, 30000);
            </script>
        </body>
        </html>
        """
        
        return html_template

class ChartGenerator:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.use_matplotlib = MATPLOTLIB_AVAILABLE

    def generate_threat_timeline(self, alerts: List[ThreatAlert], output_file: str = "threat_timeline.png") -> bool:
        """Generate threat timeline chart"""
        if not self.use_matplotlib:
            self.logger.warning("Matplotlib not available, cannot generate charts")
            return False
        
        try:
            if not alerts:
                return False
            
            # Group alerts by hour
            hourly_counts = {}
            for alert in alerts:
                hour = datetime.fromtimestamp(alert.timestamp).replace(minute=0, second=0, microsecond=0)
                hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
            
            # Sort by time
            times = sorted(hourly_counts.keys())
            counts = [hourly_counts[time] for time in times]
            
            plt.figure(figsize=(12, 6))
            plt.plot(times, counts, marker='o', linewidth=2, markersize=6)
            plt.title('Threat Detection Timeline', fontsize=16, fontweight='bold')
            plt.xlabel('Time')
            plt.ylabel('Number of Threats')
            plt.grid(True, alpha=0.3)
            
            # Format x-axis
            plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=2))
            plt.xticks(rotation=45)
            
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Threat timeline chart saved: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating threat timeline: {e}")
            return False

    def generate_severity_distribution(self, alerts: List[ThreatAlert], output_file: str = "severity_distribution.png") -> bool:
        """Generate severity distribution pie chart"""
        if not self.use_matplotlib:
            return False
        
        try:
            severity_counts = {}
            for alert in alerts:
                severity = alert.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if not severity_counts:
                return False
            
            colors = {'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107', 'low': '#28a745'}
            labels = list(severity_counts.keys())
            sizes = list(severity_counts.values())
            chart_colors = [colors.get(label, '#6c757d') for label in labels]
            
            plt.figure(figsize=(8, 8))
            plt.pie(sizes, labels=labels, colors=chart_colors, autopct='%1.1f%%', startangle=90)
            plt.title('Threat Severity Distribution', fontsize=16, fontweight='bold')
            plt.axis('equal')
            
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"Severity distribution chart saved: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating severity distribution: {e}")
            return False

class ReportManager:
    def __init__(self, config: Dict[str, Any], db: ThreatDatabase):
        self.config = config
        self.db = db
        self.console_reporter = ConsoleReporter(config)
        self.file_reporter = FileReporter(config)
        self.html_reporter = HTMLReporter(config)
        self.chart_generator = ChartGenerator(config)
        self.logger = logging.getLogger(__name__)

    def handle_threat_alert(self, alert: ThreatAlert):
        """Handle a new threat alert"""
        # Console output
        self.console_reporter.print_threat_alert(alert)
        
        # Store in database
        self.db.store_threat_alert(alert)

    def generate_summary_report(self, hours: int = 24):
        """Generate summary report for the specified time period"""
        since_timestamp = time.time() - (hours * 3600)
        alerts = self.db.get_threats(since=since_timestamp, limit=1000)
        
        # Convert dict alerts back to ThreatAlert objects for console display
        alert_objects = []
        for alert_dict in alerts:
            alert_objects.append(ThreatAlert(
                alert_id=alert_dict['alert_id'],
                timestamp=alert_dict['timestamp'],
                threat_type=alert_dict['threat_type'],
                severity=ThreatLevel(alert_dict['severity']),
                source_ip=alert_dict['source_ip'],
                target_ip=alert_dict['target_ip'],
                description=alert_dict['description'],
                details=alert_dict.get('details', {}),
                recommended_action=alert_dict['recommended_action']
            ))
        
        self.console_reporter.print_threat_summary(alert_objects)
        
        # Generate statistics
        stats = self.db.get_threat_statistics(days=hours//24 or 1)
        self.console_reporter.print_statistics_table(stats)

    def export_reports(self, output_dir: str = "reports", hours: int = 24) -> Dict[str, bool]:
        """Export reports in various formats"""
        os.makedirs(output_dir, exist_ok=True)
        
        since_timestamp = time.time() - (hours * 3600)
        alerts = self.db.get_threats(since=since_timestamp, limit=10000)
        
        # Convert to ThreatAlert objects
        alert_objects = []
        for alert_dict in alerts:
            alert_objects.append(ThreatAlert(
                alert_id=alert_dict['alert_id'],
                timestamp=alert_dict['timestamp'],
                threat_type=alert_dict['threat_type'],
                severity=ThreatLevel(alert_dict['severity']),
                source_ip=alert_dict['source_ip'],
                target_ip=alert_dict['target_ip'],
                description=alert_dict['description'],
                details=alert_dict.get('details', {}),
                recommended_action=alert_dict['recommended_action']
            ))
        
        results = {}
        
        # JSON export
        json_file = os.path.join(output_dir, f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        results['json'] = self.file_reporter.export_threats_json(alert_objects, json_file)
        
        # CSV export
        csv_file = os.path.join(output_dir, f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        results['csv'] = self.file_reporter.export_threats_csv(alert_objects, csv_file)
        
        # HTML dashboard
        html_file = os.path.join(output_dir, "dashboard.html")
        results['html'] = self.html_reporter.generate_dashboard(self.db, html_file)
        
        # Charts
        if alert_objects:
            timeline_file = os.path.join(output_dir, "threat_timeline.png")
            results['timeline'] = self.chart_generator.generate_threat_timeline(alert_objects, timeline_file)
            
            severity_file = os.path.join(output_dir, "severity_distribution.png")
            results['severity_chart'] = self.chart_generator.generate_severity_distribution(alert_objects, severity_file)
        
        return results