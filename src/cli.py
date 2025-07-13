import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from typing import Optional, List

from .config_manager import ConfigManager
from .packet_analyzer import PacketAnalyzer, TrafficAnalyzer
from .threat_detector import ThreatDetectionEngine
from .database import ThreatDatabase
from .reporting import ReportManager
from .api_integrations import ThreatIntelligenceAggregator
from .email_notifier import EmailNotifier

class NetworkThreatAnalyzer:
    def __init__(self, config_path: Optional[str] = None):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.config
        
        # Initialize logging
        self._setup_logging()
        
        self.logger = logging.getLogger(__name__)
        self.is_running = False
        
        # Initialize components
        self.packet_analyzer = None
        self.traffic_analyzer = None
        self.threat_detector = None
        self.database = None
        self.report_manager = None
        self.threat_intel = None
        self.email_notifier = None
        
        self._initialize_components()

    def _setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_file = log_config.get('file', 'network_threat_analyzer.log')
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def _initialize_components(self):
        """Initialize all system components"""
        try:
            # Database
            db_config = self.config.get('database', {})
            self.database = ThreatDatabase(
                db_path=db_config.get('file_path', 'threats.db'),
                max_file_size_mb=db_config.get('max_file_size_mb', 100),
                retention_days=db_config.get('retention_days', 30),
                auto_rotate=db_config.get('auto_rotate', True)
            )
            
            # Packet analyzer
            monitoring_config = self.config.get('monitoring', {})
            self.packet_analyzer = PacketAnalyzer(
                interface=monitoring_config.get('interface', 'eth0'),
                packet_count=monitoring_config.get('packet_count', 0),
                timeout=monitoring_config.get('timeout', 30)
            )
            
            # Traffic analyzer
            self.traffic_analyzer = TrafficAnalyzer(time_window=60)
            
            # Threat detection engine
            self.threat_detector = ThreatDetectionEngine(self.config)
            
            # Report manager
            self.report_manager = ReportManager(self.config, self.database)
            
            # Threat intelligence
            if self.config.get('integrations', {}).get('enable_api_lookups', False):
                self.threat_intel = ThreatIntelligenceAggregator(self.config)
            
            # Email notifier
            if self.config.get('notifications', {}).get('email_enabled', False):
                self.email_notifier = EmailNotifier(self.config)
            
            # Register callbacks
            self.packet_analyzer.add_callback(self._packet_callback)
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}")
            raise

    def _packet_callback(self, packet_info):
        """Callback function for each analyzed packet"""
        try:
            # Analyze traffic patterns
            self.traffic_analyzer.analyze_packet(packet_info)
            
            # Detect threats
            alerts = self.threat_detector.analyze_packet(packet_info)
            
            # Handle alerts
            for alert in alerts:
                asyncio.create_task(self._handle_threat_alert(alert))
            
            # Store packet info (optional, for detailed analysis)
            if self.config.get('database', {}).get('store_packets', False):
                self.database.store_packet_info(packet_info)
                
        except Exception as e:
            self.logger.error(f"Error in packet callback: {e}")

    async def _handle_threat_alert(self, alert):
        """Handle a detected threat alert"""
        try:
            # Enrich with threat intelligence
            if self.threat_intel:
                enrichment = await self.threat_intel.enrich_threat_alert(
                    alert.source_ip, alert.target_ip
                )
                alert.details.update({'threat_intel': enrichment})
            
            # Report the alert
            self.report_manager.handle_threat_alert(alert)
            
            # Send email notification if configured
            if self.email_notifier and alert.severity.value in self.config.get('notifications', {}).get('alert_levels', []):
                await self.email_notifier.send_alert_email(alert)
                
        except Exception as e:
            self.logger.error(f"Error handling threat alert: {e}")

    async def start_monitoring(self, duration: Optional[int] = None):
        """Start network monitoring"""
        self.logger.info("Starting network threat monitoring...")
        self.is_running = True
        
        try:
            # Start packet capture in background
            capture_filter = self.config.get('monitoring', {}).get('capture_filter', '')
            
            if duration:
                self.packet_analyzer.timeout = duration
            
            await self.packet_analyzer.start_async_capture(capture_filter)
            
        except KeyboardInterrupt:
            self.logger.info("Monitoring interrupted by user")
        except Exception as e:
            self.logger.error(f"Error during monitoring: {e}")
        finally:
            self.stop_monitoring()

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.logger.info("Stopping network threat monitoring...")
        self.is_running = False
        
        if self.packet_analyzer:
            self.packet_analyzer.stop_capture()
        
        if self.database:
            self.database.close()

def create_cli_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        description='Network Threat Analyzer - Real-time network security monitoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --monitor --interface eth0 --duration 3600
  %(prog)s --scan-logs --severity high --export json
  %(prog)s --real-time --dashboard
  %(prog)s --config-sample config.yaml
        '''
    )
    
    # Main operation modes
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument('--monitor', action='store_true',
                                help='Start real-time network monitoring')
    operation_group.add_argument('--scan-logs', action='store_true',
                                help='Scan and analyze existing logs')
    operation_group.add_argument('--dashboard', action='store_true',
                                help='Generate HTML dashboard')
    operation_group.add_argument('--export', choices=['json', 'csv', 'html', 'all'],
                                help='Export threat data')
    operation_group.add_argument('--config-sample', metavar='FILE',
                                help='Generate sample configuration file')
    operation_group.add_argument('--validate-config', action='store_true',
                                help='Validate configuration file')
    
    # Monitoring options
    monitor_group = parser.add_argument_group('monitoring options')
    monitor_group.add_argument('--interface', metavar='INTERFACE',
                              help='Network interface to monitor')
    monitor_group.add_argument('--duration', type=int, metavar='SECONDS',
                              help='Monitoring duration in seconds')
    monitor_group.add_argument('--packet-count', type=int, metavar='COUNT',
                              help='Number of packets to capture')
    monitor_group.add_argument('--filter', metavar='FILTER',
                              help='BPF capture filter')
    
    # Analysis options
    analysis_group = parser.add_argument_group('analysis options')
    analysis_group.add_argument('--severity', choices=['low', 'medium', 'high', 'critical'],
                               help='Filter by threat severity')
    analysis_group.add_argument('--threat-type', metavar='TYPE',
                               help='Filter by threat type')
    analysis_group.add_argument('--since', type=int, metavar='HOURS',
                               help='Analyze threats from last N hours')
    analysis_group.add_argument('--limit', type=int, metavar='COUNT', default=100,
                               help='Maximum number of results to show')
    
    # Output options
    output_group = parser.add_argument_group('output options')
    output_group.add_argument('--output', metavar='FILE',
                             help='Output file path')
    output_group.add_argument('--quiet', action='store_true',
                             help='Suppress console output')
    output_group.add_argument('--verbose', action='store_true',
                             help='Enable verbose output')
    
    # Configuration
    config_group = parser.add_argument_group('configuration')
    config_group.add_argument('--config', metavar='FILE',
                             help='Configuration file path')
    
    return parser

async def main():
    """Main entry point"""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    try:
        # Handle config sample generation
        if args.config_sample:
            config_manager = ConfigManager()
            if config_manager.create_sample_config(args.config_sample):
                print(f"Sample configuration created: {args.config_sample}")
                return 0
            else:
                print("Error creating sample configuration", file=sys.stderr)
                return 1
        
        # Initialize analyzer
        analyzer = NetworkThreatAnalyzer(args.config)
        
        # Handle config validation
        if args.validate_config:
            issues = analyzer.config_manager.validate_config()
            if issues:
                print("Configuration validation failed:")
                for issue in issues:
                    print(f"  - {issue}")
                return 1
            else:
                print("Configuration is valid")
                return 0
        
        # Apply command line overrides
        if args.interface:
            analyzer.config['monitoring']['interface'] = args.interface
        if args.duration:
            analyzer.config['monitoring']['timeout'] = args.duration
        if args.packet_count:
            analyzer.config['monitoring']['packet_count'] = args.packet_count
        if args.filter:
            analyzer.config['monitoring']['capture_filter'] = args.filter
        if args.quiet:
            analyzer.config['reporting']['console_output'] = False
        if args.verbose:
            analyzer.config['logging']['level'] = 'DEBUG'
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Handle different operation modes
        if args.monitor:
            # Setup signal handlers
            def signal_handler(signum, frame):
                analyzer.stop_monitoring()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            # Start monitoring
            await analyzer.start_monitoring(args.duration)
        
        elif args.scan_logs:
            # Analyze existing logs
            since_hours = args.since or 24
            analyzer.report_manager.generate_summary_report(since_hours)
        
        elif args.dashboard:
            # Generate dashboard
            output_file = args.output or "dashboard.html"
            if analyzer.report_manager.html_reporter.generate_dashboard(analyzer.database, output_file):
                print(f"Dashboard generated: {output_file}")
            else:
                print("Error generating dashboard", file=sys.stderr)
                return 1
        
        elif args.export:
            # Export data
            output_dir = args.output or "reports"
            since_hours = args.since or 24
            results = analyzer.report_manager.export_reports(output_dir, since_hours)
            
            success_count = sum(1 for success in results.values() if success)
            total_count = len(results)
            
            print(f"Export completed: {success_count}/{total_count} formats successful")
            for format_name, success in results.items():
                status = "" if success else ""
                print(f"  {status} {format_name}")
            
            if success_count == 0:
                return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(asyncio.run(main()))