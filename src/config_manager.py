import os
import yaml
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

class ConfigManager:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()
        self.config = {}
        self.logger = logging.getLogger(__name__)
        
        # Default configuration
        self.default_config = {
            'monitoring': {
                'interface': 'eth0',
                'packet_count': 1000,
                'timeout': 30,
                'capture_filter': ''
            },
            'thresholds': {
                'brute_force_attempts': 5,
                'brute_force_time_window': 300,
                'ddos_packets_per_second': 1000,
                'port_scan_threshold': 10,
                'port_scan_time_window': 60,
                'suspicious_ports': [22, 23, 135, 445, 3389, 5900, 1433, 3306],
                'data_exfiltration_threshold_mb': 100
            },
            'detection': {
                'enable_port_scan': True,
                'enable_brute_force': True,
                'enable_ddos': True,
                'enable_malware_communication': True,
                'enable_data_exfiltration': True
            },
            'integrations': {
                'virustotal_api_key': '',
                'abuseipdb_api_key': '',
                'enable_api_lookups': False,
                'api_rate_limit': 4
            },
            'reporting': {
                'console_output': True,
                'log_file': 'threat_analyzer.log',
                'export_formats': ['json', 'csv'],
                'html_dashboard': True,
                'dashboard_port': 8080
            },
            'notifications': {
                'email_enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'smtp_username': '',
                'smtp_password': '',
                'recipients': [],
                'alert_levels': ['high', 'critical']
            },
            'database': {
                'file_path': 'threats.db',
                'max_file_size_mb': 100,
                'auto_rotate': True,
                'retention_days': 30
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': 'network_threat_analyzer.log'
            }
        }
        
        self.load_config()

    def _find_config_file(self) -> str:
        """Find configuration file in standard locations"""
        possible_paths = [
            'config.yaml',
            'configs/config.yaml',
            os.path.expanduser('~/.network_threat_analyzer/config.yaml'),
            '/etc/network_threat_analyzer/config.yaml'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Return first path as default
        return possible_paths[0]

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as file:
                    user_config = yaml.safe_load(file) or {}
                    
                # Merge with default config
                self.config = self._deep_merge(self.default_config, user_config)
                self.logger.info(f"Configuration loaded from {self.config_path}")
            else:
                self.config = self.default_config.copy()
                self.logger.warning(f"Configuration file not found: {self.config_path}. Using defaults.")
                
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing YAML configuration: {e}")
            self.config = self.default_config.copy()
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            self.config = self.default_config.copy()
        
        # Override with environment variables
        self._load_env_overrides()
        
        return self.config

    def _deep_merge(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries"""
        result = base.copy()
        
        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result

    def _load_env_overrides(self):
        """Load configuration overrides from environment variables"""
        env_mappings = {
            'NTA_INTERFACE': ('monitoring', 'interface'),
            'NTA_PACKET_COUNT': ('monitoring', 'packet_count'),
            'NTA_TIMEOUT': ('monitoring', 'timeout'),
            'NTA_VT_API_KEY': ('integrations', 'virustotal_api_key'),
            'NTA_ABUSEIPDB_API_KEY': ('integrations', 'abuseipdb_api_key'),
            'NTA_ENABLE_API_LOOKUPS': ('integrations', 'enable_api_lookups'),
            'NTA_DB_PATH': ('database', 'file_path'),
            'NTA_LOG_LEVEL': ('logging', 'level'),
            'NTA_LOG_FILE': ('logging', 'file'),
            'NTA_SMTP_SERVER': ('notifications', 'smtp_server'),
            'NTA_SMTP_PORT': ('notifications', 'smtp_port'),
            'NTA_SMTP_USERNAME': ('notifications', 'smtp_username'),
            'NTA_SMTP_PASSWORD': ('notifications', 'smtp_password'),
            'NTA_EMAIL_ENABLED': ('notifications', 'email_enabled')
        }
        
        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Type conversion
                if key in ['packet_count', 'timeout', 'smtp_port']:
                    try:
                        value = int(value)
                    except ValueError:
                        self.logger.warning(f"Invalid integer value for {env_var}: {value}")
                        continue
                elif key in ['enable_api_lookups', 'email_enabled']:
                    value = value.lower() in ('true', '1', 'yes', 'on')
                
                if section not in self.config:
                    self.config[section] = {}
                self.config[section][key] = value
                self.logger.debug(f"Environment override: {env_var} -> {section}.{key} = {value}")

    def save_config(self, config_path: Optional[str] = None) -> bool:
        """Save current configuration to YAML file"""
        path = config_path or self.config_path
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            with open(path, 'w') as file:
                yaml.dump(self.config, file, default_flow_style=False, indent=2)
            
            self.logger.info(f"Configuration saved to {path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            return False

    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """Get configuration value"""
        if key is None:
            return self.config.get(section, default)
        
        section_config = self.config.get(section, {})
        return section_config.get(key, default)

    def set(self, section: str, key: str, value: Any):
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value

    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Validate monitoring configuration
        monitoring = self.config.get('monitoring', {})
        if not isinstance(monitoring.get('packet_count'), int) or monitoring.get('packet_count') < 0:
            issues.append("monitoring.packet_count must be a non-negative integer")
        
        if not isinstance(monitoring.get('timeout'), int) or monitoring.get('timeout') < 0:
            issues.append("monitoring.timeout must be a non-negative integer")
        
        # Validate thresholds
        thresholds = self.config.get('thresholds', {})
        threshold_checks = [
            ('brute_force_attempts', int, 1),
            ('brute_force_time_window', int, 1),
            ('ddos_packets_per_second', int, 1),
            ('port_scan_threshold', int, 1),
            ('port_scan_time_window', int, 1)
        ]
        
        for key, expected_type, min_value in threshold_checks:
            value = thresholds.get(key)
            if not isinstance(value, expected_type) or value < min_value:
                issues.append(f"thresholds.{key} must be a {expected_type.__name__} >= {min_value}")
        
        # Validate suspicious ports
        suspicious_ports = thresholds.get('suspicious_ports', [])
        if not isinstance(suspicious_ports, list):
            issues.append("thresholds.suspicious_ports must be a list")
        else:
            for port in suspicious_ports:
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    issues.append(f"Invalid port in suspicious_ports: {port}")
        
        # Validate database configuration
        database = self.config.get('database', {})
        if not isinstance(database.get('max_file_size_mb'), int) or database.get('max_file_size_mb') < 1:
            issues.append("database.max_file_size_mb must be an integer >= 1")
        
        if not isinstance(database.get('retention_days'), int) or database.get('retention_days') < 0:
            issues.append("database.retention_days must be a non-negative integer")
        
        # Validate notification configuration
        notifications = self.config.get('notifications', {})
        if notifications.get('email_enabled'):
            required_fields = ['smtp_server', 'smtp_username', 'smtp_password', 'recipients']
            for field in required_fields:
                if not notifications.get(field):
                    issues.append(f"notifications.{field} is required when email is enabled")
            
            smtp_port = notifications.get('smtp_port')
            if not isinstance(smtp_port, int) or not (1 <= smtp_port <= 65535):
                issues.append("notifications.smtp_port must be a valid port number")
        
        # Validate API configuration
        integrations = self.config.get('integrations', {})
        if integrations.get('enable_api_lookups'):
            if not integrations.get('virustotal_api_key') and not integrations.get('abuseipdb_api_key'):
                issues.append("At least one API key required when enable_api_lookups is true")
        
        return issues

    def get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        try:
            import psutil
            interfaces = list(psutil.net_if_addrs().keys())
            return [iface for iface in interfaces if not iface.startswith('lo')]
        except ImportError:
            self.logger.warning("psutil not available, cannot list network interfaces")
            return ['eth0', 'wlan0', 'en0']  # Common defaults

    def create_sample_config(self, output_path: str) -> bool:
        """Create a sample configuration file with comments"""
        sample_config = """# Network Threat Analyzer Configuration
# All settings are optional and will fall back to defaults if not specified

monitoring:
  # Network interface to monitor (use 'any' for all interfaces)
  interface: "eth0"
  
  # Number of packets to capture (0 = unlimited)
  packet_count: 1000
  
  # Capture timeout in seconds (0 = no timeout)
  timeout: 30
  
  # BPF capture filter (leave empty for no filter)
  capture_filter: ""

thresholds:
  # Number of failed login attempts before triggering brute force alert
  brute_force_attempts: 5
  
  # Time window for brute force detection (seconds)
  brute_force_time_window: 300
  
  # Packets per second threshold for DDoS detection
  ddos_packets_per_second: 1000
  
  # Number of ports to trigger port scan alert
  port_scan_threshold: 10
  
  # Time window for port scan detection (seconds)
  port_scan_time_window: 60
  
  # List of ports considered suspicious
  suspicious_ports: [22, 23, 135, 445, 3389, 5900, 1433, 3306]
  
  # Data exfiltration threshold in MB
  data_exfiltration_threshold_mb: 100

detection:
  # Enable/disable specific detection modules
  enable_port_scan: true
  enable_brute_force: true
  enable_ddos: true
  enable_malware_communication: true
  enable_data_exfiltration: true

integrations:
  # VirusTotal API key (get from https://www.virustotal.com/gui/my-apikey)
  virustotal_api_key: ""
  
  # AbuseIPDB API key (get from https://www.abuseipdb.com/api)
  abuseipdb_api_key: ""
  
  # Enable external API lookups (requires API keys)
  enable_api_lookups: false
  
  # API rate limit (requests per minute)
  api_rate_limit: 4

reporting:
  # Enable console output
  console_output: true
  
  # Log file path
  log_file: "threat_analyzer.log"
  
  # Export formats to support
  export_formats: ["json", "csv"]
  
  # Enable HTML dashboard
  html_dashboard: true
  
  # Dashboard web server port
  dashboard_port: 8080

notifications:
  # Enable email notifications
  email_enabled: false
  
  # SMTP server settings
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  smtp_username: ""
  smtp_password: ""
  
  # Email recipients
  recipients: []
  
  # Alert levels to send notifications for
  alert_levels: ["high", "critical"]

database:
  # SQLite database file path
  file_path: "threats.db"
  
  # Maximum database file size in MB
  max_file_size_mb: 100
  
  # Auto-rotate database when size limit reached
  auto_rotate: true
  
  # Data retention period in days
  retention_days: 30

logging:
  # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  level: "INFO"
  
  # Log message format
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  
  # Log file path
  file: "network_threat_analyzer.log"
"""
        
        try:
            with open(output_path, 'w') as file:
                file.write(sample_config)
            self.logger.info(f"Sample configuration created: {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error creating sample configuration: {e}")
            return False

    def __getitem__(self, key):
        """Allow dictionary-style access"""
        return self.config[key]

    def __setitem__(self, key, value):
        """Allow dictionary-style assignment"""
        self.config[key] = value

    def __contains__(self, key):
        """Allow 'in' operator"""
        return key in self.config

    def keys(self):
        """Return configuration keys"""
        return self.config.keys()

    def items(self):
        """Return configuration items"""
        return self.config.items()

    def copy(self):
        """Return a copy of the configuration"""
        return self.config.copy()