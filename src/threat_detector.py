import time
import logging
import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Any
from enum import Enum
import statistics

from .packet_analyzer import PacketInfo

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatAlert:
    alert_id: str
    timestamp: float
    threat_type: str
    severity: ThreatLevel
    source_ip: str
    target_ip: Optional[str]
    description: str
    details: Dict[str, Any]
    recommended_action: str

class PortScanDetector:
    def __init__(self, threshold: int = 10, time_window: int = 60, suspicious_ports: List[int] = None):
        self.threshold = threshold
        self.time_window = time_window
        self.suspicious_ports = suspicious_ports or [22, 23, 135, 445, 3389, 5900, 1433, 3306]
        self.scan_attempts = defaultdict(lambda: defaultdict(list))
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet_info: PacketInfo) -> Optional[ThreatAlert]:
        """Analyze packet for port scanning activity"""
        if packet_info.protocol != "TCP" or not packet_info.flags or "SYN" not in packet_info.flags:
            return None

        current_time = time.time()
        src_ip = packet_info.src_ip
        dst_ip = packet_info.dst_ip
        dst_port = packet_info.dst_port

        if not dst_port:
            return None

        # Clean old scan attempts
        self._cleanup_old_attempts(current_time)

        # Record scan attempt
        self.scan_attempts[src_ip][dst_ip].append({
            'timestamp': packet_info.timestamp,
            'port': dst_port,
            'flags': packet_info.flags
        })

        # Check for port scan
        recent_attempts = [
            attempt for attempt in self.scan_attempts[src_ip][dst_ip]
            if current_time - attempt['timestamp'] <= self.time_window
        ]

        unique_ports = set(attempt['port'] for attempt in recent_attempts)
        
        if len(unique_ports) >= self.threshold:
            severity = self._determine_severity(unique_ports, recent_attempts)
            
            return ThreatAlert(
                alert_id=f"portscan_{src_ip}_{dst_ip}_{int(current_time)}",
                timestamp=current_time,
                threat_type="port_scan",
                severity=severity,
                source_ip=src_ip,
                target_ip=dst_ip,
                description=f"Port scan detected from {src_ip} to {dst_ip}",
                details={
                    'ports_scanned': list(unique_ports),
                    'scan_count': len(recent_attempts),
                    'suspicious_ports': [p for p in unique_ports if p in self.suspicious_ports],
                    'time_window': self.time_window
                },
                recommended_action="Block source IP and investigate network access"
            )

        return None

    def _cleanup_old_attempts(self, current_time: float):
        """Remove scan attempts older than time window"""
        cutoff_time = current_time - self.time_window
        
        for src_ip in list(self.scan_attempts.keys()):
            for dst_ip in list(self.scan_attempts[src_ip].keys()):
                self.scan_attempts[src_ip][dst_ip] = [
                    attempt for attempt in self.scan_attempts[src_ip][dst_ip]
                    if attempt['timestamp'] > cutoff_time
                ]
                if not self.scan_attempts[src_ip][dst_ip]:
                    del self.scan_attempts[src_ip][dst_ip]
            
            if not self.scan_attempts[src_ip]:
                del self.scan_attempts[src_ip]

    def _determine_severity(self, ports: Set[int], attempts: List[Dict]) -> ThreatLevel:
        """Determine severity based on ports and scan characteristics"""
        suspicious_count = len([p for p in ports if p in self.suspicious_ports])
        total_ports = len(ports)
        
        if suspicious_count >= 3 or total_ports >= 50:
            return ThreatLevel.CRITICAL
        elif suspicious_count >= 2 or total_ports >= 25:
            return ThreatLevel.HIGH
        elif suspicious_count >= 1 or total_ports >= 15:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

class BruteForceDetector:
    def __init__(self, threshold: int = 5, time_window: int = 300):
        self.threshold = threshold
        self.time_window = time_window
        self.auth_attempts = defaultdict(lambda: defaultdict(list))
        self.failed_logins = defaultdict(list)
        self.common_auth_ports = [22, 23, 21, 25, 110, 143, 993, 995, 3389, 5900]
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet_info: PacketInfo) -> Optional[ThreatAlert]:
        """Analyze packet for brute force attempts"""
        if packet_info.protocol != "TCP" or not packet_info.dst_port:
            return None

        if packet_info.dst_port not in self.common_auth_ports:
            return None

        current_time = time.time()
        src_ip = packet_info.src_ip
        dst_ip = packet_info.dst_ip
        dst_port = packet_info.dst_port

        # Clean old attempts
        self._cleanup_old_attempts(current_time)

        # Record authentication attempt
        self.auth_attempts[src_ip][f"{dst_ip}:{dst_port}"].append({
            'timestamp': packet_info.timestamp,
            'flags': packet_info.flags,
            'payload_size': packet_info.payload_size
        })

        # Check for brute force pattern
        target_key = f"{dst_ip}:{dst_port}"
        recent_attempts = [
            attempt for attempt in self.auth_attempts[src_ip][target_key]
            if current_time - attempt['timestamp'] <= self.time_window
        ]

        if len(recent_attempts) >= self.threshold:
            severity = self._determine_severity(recent_attempts, dst_port)
            
            return ThreatAlert(
                alert_id=f"bruteforce_{src_ip}_{target_key}_{int(current_time)}",
                timestamp=current_time,
                threat_type="brute_force",
                severity=severity,
                source_ip=src_ip,
                target_ip=dst_ip,
                description=f"Brute force attempt detected from {src_ip} to {dst_ip}:{dst_port}",
                details={
                    'attempt_count': len(recent_attempts),
                    'target_port': dst_port,
                    'service_type': self._get_service_type(dst_port),
                    'time_window': self.time_window,
                    'attempts_per_minute': len(recent_attempts) / (self.time_window / 60)
                },
                recommended_action="Block source IP and enable account lockout policies"
            )

        return None

    def _cleanup_old_attempts(self, current_time: float):
        """Remove attempts older than time window"""
        cutoff_time = current_time - self.time_window
        
        for src_ip in list(self.auth_attempts.keys()):
            for target in list(self.auth_attempts[src_ip].keys()):
                self.auth_attempts[src_ip][target] = [
                    attempt for attempt in self.auth_attempts[src_ip][target]
                    if attempt['timestamp'] > cutoff_time
                ]
                if not self.auth_attempts[src_ip][target]:
                    del self.auth_attempts[src_ip][target]
            
            if not self.auth_attempts[src_ip]:
                del self.auth_attempts[src_ip]

    def _determine_severity(self, attempts: List[Dict], port: int) -> ThreatLevel:
        """Determine severity based on attempt characteristics"""
        attempt_count = len(attempts)
        rate = attempt_count / (self.time_window / 60)  # attempts per minute
        
        if port in [22, 3389] and attempt_count >= 20:  # SSH/RDP
            return ThreatLevel.CRITICAL
        elif attempt_count >= 15 or rate >= 2:
            return ThreatLevel.HIGH
        elif attempt_count >= 10 or rate >= 1:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _get_service_type(self, port: int) -> str:
        """Get service type based on port"""
        service_map = {
            22: "SSH", 23: "Telnet", 21: "FTP", 25: "SMTP",
            110: "POP3", 143: "IMAP", 993: "IMAPS", 995: "POP3S",
            3389: "RDP", 5900: "VNC"
        }
        return service_map.get(port, f"Port {port}")

class DDoSDetector:
    def __init__(self, packets_per_second_threshold: int = 1000, time_window: int = 10):
        self.pps_threshold = packets_per_second_threshold
        self.time_window = time_window
        self.packet_counts = defaultdict(lambda: deque(maxlen=1000))
        self.traffic_baselines = defaultdict(lambda: {'avg': 0, 'std': 0, 'samples': deque(maxlen=100)})
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet_info: PacketInfo) -> Optional[ThreatAlert]:
        """Analyze packet for DDoS attack patterns"""
        current_time = time.time()
        dst_ip = packet_info.dst_ip
        
        # Record packet timestamp
        self.packet_counts[dst_ip].append(packet_info.timestamp)
        
        # Calculate recent packet rate
        recent_packets = [
            ts for ts in self.packet_counts[dst_ip]
            if current_time - ts <= self.time_window
        ]
        
        current_rate = len(recent_packets) / self.time_window
        
        # Update baseline
        self._update_baseline(dst_ip, current_rate)
        
        # Check for DDoS
        if current_rate >= self.pps_threshold:
            severity = self._determine_severity(current_rate, dst_ip)
            
            # Analyze attack characteristics
            attack_details = self._analyze_attack_pattern(packet_info, recent_packets)
            
            return ThreatAlert(
                alert_id=f"ddos_{dst_ip}_{int(current_time)}",
                timestamp=current_time,
                threat_type="ddos",
                severity=severity,
                source_ip="multiple",  # DDoS typically involves multiple sources
                target_ip=dst_ip,
                description=f"DDoS attack detected against {dst_ip}",
                details={
                    'packets_per_second': current_rate,
                    'threshold': self.pps_threshold,
                    'attack_type': attack_details['type'],
                    'source_diversity': attack_details['source_count'],
                    'protocol_distribution': attack_details['protocols'],
                    'anomaly_score': self._calculate_anomaly_score(current_rate, dst_ip)
                },
                recommended_action="Activate DDoS mitigation and rate limiting"
            )
        
        return None

    def _update_baseline(self, target_ip: str, rate: float):
        """Update traffic baseline for anomaly detection"""
        baseline = self.traffic_baselines[target_ip]
        baseline['samples'].append(rate)
        
        if len(baseline['samples']) >= 10:
            baseline['avg'] = statistics.mean(baseline['samples'])
            baseline['std'] = statistics.stdev(baseline['samples']) if len(baseline['samples']) > 1 else 0

    def _determine_severity(self, rate: float, target_ip: str) -> ThreatLevel:
        """Determine severity based on traffic rate and baseline"""
        if rate >= self.pps_threshold * 10:
            return ThreatLevel.CRITICAL
        elif rate >= self.pps_threshold * 5:
            return ThreatLevel.HIGH
        elif rate >= self.pps_threshold * 2:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _analyze_attack_pattern(self, packet_info: PacketInfo, recent_packets: List[float]) -> Dict[str, Any]:
        """Analyze attack pattern characteristics"""
        # This is a simplified analysis - in practice, you'd need to track more packet details
        return {
            'type': 'volumetric',  # Could be volumetric, protocol, or application layer
            'source_count': 'unknown',  # Would need to track source IPs
            'protocols': {packet_info.protocol: len(recent_packets)}
        }

    def _calculate_anomaly_score(self, current_rate: float, target_ip: str) -> float:
        """Calculate anomaly score based on baseline"""
        baseline = self.traffic_baselines[target_ip]
        if baseline['std'] == 0:
            return 0.0
        
        z_score = abs(current_rate - baseline['avg']) / baseline['std']
        return min(z_score / 10, 1.0)  # Normalize to 0-1 range

class MalwareCommunicationDetector:
    def __init__(self, suspicious_domains: List[str] = None, suspicious_ips: List[str] = None):
        self.suspicious_domains = suspicious_domains or []
        self.suspicious_ips = suspicious_ips or []
        self.c2_indicators = {
            'beaconing_intervals': defaultdict(list),
            'suspicious_patterns': defaultdict(int),
            'dns_requests': defaultdict(list)
        }
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet_info: PacketInfo) -> Optional[ThreatAlert]:
        """Analyze packet for malware communication patterns"""
        current_time = time.time()
        
        # Check for communication with known malicious IPs
        if packet_info.dst_ip in self.suspicious_ips:
            return ThreatAlert(
                alert_id=f"malware_comm_{packet_info.src_ip}_{packet_info.dst_ip}_{int(current_time)}",
                timestamp=current_time,
                threat_type="malware_communication",
                severity=ThreatLevel.HIGH,
                source_ip=packet_info.src_ip,
                target_ip=packet_info.dst_ip,
                description=f"Communication with known malicious IP {packet_info.dst_ip}",
                details={
                    'malicious_ip': packet_info.dst_ip,
                    'communication_port': packet_info.dst_port,
                    'protocol': packet_info.protocol,
                    'payload_size': packet_info.payload_size
                },
                recommended_action="Isolate infected host and perform malware analysis"
            )
        
        # Detect beaconing behavior (regular intervals)
        if packet_info.protocol in ["TCP", "UDP"] and packet_info.dst_port:
            connection_key = f"{packet_info.src_ip}:{packet_info.dst_ip}:{packet_info.dst_port}"
            self.c2_indicators['beaconing_intervals'][connection_key].append(packet_info.timestamp)
            
            # Check for beaconing pattern
            intervals = self.c2_indicators['beaconing_intervals'][connection_key]
            if len(intervals) >= 5:
                # Keep only recent intervals
                intervals = [ts for ts in intervals if current_time - ts <= 3600]  # 1 hour
                self.c2_indicators['beaconing_intervals'][connection_key] = intervals
                
                if self._detect_beaconing(intervals):
                    return ThreatAlert(
                        alert_id=f"beaconing_{packet_info.src_ip}_{packet_info.dst_ip}_{int(current_time)}",
                        timestamp=current_time,
                        threat_type="malware_beaconing",
                        severity=ThreatLevel.MEDIUM,
                        source_ip=packet_info.src_ip,
                        target_ip=packet_info.dst_ip,
                        description=f"Suspicious beaconing behavior detected from {packet_info.src_ip}",
                        details={
                            'beacon_intervals': self._calculate_intervals(intervals),
                            'target_host': packet_info.dst_ip,
                            'target_port': packet_info.dst_port,
                            'interval_count': len(intervals)
                        },
                        recommended_action="Investigate host for malware infection"
                    )
        
        return None

    def _detect_beaconing(self, timestamps: List[float]) -> bool:
        """Detect regular beaconing intervals"""
        if len(timestamps) < 5:
            return False
        
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        
        if len(intervals) < 4:
            return False
        
        # Check for regular intervals (coefficient of variation < 0.3)
        avg_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        if avg_interval > 0:
            coefficient_of_variation = std_interval / avg_interval
            return coefficient_of_variation < 0.3 and avg_interval >= 30  # At least 30 second intervals
        
        return False

    def _calculate_intervals(self, timestamps: List[float]) -> List[float]:
        """Calculate intervals between timestamps"""
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        return intervals

class ThreatDetectionEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.detectors = []
        self.alerts = deque(maxlen=1000)
        self.logger = logging.getLogger(__name__)
        
        # Initialize detectors based on configuration
        self._initialize_detectors()

    def _initialize_detectors(self):
        """Initialize threat detectors based on configuration"""
        detection_config = self.config.get('detection', {})
        thresholds = self.config.get('thresholds', {})
        
        if detection_config.get('enable_port_scan', True):
            self.detectors.append(PortScanDetector(
                threshold=thresholds.get('port_scan_threshold', 10),
                time_window=thresholds.get('port_scan_time_window', 60),
                suspicious_ports=thresholds.get('suspicious_ports', [])
            ))
        
        if detection_config.get('enable_brute_force', True):
            self.detectors.append(BruteForceDetector(
                threshold=thresholds.get('brute_force_attempts', 5),
                time_window=thresholds.get('brute_force_time_window', 300)
            ))
        
        if detection_config.get('enable_ddos', True):
            self.detectors.append(DDoSDetector(
                packets_per_second_threshold=thresholds.get('ddos_packets_per_second', 1000)
            ))
        
        if detection_config.get('enable_malware_communication', True):
            self.detectors.append(MalwareCommunicationDetector())

    def analyze_packet(self, packet_info: PacketInfo) -> List[ThreatAlert]:
        """Analyze packet with all enabled detectors"""
        alerts = []
        
        for detector in self.detectors:
            try:
                alert = detector.analyze_packet(packet_info)
                if alert:
                    alerts.append(alert)
                    self.alerts.append(alert)
                    self.logger.warning(f"Threat detected: {alert.description}")
            except Exception as e:
                self.logger.error(f"Error in threat detector {type(detector).__name__}: {e}")
        
        return alerts

    def get_recent_alerts(self, count: int = 50) -> List[ThreatAlert]:
        """Get most recent threat alerts"""
        return list(self.alerts)[-count:]

    def get_alerts_by_severity(self, severity: ThreatLevel) -> List[ThreatAlert]:
        """Get alerts filtered by severity level"""
        return [alert for alert in self.alerts if alert.severity == severity]

    def clear_alerts(self):
        """Clear all stored alerts"""
        self.alerts.clear()