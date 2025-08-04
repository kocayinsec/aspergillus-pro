import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Any
import threading

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
except ImportError:
    print("Error: scapy not installed. Run: pip install scapy")
    exit(1)

@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    flags: Optional[str] = None
    payload_size: int = 0

class PacketAnalyzer:
    def __init__(self, interface: str = None, packet_count: int = 0, timeout: int = 30):
        self.interface = interface
        self.packet_count = packet_count
        self.timeout = timeout
        self.is_running = False
        self.packet_buffer = deque(maxlen=10000)
        self.callbacks: List[Callable[[PacketInfo], None]] = []
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0
        }
        self.logger = logging.getLogger(__name__)
        self.lock = threading.Lock()

    def add_callback(self, callback: Callable[[PacketInfo], None]):
        """Add callback function to be called for each analyzed packet"""
        self.callbacks.append(callback)

    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract relevant information from captured packet"""
        try:
            if not packet.haslayer(IP):
                return None

            ip_layer = packet[IP]
            timestamp = time.time()
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            packet_size = len(packet)
            
            src_port = None
            dst_port = None
            protocol = "OTHER"
            flags = None
            payload_size = 0

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
                flags = self._get_tcp_flags(tcp_layer)
                payload_size = len(tcp_layer.payload)
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
                payload_size = len(udp_layer.payload)
                
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                payload_size = len(packet[ICMP].payload) if packet[ICMP].payload else 0

            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                flags=flags,
                payload_size=payload_size
            )
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None

    def _get_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string"""
        flags = []
        if tcp_layer.flags.F: flags.append("FIN")
        if tcp_layer.flags.S: flags.append("SYN")
        if tcp_layer.flags.R: flags.append("RST")
        if tcp_layer.flags.P: flags.append("PSH")
        if tcp_layer.flags.A: flags.append("ACK")
        if tcp_layer.flags.U: flags.append("URG")
        return "|".join(flags)

    def _packet_handler(self, packet):
        """Handle each captured packet"""
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return

        with self.lock:
            self.packet_buffer.append(packet_info)
            self.stats['total_packets'] += 1
            
            if packet_info.protocol == "TCP":
                self.stats['tcp_packets'] += 1
            elif packet_info.protocol == "UDP":
                self.stats['udp_packets'] += 1
            elif packet_info.protocol == "ICMP":
                self.stats['icmp_packets'] += 1
            else:
                self.stats['other_packets'] += 1

        # Call all registered callbacks
        for callback in self.callbacks:
            try:
                callback(packet_info)
            except Exception as e:
                self.logger.error(f"Error in packet callback: {e}")

    def start_capture(self, capture_filter: str = ""):
        """Start packet capture"""
        self.logger.info(f"Starting packet capture on interface: {self.interface}")
        self.is_running = True
        
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                count=self.packet_count if self.packet_count > 0 else 0,
                timeout=self.timeout if self.timeout > 0 else None,
                filter=capture_filter,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            self.logger.error(f"Error during packet capture: {e}")
            raise
        finally:
            self.is_running = False

    def stop_capture(self):
        """Stop packet capture"""
        self.logger.info("Stopping packet capture")
        self.is_running = False

    def get_recent_packets(self, count: int = 100) -> List[PacketInfo]:
        """Get most recent packets from buffer"""
        with self.lock:
            return list(self.packet_buffer)[-count:]

    def get_stats(self) -> Dict[str, Any]:
        """Get packet capture statistics"""
        with self.lock:
            return self.stats.copy()

    def clear_buffer(self):
        """Clear packet buffer"""
        with self.lock:
            self.packet_buffer.clear()

    async def start_async_capture(self, capture_filter: str = ""):
        """Start packet capture in async mode"""
        loop = asyncio.get_event_loop()
        capture_thread = threading.Thread(
            target=self.start_capture,
            args=(capture_filter,)
        )
        capture_thread.daemon = True
        capture_thread.start()
        
        while self.is_running and capture_thread.is_alive():
            await asyncio.sleep(0.1)

class TrafficAnalyzer:
    def __init__(self, time_window: int = 60):
        self.time_window = time_window
        self.traffic_data = defaultdict(list)
        self.connection_data = defaultdict(list)
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet_info: PacketInfo):
        """Analyze individual packet for traffic patterns"""
        current_time = time.time()
        
        # Clean old data
        self._cleanup_old_data(current_time)
        
        # Store traffic data
        key = f"{packet_info.src_ip}->{packet_info.dst_ip}"
        self.traffic_data[key].append({
            'timestamp': packet_info.timestamp,
            'size': packet_info.packet_size,
            'protocol': packet_info.protocol,
            'src_port': packet_info.src_port,
            'dst_port': packet_info.dst_port
        })
        
        # Store connection attempts
        if packet_info.protocol == "TCP" and packet_info.flags and "SYN" in packet_info.flags:
            conn_key = f"{packet_info.src_ip}:{packet_info.dst_ip}:{packet_info.dst_port}"
            self.connection_data[conn_key].append(packet_info.timestamp)

    def _cleanup_old_data(self, current_time: float):
        """Remove data older than time window"""
        cutoff_time = current_time - self.time_window
        
        # Clean traffic data
        for key in list(self.traffic_data.keys()):
            self.traffic_data[key] = [
                data for data in self.traffic_data[key]
                if data['timestamp'] > cutoff_time
            ]
            if not self.traffic_data[key]:
                del self.traffic_data[key]
        
        # Clean connection data
        for key in list(self.connection_data.keys()):
            self.connection_data[key] = [
                timestamp for timestamp in self.connection_data[key]
                if timestamp > cutoff_time
            ]
            if not self.connection_data[key]:
                del self.connection_data[key]

    def get_traffic_summary(self) -> Dict[str, Any]:
        """Get current traffic summary"""
        summary = {
            'active_connections': len(self.traffic_data),
            'total_packets': sum(len(data) for data in self.traffic_data.values()),
            'top_talkers': [],
            'protocol_distribution': defaultdict(int)
        }
        
        # Calculate top talkers
        traffic_volume = {}
        for key, packets in self.traffic_data.items():
            total_bytes = sum(p['size'] for p in packets)
            traffic_volume[key] = total_bytes
            
            for packet in packets:
                summary['protocol_distribution'][packet['protocol']] += 1
        
        # Sort by traffic volume
        summary['top_talkers'] = sorted(
            traffic_volume.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return summary

    def get_connection_attempts(self) -> Dict[str, List[float]]:
        """Get recent connection attempts"""
        return dict(self.connection_data)