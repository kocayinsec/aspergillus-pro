import sqlite3
import logging
import os
import time
import json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import asdict

from .threat_detector import ThreatAlert, ThreatLevel
from .packet_analyzer import PacketInfo

class ThreatDatabase:
    def __init__(self, db_path: str = "threats.db", max_file_size_mb: int = 100, 
                 retention_days: int = 30, auto_rotate: bool = True):
        self.db_path = db_path
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.retention_days = retention_days
        self.auto_rotate = auto_rotate
        self.logger = logging.getLogger(__name__)
        
        self._init_database()

    def _init_database(self):
        """Initialize database tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create threats table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_id TEXT UNIQUE NOT NULL,
                        timestamp REAL NOT NULL,
                        threat_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        target_ip TEXT,
                        description TEXT NOT NULL,
                        details TEXT,
                        recommended_action TEXT,
                        status TEXT DEFAULT 'active',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create packets table for historical analysis
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        src_ip TEXT NOT NULL,
                        dst_ip TEXT NOT NULL,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT NOT NULL,
                        packet_size INTEGER NOT NULL,
                        flags TEXT,
                        payload_size INTEGER DEFAULT 0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create threat statistics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        date DATE NOT NULL,
                        threat_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        count INTEGER NOT NULL,
                        source_ips TEXT,
                        target_ips TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(date, threat_type, severity)
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_source_ip ON threats(source_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_stats_date ON threat_stats(date)')
                
                conn.commit()
                self.logger.info(f"Database initialized: {self.db_path}")
                
        except sqlite3.Error as e:
            self.logger.error(f"Database initialization error: {e}")
            raise

    def store_threat_alert(self, alert: ThreatAlert) -> bool:
        """Store threat alert in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO threats 
                    (alert_id, timestamp, threat_type, severity, source_ip, target_ip, 
                     description, details, recommended_action)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.alert_id,
                    alert.timestamp,
                    alert.threat_type,
                    alert.severity.value,
                    alert.source_ip,
                    alert.target_ip,
                    alert.description,
                    json.dumps(alert.details),
                    alert.recommended_action
                ))
                conn.commit()
                self.logger.debug(f"Stored threat alert: {alert.alert_id}")
                return True
                
        except sqlite3.Error as e:
            self.logger.error(f"Error storing threat alert: {e}")
            return False

    def store_packet_info(self, packet: PacketInfo, batch_size: int = 100) -> bool:
        """Store packet information (with batching for performance)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO packets 
                    (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, 
                     packet_size, flags, payload_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    packet.timestamp,
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    packet.protocol,
                    packet.packet_size,
                    packet.flags,
                    packet.payload_size
                ))
                conn.commit()
                return True
                
        except sqlite3.Error as e:
            self.logger.error(f"Error storing packet info: {e}")
            return False

    def get_threats(self, limit: int = 100, severity: Optional[ThreatLevel] = None,
                   threat_type: Optional[str] = None, since: Optional[float] = None) -> List[Dict[str, Any]]:
        """Retrieve threat alerts with optional filtering"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = "SELECT * FROM threats WHERE 1=1"
                params = []
                
                if severity:
                    query += " AND severity = ?"
                    params.append(severity.value)
                
                if threat_type:
                    query += " AND threat_type = ?"
                    params.append(threat_type)
                
                if since:
                    query += " AND timestamp >= ?"
                    params.append(since)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                threats = []
                for row in rows:
                    threat = dict(row)
                    if threat['details']:
                        threat['details'] = json.loads(threat['details'])
                    threats.append(threat)
                
                return threats
                
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving threats: {e}")
            return []

    def get_threat_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Get threat statistics for the specified number of days"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                since_timestamp = time.time() - (days * 24 * 3600)
                
                # Total threats by type
                cursor.execute('''
                    SELECT threat_type, COUNT(*) as count
                    FROM threats
                    WHERE timestamp >= ?
                    GROUP BY threat_type
                    ORDER BY count DESC
                ''', (since_timestamp,))
                threats_by_type = dict(cursor.fetchall())
                
                # Threats by severity
                cursor.execute('''
                    SELECT severity, COUNT(*) as count
                    FROM threats
                    WHERE timestamp >= ?
                    GROUP BY severity
                    ORDER BY 
                        CASE severity
                            WHEN 'critical' THEN 1
                            WHEN 'high' THEN 2
                            WHEN 'medium' THEN 3
                            WHEN 'low' THEN 4
                        END
                ''', (since_timestamp,))
                threats_by_severity = dict(cursor.fetchall())
                
                # Top source IPs
                cursor.execute('''
                    SELECT source_ip, COUNT(*) as count
                    FROM threats
                    WHERE timestamp >= ?
                    GROUP BY source_ip
                    ORDER BY count DESC
                    LIMIT 10
                ''', (since_timestamp,))
                top_source_ips = dict(cursor.fetchall())
                
                # Daily threat counts
                cursor.execute('''
                    SELECT DATE(datetime(timestamp, 'unixepoch')) as date, COUNT(*) as count
                    FROM threats
                    WHERE timestamp >= ?
                    GROUP BY DATE(datetime(timestamp, 'unixepoch'))
                    ORDER BY date DESC
                ''', (since_timestamp,))
                daily_counts = dict(cursor.fetchall())
                
                return {
                    'period_days': days,
                    'total_threats': sum(threats_by_type.values()),
                    'threats_by_type': threats_by_type,
                    'threats_by_severity': threats_by_severity,
                    'top_source_ips': top_source_ips,
                    'daily_counts': daily_counts
                }
                
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving threat statistics: {e}")
            return {}

    def get_packet_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get packet statistics for the specified number of hours"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                since_timestamp = time.time() - (hours * 3600)
                
                # Total packets by protocol
                cursor.execute('''
                    SELECT protocol, COUNT(*) as count, SUM(packet_size) as total_bytes
                    FROM packets
                    WHERE timestamp >= ?
                    GROUP BY protocol
                    ORDER BY count DESC
                ''', (since_timestamp,))
                protocol_stats = {}
                for row in cursor.fetchall():
                    protocol_stats[row[0]] = {'count': row[1], 'total_bytes': row[2]}
                
                # Top talkers
                cursor.execute('''
                    SELECT src_ip, COUNT(*) as packets, SUM(packet_size) as bytes
                    FROM packets
                    WHERE timestamp >= ?
                    GROUP BY src_ip
                    ORDER BY bytes DESC
                    LIMIT 10
                ''', (since_timestamp,))
                top_talkers = []
                for row in cursor.fetchall():
                    top_talkers.append({
                        'ip': row[0],
                        'packets': row[1],
                        'bytes': row[2]
                    })
                
                # Hourly packet counts
                cursor.execute('''
                    SELECT strftime('%Y-%m-%d %H', datetime(timestamp, 'unixepoch')) as hour,
                           COUNT(*) as count
                    FROM packets
                    WHERE timestamp >= ?
                    GROUP BY strftime('%Y-%m-%d %H', datetime(timestamp, 'unixepoch'))
                    ORDER BY hour DESC
                ''', (since_timestamp,))
                hourly_counts = dict(cursor.fetchall())
                
                return {
                    'period_hours': hours,
                    'protocol_stats': protocol_stats,
                    'top_talkers': top_talkers,
                    'hourly_counts': hourly_counts
                }
                
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving packet statistics: {e}")
            return {}

    def cleanup_old_data(self):
        """Remove data older than retention period"""
        if self.retention_days <= 0:
            return
        
        try:
            cutoff_timestamp = time.time() - (self.retention_days * 24 * 3600)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clean old threats
                cursor.execute('DELETE FROM threats WHERE timestamp < ?', (cutoff_timestamp,))
                threats_deleted = cursor.rowcount
                
                # Clean old packets
                cursor.execute('DELETE FROM packets WHERE timestamp < ?', (cutoff_timestamp,))
                packets_deleted = cursor.rowcount
                
                # Clean old stats
                cutoff_date = datetime.fromtimestamp(cutoff_timestamp).date()
                cursor.execute('DELETE FROM threat_stats WHERE date < ?', (cutoff_date,))
                stats_deleted = cursor.rowcount
                
                conn.commit()
                
                if threats_deleted > 0 or packets_deleted > 0 or stats_deleted > 0:
                    self.logger.info(f"Cleaned up old data: {threats_deleted} threats, "
                                   f"{packets_deleted} packets, {stats_deleted} stats")
                
                # Vacuum database to reclaim space
                cursor.execute('VACUUM')
                
        except sqlite3.Error as e:
            self.logger.error(f"Error during cleanup: {e}")

    def rotate_database_if_needed(self):
        """Rotate database file if it exceeds maximum size"""
        if not self.auto_rotate:
            return
        
        try:
            if os.path.exists(self.db_path):
                file_size = os.path.getsize(self.db_path)
                
                if file_size >= self.max_file_size_bytes:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_path = f"{self.db_path}.{timestamp}.backup"
                    
                    # Rename current database
                    os.rename(self.db_path, backup_path)
                    self.logger.info(f"Database rotated: {backup_path}")
                    
                    # Initialize new database
                    self._init_database()
                    
        except Exception as e:
            self.logger.error(f"Error during database rotation: {e}")

    def export_threats_to_csv(self, output_file: str, since: Optional[float] = None) -> bool:
        """Export threats to CSV file"""
        try:
            import csv
            
            threats = self.get_threats(limit=10000, since=since)
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                if not threats:
                    return True
                
                fieldnames = ['alert_id', 'timestamp', 'threat_type', 'severity', 
                             'source_ip', 'target_ip', 'description', 'recommended_action', 'details']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for threat in threats:
                    # Convert details dict to string for CSV
                    if isinstance(threat.get('details'), dict):
                        threat['details'] = json.dumps(threat['details'])
                    writer.writerow(threat)
            
            self.logger.info(f"Exported {len(threats)} threats to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting threats to CSV: {e}")
            return False

    def export_threats_to_json(self, output_file: str, since: Optional[float] = None) -> bool:
        """Export threats to JSON file"""
        try:
            threats = self.get_threats(limit=10000, since=since)
            
            with open(output_file, 'w', encoding='utf-8') as jsonfile:
                json.dump(threats, jsonfile, indent=2, default=str)
            
            self.logger.info(f"Exported {len(threats)} threats to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting threats to JSON: {e}")
            return False

    def close(self):
        """Perform cleanup before closing database"""
        self.cleanup_old_data()
        self.rotate_database_if_needed()
        self.logger.info("Database closed")