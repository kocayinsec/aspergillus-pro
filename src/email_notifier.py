import smtplib
import ssl
import logging
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from typing import Dict, Any, List, Optional
import json

from .threat_detector import ThreatAlert, ThreatLevel

class EmailNotifier:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.notifications_config = config.get('notifications', {})
        self.logger = logging.getLogger(__name__)
        
        # Email configuration
        self.smtp_server = self.notifications_config.get('smtp_server', 'smtp.gmail.com')
        self.smtp_port = self.notifications_config.get('smtp_port', 587)
        self.username = self.notifications_config.get('smtp_username', '')
        self.password = self.notifications_config.get('smtp_password', '')
        self.recipients = self.notifications_config.get('recipients', [])
        self.alert_levels = self.notifications_config.get('alert_levels', ['high', 'critical'])
        
        # Rate limiting to prevent spam
        self.last_sent_times = {}
        self.rate_limit_minutes = 5  # Minimum 5 minutes between similar alerts
        
        # Validate configuration
        self._validate_config()

    def _validate_config(self):
        """Validate email configuration"""
        if not self.notifications_config.get('email_enabled', False):
            return
        
        required_fields = ['smtp_username', 'smtp_password', 'recipients']
        missing_fields = []
        
        for field in required_fields:
            if not self.notifications_config.get(field):
                missing_fields.append(field)
        
        if missing_fields:
            self.logger.error(f"Missing required email configuration fields: {missing_fields}")
            raise ValueError(f"Missing email configuration: {missing_fields}")
        
        if not isinstance(self.recipients, list) or not self.recipients:
            self.logger.error("No email recipients configured")
            raise ValueError("No email recipients configured")

    def _should_send_alert(self, alert: ThreatAlert) -> bool:
        """Determine if alert should be sent via email"""
        # Check if email notifications are enabled
        if not self.notifications_config.get('email_enabled', False):
            return False
        
        # Check if alert severity is in configured levels
        if alert.severity.value not in self.alert_levels:
            return False
        
        # Rate limiting - prevent spam for similar alerts
        alert_key = f"{alert.threat_type}_{alert.source_ip}_{alert.target_ip}"
        current_time = datetime.now()
        
        if alert_key in self.last_sent_times:
            time_diff = (current_time - self.last_sent_times[alert_key]).total_seconds()
            if time_diff < (self.rate_limit_minutes * 60):
                self.logger.debug(f"Rate limiting email for alert: {alert_key}")
                return False
        
        self.last_sent_times[alert_key] = current_time
        return True

    def _create_alert_email(self, alert: ThreatAlert) -> MIMEMultipart:
        """Create email message for threat alert"""
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"=¨ Network Threat Alert: {alert.threat_type.upper()} ({alert.severity.value.upper()})"
        msg['From'] = self.username
        msg['To'] = ", ".join(self.recipients)
        
        # Create plain text version
        text_body = self._create_text_body(alert)
        text_part = MIMEText(text_body, 'plain')
        msg.attach(text_part)
        
        # Create HTML version
        html_body = self._create_html_body(alert)
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        return msg

    def _create_text_body(self, alert: ThreatAlert) -> str:
        """Create plain text email body"""
        timestamp_str = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        body = f"""
NETWORK THREAT ALERT

Threat Type: {alert.threat_type.replace('_', ' ').title()}
Severity: {alert.severity.value.upper()}
Timestamp: {timestamp_str}
Source IP: {alert.source_ip}
"""
        
        if alert.target_ip:
            body += f"Target IP: {alert.target_ip}\n"
        
        body += f"""
Description: {alert.description}

Recommended Action: {alert.recommended_action}
"""
        
        if alert.details:
            body += "\nDetailed Information:\n"
            for key, value in alert.details.items():
                if key != 'threat_intel':  # Skip complex threat intel data in text version
                    body += f"  {key}: {value}\n"
        
        # Add threat intelligence summary if available
        if 'threat_intel' in alert.details:
            threat_intel = alert.details['threat_intel']
            if threat_intel.get('source_intel'):
                source_intel = threat_intel['source_intel']
                body += f"\nThreat Intelligence (Source IP):\n"
                body += f"  Malicious: {'Yes' if source_intel.get('is_malicious') else 'No'}\n"
                body += f"  Reputation Score: {source_intel.get('reputation_score', 'Unknown')}\n"
                body += f"  Sources: {', '.join(source_intel.get('sources', []))}\n"
        
        body += f"""
---
Generated by Network Threat Analyzer
Alert ID: {alert.alert_id}
"""
        
        return body

    def _create_html_body(self, alert: ThreatAlert) -> str:
        """Create HTML email body"""
        timestamp_str = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # Severity color mapping
        severity_colors = {
            'low': '#28a745',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545'
        }
        
        severity_color = severity_colors.get(alert.severity.value, '#6c757d')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Network Threat Alert</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: {severity_color}; color: white; padding: 20px; text-align: center; }}
                .content {{ background-color: #f8f9fa; padding: 20px; border: 1px solid #dee2e6; }}
                .field {{ margin-bottom: 10px; }}
                .field strong {{ display: inline-block; width: 120px; }}
                .details {{ background-color: white; padding: 15px; border-left: 4px solid {severity_color}; margin-top: 15px; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #6c757d; }}
                .severity-badge {{ background-color: {severity_color}; color: white; padding: 4px 8px; border-radius: 4px; }}
                .intel-section {{ background-color: #e3f2fd; padding: 10px; border-radius: 4px; margin-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>=¨ Network Threat Alert</h1>
                    <span class="severity-badge">{alert.severity.value.upper()}</span>
                </div>
                
                <div class="content">
                    <div class="field">
                        <strong>Threat Type:</strong> {alert.threat_type.replace('_', ' ').title()}
                    </div>
                    <div class="field">
                        <strong>Timestamp:</strong> {timestamp_str}
                    </div>
                    <div class="field">
                        <strong>Source IP:</strong> <code>{alert.source_ip}</code>
                    </div>
        """
        
        if alert.target_ip:
            html += f"""
                    <div class="field">
                        <strong>Target IP:</strong> <code>{alert.target_ip}</code>
                    </div>
            """
        
        html += f"""
                    <div class="field">
                        <strong>Description:</strong> {alert.description}
                    </div>
                    
                    <div class="details">
                        <h3>Recommended Action</h3>
                        <p>{alert.recommended_action}</p>
                    </div>
        """
        
        # Add detailed information
        if alert.details:
            html += """
                    <div class="details">
                        <h3>Technical Details</h3>
                        <ul>
            """
            
            for key, value in alert.details.items():
                if key != 'threat_intel':  # Handle threat intel separately
                    html += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
            
            html += "</ul></div>"
        
        # Add threat intelligence if available
        if 'threat_intel' in alert.details:
            threat_intel = alert.details['threat_intel']
            html += '<div class="intel-section"><h3>= Threat Intelligence</h3>'
            
            if threat_intel.get('source_intel'):
                source_intel = threat_intel['source_intel']
                malicious_status = "=4 Yes" if source_intel.get('is_malicious') else "=â No"
                reputation = source_intel.get('reputation_score', 'Unknown')
                sources = ', '.join(source_intel.get('sources', []))
                
                html += f"""
                <p><strong>Source IP Analysis:</strong></p>
                <ul>
                    <li><strong>Malicious:</strong> {malicious_status}</li>
                    <li><strong>Reputation Score:</strong> {reputation}/100</li>
                    <li><strong>Intelligence Sources:</strong> {sources}</li>
                </ul>
                """
            
            html += "</div>"
        
        html += f"""
                </div>
                
                <div class="footer">
                    <p>Generated by Network Threat Analyzer</p>
                    <p>Alert ID: <code>{alert.alert_id}</code></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html

    async def send_alert_email(self, alert: ThreatAlert) -> bool:
        """Send threat alert via email"""
        if not self._should_send_alert(alert):
            return False
        
        try:
            # Create email message
            msg = self._create_alert_email(alert)
            
            # Send email
            await self._send_email(msg)
            
            self.logger.info(f"Threat alert email sent: {alert.alert_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send threat alert email: {e}")
            return False

    async def _send_email(self, msg: MIMEMultipart):
        """Send email message"""
        # Run email sending in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_email_sync, msg)

    def _send_email_sync(self, msg: MIMEMultipart):
        """Send email synchronously"""
        try:
            # Create SMTP session
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()  # Enable security
            server.login(self.username, self.password)
            
            # Send email
            text = msg.as_string()
            server.sendmail(self.username, self.recipients, text)
            server.quit()
            
        except Exception as e:
            self.logger.error(f"SMTP error: {e}")
            raise

    async def send_summary_email(self, summary_data: Dict[str, Any]) -> bool:
        """Send periodic summary email"""
        if not self.notifications_config.get('email_enabled', False):
            return False
        
        try:
            # Create summary email
            msg = self._create_summary_email(summary_data)
            
            # Send email
            await self._send_email(msg)
            
            self.logger.info("Summary email sent successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send summary email: {e}")
            return False

    def _create_summary_email(self, summary_data: Dict[str, Any]) -> MIMEMultipart:
        """Create periodic summary email"""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"=Ê Network Security Summary - {datetime.now().strftime('%Y-%m-%d')}"
        msg['From'] = self.username
        msg['To'] = ", ".join(self.recipients)
        
        # Create text version
        text_body = self._create_summary_text(summary_data)
        text_part = MIMEText(text_body, 'plain')
        msg.attach(text_part)
        
        # Create HTML version
        html_body = self._create_summary_html(summary_data)
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        return msg

    def _create_summary_text(self, summary_data: Dict[str, Any]) -> str:
        """Create plain text summary"""
        total_threats = summary_data.get('total_threats', 0)
        period_days = summary_data.get('period_days', 7)
        
        body = f"""
NETWORK SECURITY SUMMARY ({period_days} days)

Total Threats Detected: {total_threats}
"""
        
        # Threats by severity
        threats_by_severity = summary_data.get('threats_by_severity', {})
        if threats_by_severity:
            body += "\nThreats by Severity:\n"
            for severity in ['critical', 'high', 'medium', 'low']:
                count = threats_by_severity.get(severity, 0)
                if count > 0:
                    body += f"  {severity.title()}: {count}\n"
        
        # Threats by type
        threats_by_type = summary_data.get('threats_by_type', {})
        if threats_by_type:
            body += "\nThreats by Type:\n"
            for threat_type, count in threats_by_type.items():
                body += f"  {threat_type.replace('_', ' ').title()}: {count}\n"
        
        # Top source IPs
        top_source_ips = summary_data.get('top_source_ips', {})
        if top_source_ips:
            body += "\nTop Source IPs:\n"
            for ip, count in list(top_source_ips.items())[:5]:
                body += f"  {ip}: {count}\n"
        
        body += """
---
Generated by Network Threat Analyzer
"""
        
        return body

    def _create_summary_html(self, summary_data: Dict[str, Any]) -> str:
        """Create HTML summary email"""
        total_threats = summary_data.get('total_threats', 0)
        period_days = summary_data.get('period_days', 7)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Network Security Summary</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #007bff; color: white; padding: 20px; text-align: center; }}
                .content {{ background-color: #f8f9fa; padding: 20px; border: 1px solid #dee2e6; }}
                .metric {{ background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #6c757d; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f8f9fa; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>=Ê Network Security Summary</h1>
                    <p>{period_days} Day Report</p>
                </div>
                
                <div class="content">
                    <div class="metric">
                        <h2>Total Threats: {total_threats}</h2>
                    </div>
        """
        
        # Threats by severity
        threats_by_severity = summary_data.get('threats_by_severity', {})
        if threats_by_severity:
            html += """
                    <div class="metric">
                        <h3>Threats by Severity</h3>
                        <table>
            """
            for severity in ['critical', 'high', 'medium', 'low']:
                count = threats_by_severity.get(severity, 0)
                if count > 0:
                    html += f"<tr><td>{severity.title()}</td><td>{count}</td></tr>"
            html += "</table></div>"
        
        # Threats by type
        threats_by_type = summary_data.get('threats_by_type', {})
        if threats_by_type:
            html += """
                    <div class="metric">
                        <h3>Threats by Type</h3>
                        <table>
            """
            for threat_type, count in threats_by_type.items():
                html += f"<tr><td>{threat_type.replace('_', ' ').title()}</td><td>{count}</td></tr>"
            html += "</table></div>"
        
        html += f"""
                </div>
                
                <div class="footer">
                    <p>Generated by Network Threat Analyzer</p>
                    <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html

    def test_email_configuration(self) -> bool:
        """Test email configuration by sending a test message"""
        if not self.notifications_config.get('email_enabled', False):
            self.logger.info("Email notifications are disabled")
            return False
        
        try:
            # Create test message
            msg = MIMEText("This is a test message from Network Threat Analyzer.")
            msg['Subject'] = "Network Threat Analyzer - Test Email"
            msg['From'] = self.username
            msg['To'] = ", ".join(self.recipients)
            
            # Send test email
            self._send_email_sync(msg)
            
            self.logger.info("Test email sent successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Test email failed: {e}")
            return False