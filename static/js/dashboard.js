class ThreatAnalyzerDashboard {
    constructor() {
        this.websocket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000;
        this.isMonitoring = false;
        this.chart = null;
        this.chartData = {
            labels: [],
            packets: [],
            threats: []
        };
        
        this.init();
    }

    init() {
        this.setupWebSocket();
        this.setupEventListeners();
        this.setupChart();
        this.loadInitialData();
    }

    setupWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        try {
            this.websocket = new WebSocket(wsUrl);
            
            this.websocket.onopen = (event) => {
                console.log('WebSocket connected');
                this.updateConnectionStatus(true);
                this.reconnectAttempts = 0;
            };
            
            this.websocket.onmessage = (event) => {
                this.handleWebSocketMessage(JSON.parse(event.data));
            };
            
            this.websocket.onclose = (event) => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus(false);
                this.attemptReconnect();
            };
            
            this.websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus(false);
            };
        } catch (error) {
            console.error('Failed to create WebSocket:', error);
            this.updateConnectionStatus(false);
        }
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'connection_established':
                this.updateStats(message.stats);
                break;
            case 'threat_alert':
                this.addThreatAlert(message.threat);
                this.showThreatToast(message.threat);
                break;
            case 'stats_update':
                this.updateStats(message.stats);
                break;
            case 'monitoring_started':
                this.isMonitoring = true;
                this.updateMonitoringStatus();
                this.showNotification('Monitoring started', 'success');
                break;
            case 'monitoring_stopped':
                this.isMonitoring = false;
                this.updateMonitoringStatus();
                this.showNotification('Monitoring stopped', 'info');
                break;
            case 'pong':
                // Handle ping/pong for keep-alive
                break;
            default:
                console.log('Unknown message type:', message.type);
        }
    }

    updateConnectionStatus(connected) {
        const statusIcon = document.getElementById('connection-status');
        const statusText = document.getElementById('connection-text');
        
        if (connected) {
            statusIcon.className = 'fas fa-circle text-success';
            statusText.textContent = 'Connected';
        } else {
            statusIcon.className = 'fas fa-circle text-danger';
            statusText.textContent = 'Disconnected';
        }
    }

    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
            
            console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);
            
            setTimeout(() => {
                this.setupWebSocket();
            }, delay);
        } else {
            console.error('Max reconnection attempts reached');
            this.showNotification('Connection lost. Please refresh the page.', 'danger');
        }
    }

    updateStats(stats) {
        document.getElementById('packets-count').textContent = stats.packets_analyzed || 0;
        document.getElementById('threats-count').textContent = stats.threats_detected || 0;
        document.getElementById('uptime').textContent = this.formatUptime(stats.uptime);
        document.getElementById('last-update').textContent = stats.last_update ? 
            new Date(stats.last_update).toLocaleTimeString() : 'Never';
        document.getElementById('active-connections').textContent = stats.active_connections || 0;
        
        // Update chart
        this.updateChart(stats);
    }

    updateChart(stats) {
        const now = new Date().toLocaleTimeString();
        
        // Keep only last 20 data points
        if (this.chartData.labels.length >= 20) {
            this.chartData.labels.shift();
            this.chartData.packets.shift();
            this.chartData.threats.shift();
        }
        
        this.chartData.labels.push(now);
        this.chartData.packets.push(stats.packets_analyzed || 0);
        this.chartData.threats.push(stats.threats_detected || 0);
        
        if (this.chart) {
            this.chart.update();
        }
    }

    setupChart() {
        const ctx = document.getElementById('networkChart').getContext('2d');
        
        this.chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.chartData.labels,
                datasets: [{
                    label: 'Packets Analyzed',
                    data: this.chartData.packets,
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'Threats Detected',
                    data: this.chartData.threats,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#fff'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#adb5bd'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#adb5bd'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                }
            }
        });
    }

    addThreatAlert(threat) {
        const threatFeed = document.getElementById('threat-feed');
        const alertDiv = document.createElement('div');
        alertDiv.className = `threat-item threat-severity-${threat.severity || 'medium'}`;
        
        const timeStr = new Date().toLocaleTimeString();
        
        alertDiv.innerHTML = `
            <div class="threat-header">
                <span class="threat-type">
                    <i class="fas fa-exclamation-triangle"></i>
                    ${threat.type || 'Security Alert'}
                </span>
                <span class="threat-time">${timeStr}</span>
            </div>
            <div class="threat-description">
                ${threat.description || 'No description available'}
            </div>
            <div class="threat-details">
                <small>
                    ${threat.source_ip ? `Source: ${threat.source_ip}` : ''}
                    ${threat.target_ip ? ` → Target: ${threat.target_ip}` : ''}
                    ${threat.port ? ` Port: ${threat.port}` : ''}
                </small>
            </div>
        `;
        
        // Remove placeholder if exists
        const placeholder = threatFeed.querySelector('.text-center');
        if (placeholder) {
            placeholder.remove();
        }
        
        // Add new threat at the top
        threatFeed.insertBefore(alertDiv, threatFeed.firstChild);
        
        // Keep only last 50 alerts
        while (threatFeed.children.length > 50) {
            threatFeed.removeChild(threatFeed.lastChild);
        }
        
        // Update threat summary
        this.updateThreatSummary();
    }

    updateThreatSummary() {
        const threatFeed = document.getElementById('threat-feed');
        const threatSummary = document.getElementById('threat-summary');
        const threats = threatFeed.querySelectorAll('.threat-item');
        
        if (threats.length === 0) {
            threatSummary.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-check-circle fa-2x mb-2"></i>
                    <p>No recent threats</p>
                </div>
            `;
            return;
        }
        
        // Count threats by severity
        const severityCounts = { high: 0, medium: 0, low: 0 };
        threats.forEach(threat => {
            if (threat.classList.contains('threat-severity-high')) severityCounts.high++;
            else if (threat.classList.contains('threat-severity-medium')) severityCounts.medium++;
            else if (threat.classList.contains('threat-severity-low')) severityCounts.low++;
        });
        
        threatSummary.innerHTML = `
            <div class="mb-2">
                <span class="badge bg-danger me-2">High: ${severityCounts.high}</span>
                <span class="badge bg-warning me-2">Medium: ${severityCounts.medium}</span>
                <span class="badge bg-success">Low: ${severityCounts.low}</span>
            </div>
            <small class="text-muted">Last 50 threats shown</small>
        `;
    }

    showThreatToast(threat) {
        const toast = document.getElementById('threat-toast');
        const toastMessage = document.getElementById('toast-message');
        
        toastMessage.innerHTML = `
            <strong>${threat.type || 'Security Alert'}</strong><br>
            ${threat.description || 'New threat detected'}
        `;
        
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
    }

    setupEventListeners() {
        // Monitor toggle button
        document.getElementById('monitor-toggle').addEventListener('click', () => {
            this.toggleMonitoring();
        });
        
        // Export data button
        document.getElementById('export-data').addEventListener('click', () => {
            this.exportData();
        });
        
        // Clear alerts button
        document.getElementById('clear-alerts').addEventListener('click', () => {
            this.clearAlerts();
        });
        
        // Refresh config button
        document.getElementById('refresh-config').addEventListener('click', () => {
            this.refreshConfig();
        });
        
        // Send ping every 30 seconds to keep connection alive
        setInterval(() => {
            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                this.websocket.send(JSON.stringify({ type: 'ping' }));
            }
        }, 30000);
    }

    async toggleMonitoring() {
        const button = document.getElementById('monitor-toggle');
        const interface = document.getElementById('interface-input').value;
        
        try {
            if (this.isMonitoring) {
                const response = await fetch('/api/monitoring/stop', { method: 'POST' });
                const result = await response.json();
                
                if (response.ok) {
                    this.isMonitoring = false;
                    this.updateMonitoringStatus();
                }
            } else {
                const response = await fetch('/api/monitoring/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ interface })
                });
                const result = await response.json();
                
                if (response.ok) {
                    this.isMonitoring = true;
                    this.updateMonitoringStatus();
                }
            }
        } catch (error) {
            console.error('Error toggling monitoring:', error);
            this.showNotification('Error controlling monitoring', 'danger');
        }
    }

    updateMonitoringStatus() {
        const button = document.getElementById('monitor-toggle');
        const statusText = document.getElementById('status-text');
        
        if (this.isMonitoring) {
            button.innerHTML = '<i class="fas fa-stop"></i> Stop';
            button.className = 'btn btn-danger';
            statusText.textContent = 'Monitoring';
        } else {
            button.innerHTML = '<i class="fas fa-play"></i> Start';
            button.className = 'btn btn-success';
            statusText.textContent = 'Stopped';
        }
    }

    async exportData() {
        try {
            const response = await fetch('/api/threats?limit=1000');
            const data = await response.json();
            
            const blob = new Blob([JSON.stringify(data, null, 2)], {
                type: 'application/json'
            });
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `threats_export_${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            this.showNotification('Data exported successfully', 'success');
        } catch (error) {
            console.error('Export error:', error);
            this.showNotification('Error exporting data', 'danger');
        }
    }

    clearAlerts() {
        const threatFeed = document.getElementById('threat-feed');
        threatFeed.innerHTML = `
            <div class="text-center p-4 text-muted">
                <i class="fas fa-shield-alt fa-3x mb-3"></i>
                <p>No threats detected. System is secure.</p>
            </div>
        `;
        this.updateThreatSummary();
        this.showNotification('Alerts cleared', 'info');
    }

    async refreshConfig() {
        try {
            const response = await fetch('/api/config');
            const config = await response.json();
            
            this.showNotification('Configuration refreshed', 'success');
        } catch (error) {
            console.error('Config refresh error:', error);
            this.showNotification('Error refreshing configuration', 'danger');
        }
    }

    async loadInitialData() {
        try {
            // Load initial stats
            const statsResponse = await fetch('/api/stats');
            const stats = await statsResponse.json();
            this.updateStats(stats);
            
            // Load recent threats
            const threatsResponse = await fetch('/api/threats?limit=10');
            const threatsData = await threatsResponse.json();
            
            if (threatsData.threats && threatsData.threats.length > 0) {
                threatsData.threats.reverse().forEach(threat => {
                    this.addThreatAlert(threat);
                });
            }
        } catch (error) {
            console.error('Error loading initial data:', error);
        }
    }

    showNotification(message, type = 'info') {
        // Create a temporary toast for notifications
        const toastContainer = document.querySelector('.toast-container');
        const toastId = 'toast-' + Date.now();
        
        const toastHTML = `
            <div id="${toastId}" class="toast align-items-center text-white bg-${type} border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">${message}</div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `;
        
        toastContainer.insertAdjacentHTML('beforeend', toastHTML);
        const toast = document.getElementById(toastId);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        // Remove toast element after it's hidden
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    }

    formatUptime(uptime) {
        if (!uptime) return '00:00:00';
        
        // Simple format for uptime display
        const parts = uptime.split(':');
        if (parts.length >= 3) {
            return `${parts[0]}:${parts[1]}:${parts[2].split('.')[0]}`;
        }
        return uptime;
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new ThreatAnalyzerDashboard();
});