import asyncio
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

from .threat_detector import ThreatDetectionEngine
from .packet_analyzer import PacketAnalyzer
from .config_manager import ConfigManager
from .database import ThreatDatabase
from .api_integrations import ThreatIntelligenceAggregator


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.logger = logging.getLogger(__name__)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.logger.info(f"WebSocket connection established. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        self.logger.info(f"WebSocket connection closed. Active connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            self.logger.error(f"Error sending WebSocket message: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        if not self.active_connections:
            return
        
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                self.logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(connection)
        
        # Remove disconnected clients
        for conn in disconnected:
            self.disconnect(conn)


class ThreatAnalyzerAPI:
    def __init__(self, config_path: str = "configs/config.yaml"):
        self.app = FastAPI(
            title="Network Threat Analyzer API",
            description="Real-time network security monitoring and threat detection",
            version="1.0.0"
        )
        
        # Initialize managers
        self.connection_manager = ConnectionManager()
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load_config()
        
        # Initialize components
        try:
            self.database = ThreatDatabase()
        except Exception as e:
            self.logger.warning(f"Database initialization failed: {e}")
            self.database = None
            
        self.threat_detector = ThreatDetectionEngine(self.config)
        self.packet_analyzer = None
        self.threat_intel = ThreatIntelligenceAggregator(self.config)
        
        # Monitoring state
        self.is_monitoring = False
        self.monitoring_task = None
        self.stats = {
            "packets_analyzed": 0,
            "threats_detected": 0,
            "last_update": None,
            "uptime_start": datetime.now(),
            "active_threats": []
        }
        
        # Setup templates and static files
        templates_dir = Path(__file__).parent.parent / "templates"
        static_dir = Path(__file__).parent.parent / "static"
        
        # Ensure directories exist
        templates_dir.mkdir(exist_ok=True)
        static_dir.mkdir(exist_ok=True)
        
        self.templates = Jinja2Templates(directory=str(templates_dir))
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Setup routes
        self._setup_routes()

    def _setup_routes(self):
        # Static files
        static_dir = Path(__file__).parent.parent / "static"
        self.app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
        
        # Web routes
        self.app.get("/", response_class=HTMLResponse)(self.dashboard_page)
        self.app.get("/api/status")(self.get_status)
        self.app.get("/api/stats")(self.get_stats)
        self.app.get("/api/threats")(self.get_threats)
        self.app.get("/api/threats/{threat_id}")(self.get_threat_detail)
        self.app.post("/api/monitoring/start")(self.start_monitoring)
        self.app.post("/api/monitoring/stop")(self.stop_monitoring)
        self.app.get("/api/config")(self.get_config)
        self.app.post("/api/config")(self.update_config)
        self.app.websocket("/ws")(self.websocket_endpoint)

    async def dashboard_page(self, request: Request):
        return self.templates.TemplateResponse("dashboard.html", {
            "request": request,
            "title": "Network Threat Analyzer Dashboard"
        })

    async def get_status(self):
        return {
            "status": "monitoring" if self.is_monitoring else "stopped",
            "uptime": str(datetime.now() - self.stats["uptime_start"]),
            "monitoring": self.is_monitoring,
            "active_connections": len(self.connection_manager.active_connections)
        }

    async def get_stats(self):
        return {
            **self.stats,
            "uptime": str(datetime.now() - self.stats["uptime_start"]),
            "active_connections": len(self.connection_manager.active_connections)
        }

    async def get_threats(self, limit: int = 100, severity: Optional[str] = None):
        try:
            if self.database:
                threats = self.database.get_recent_threats(limit=limit)
                if severity:
                    threats = [t for t in threats if t.get('severity', '').lower() == severity.lower()]
                return {"threats": threats, "count": len(threats)}
            else:
                return {"threats": [], "count": 0}
        except Exception as e:
            self.logger.error(f"Error fetching threats: {e}")
            raise HTTPException(status_code=500, detail="Error fetching threats")

    async def get_threat_detail(self, threat_id: str):
        try:
            if self.database:
                threat = self.database.get_threat_by_id(threat_id)
                if not threat:
                    raise HTTPException(status_code=404, detail="Threat not found")
                return threat
            else:
                raise HTTPException(status_code=404, detail="Database not available")
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error fetching threat detail: {e}")
            raise HTTPException(status_code=500, detail="Error fetching threat detail")

    async def start_monitoring(self, interface: Optional[str] = None):
        if self.is_monitoring:
            return {"status": "already_monitoring", "message": "Monitoring is already active"}
        
        try:
            interface = interface or self.config.get('monitoring', {}).get('interface', 'en0')
            self.packet_analyzer = PacketAnalyzer(interface=interface)
            
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            self.is_monitoring = True
            
            await self.connection_manager.broadcast(json.dumps({
                "type": "monitoring_started",
                "interface": interface,
                "timestamp": datetime.now().isoformat()
            }))
            
            return {"status": "started", "interface": interface}
        except Exception as e:
            self.logger.error(f"Error starting monitoring: {e}")
            raise HTTPException(status_code=500, detail=f"Error starting monitoring: {str(e)}")

    async def stop_monitoring(self):
        if not self.is_monitoring:
            return {"status": "not_monitoring", "message": "Monitoring is not active"}
        
        self.is_monitoring = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
        
        await self.connection_manager.broadcast(json.dumps({
            "type": "monitoring_stopped",
            "timestamp": datetime.now().isoformat()
        }))
        
        return {"status": "stopped"}

    async def get_config(self):
        return self.config

    async def update_config(self, config_data: dict):
        try:
            self.config_manager.update_config(config_data)
            self.config = self.config_manager.load_config()
            return {"status": "updated", "config": self.config}
        except Exception as e:
            self.logger.error(f"Error updating config: {e}")
            raise HTTPException(status_code=500, detail=f"Error updating config: {str(e)}")

    async def websocket_endpoint(self, websocket: WebSocket):
        await self.connection_manager.connect(websocket)
        try:
            # Send initial status
            await websocket.send_text(json.dumps({
                "type": "connection_established",
                "stats": await self.get_stats(),
                "timestamp": datetime.now().isoformat()
            }))
            
            while True:
                # Keep connection alive and handle client messages
                data = await websocket.receive_text()
                message = json.loads(data)
                
                if message.get("type") == "ping":
                    await websocket.send_text(json.dumps({
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    }))
                
        except WebSocketDisconnect:
            self.connection_manager.disconnect(websocket)
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
            self.connection_manager.disconnect(websocket)

    async def _monitoring_loop(self):
        try:
            while self.is_monitoring:
                # Capture and analyze packets
                packets = await self._capture_packets(count=10)
                
                for packet_data in packets:
                    # Analyze packet for threats
                    threats = await self.threat_detector.analyze_packet(packet_data)
                    
                    self.stats["packets_analyzed"] += 1
                    
                    for threat in threats:
                        self.stats["threats_detected"] += 1
                        self.stats["active_threats"].append(threat)
                        
                        # Store in database
                        if self.database:
                            self.database.store_threat(threat)
                        
                        # Enrich with threat intelligence
                        enrichment = await self.threat_intel.enrich_threat_alert(
                            source_ip=threat.get('source_ip'),
                            target_ip=threat.get('target_ip')
                        )
                        threat['intelligence'] = enrichment
                        
                        # Broadcast threat alert
                        await self.connection_manager.broadcast(json.dumps({
                            "type": "threat_alert",
                            "threat": threat,
                            "timestamp": datetime.now().isoformat()
                        }))
                
                # Update stats and broadcast
                self.stats["last_update"] = datetime.now().isoformat()
                await self.connection_manager.broadcast(json.dumps({
                    "type": "stats_update",
                    "stats": self.stats,
                    "timestamp": datetime.now().isoformat()
                }))
                
                # Clean old active threats (keep last 50)
                if len(self.stats["active_threats"]) > 50:
                    self.stats["active_threats"] = self.stats["active_threats"][-50:]
                
                await asyncio.sleep(1)  # 1-second monitoring interval
                
        except asyncio.CancelledError:
            self.logger.info("Monitoring task cancelled")
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}")
            self.is_monitoring = False

    async def _capture_packets(self, count: int = 10) -> List[Dict[str, Any]]:
        if not self.packet_analyzer:
            return []
        
        try:
            # This would integrate with the existing packet capture logic
            # For now, return mock data to demonstrate the API
            return []
        except Exception as e:
            self.logger.error(f"Error capturing packets: {e}")
            return []


def create_app(config_path: str = "configs/config.yaml") -> FastAPI:
    api = ThreatAnalyzerAPI(config_path)
    return api.app


def run_server(host: str = "0.0.0.0", port: int = 8000, config_path: str = "configs/config.yaml"):
    app = create_app(config_path)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Threat Analyzer Web Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--config", default="configs/config.yaml", help="Config file path")
    
    args = parser.parse_args()
    
    run_server(host=args.host, port=args.port, config_path=args.config)