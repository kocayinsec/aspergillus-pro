#!/usr/bin/env python3
"""
Aspergillus Pro - Network Monitoring Dashboard
Run script for easy startup
"""
import sys
import os
import webbrowser
import time
import subprocess

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Kill any existing servers
subprocess.run(["pkill", "-f", "uvicorn"], capture_output=True)
time.sleep(1)

print("🛡️  Aspergillus Pro - Network Monitoring Dashboard")
print("=" * 60)

# Import and run the web server
try:
    from src.web_server import run_server
    
    # Start in a thread so we can open browser
    import threading
    
    def start_server():
        run_server(host="127.0.0.1", port=8000)
    
    # Start server in background thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    print("🚀 Starting server...")
    time.sleep(3)
    
    # Open browser
    print("🌐 Opening dashboard in browser...")
    webbrowser.open("http://127.0.0.1:8000")
    
    print("\n✅ Dashboard is running at: http://127.0.0.1:8000")
    print("Press Ctrl+C to stop\n")
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping server...")
        sys.exit(0)
        
except ImportError:
    print("❌ FastAPI dependencies not found.")
    print("📥 Installing requirements...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    print("✅ Installation complete. Please run the script again.")
except Exception as e:
    print(f"❌ Error starting server: {e}")
    print("💡 Try running the standalone dashboard.html file instead")
    
    # Fallback to opening standalone HTML
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if os.path.exists(dashboard_path):
        print("🌐 Opening standalone dashboard...")
        webbrowser.open(f"file://{dashboard_path}")
    else:
        print("❌ dashboard.html not found")