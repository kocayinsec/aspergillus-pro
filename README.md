# 🛡️ Aspergillus Pro

**Advanced Network Traffic Monitoring & Analysis Platform**

A sophisticated cybersecurity dashboard with real-time network monitoring capabilities, featuring an elegant dark theme with green-purple-black color scheme.

![Platform](https://img.shields.io/badge/Platform-Web-brightgreen)
![Status](https://img.shields.io/badge/Status-Active-success)
![Version](https://img.shields.io/badge/Version-2.1-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ Features

### 🎨 **Premium UI/UX**
- **Modern Design Language** - Apple-inspired minimalist interface
- **Glassmorphism Effects** - Backdrop blur and transparency
- **Animated Backgrounds** - Subtle gradient animations
- **Responsive Design** - Works on all devices
- **Dark Theme** - Green-purple-black color scheme

### 🔍 **Network Monitoring**
- **Real-time Traffic Analysis** - Live HTTP request monitoring
- **Dynamic Statistics** - Request counts, response times, data transfer
- **Method Tracking** - GET, POST, PUT, DELETE requests
- **Status Code Analysis** - Success/error rate monitoring
- **IP & User Agent Tracking** - Detailed request information

### ⚡ **Interactive Features**
- **User Input Controls** - Custom domain and port configuration
- **Live Data Streams** - Real-time request visualization
- **Threat Level Indicators** - Dynamic security assessment
- **Data Export** - Clear logs and reset functionality
- **Smooth Animations** - Fluid transitions and hover effects

## 🚀 Quick Start

### Option 1: Standalone Dashboard (Recommended)
```bash
# Clone the repository
git clone https://github.com/kocayinsec/aspergillus-pro.git
cd aspergillus-pro

# Open the dashboard
open dashboard.html
```

### Option 2: Full Backend Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
python run_dashboard.py

# Access at http://localhost:8000
```

### Option 3: Docker Deployment
```bash
# Build and run with Docker
./docker-run.sh en0 up

# Access at http://localhost:8000
```

## 📁 Project Structure

```
aspergillus-pro/
├── dashboard.html              # Main standalone dashboard
├── src/
│   ├── web_server.py          # FastAPI backend server
│   ├── threat_detector.py     # Security analysis engine
│   ├── packet_analyzer.py     # Network packet analysis
│   └── config_manager.py      # Configuration management
├── templates/
│   └── dashboard.html         # Backend dashboard template
├── static/
│   ├── css/
│   │   └── dashboard.css      # Dashboard styles
│   └── js/
│       └── dashboard.js       # Dashboard functionality
├── docker-compose.yml         # Docker deployment
├── Dockerfile                 # Container configuration
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🎯 Usage

### 1. **Basic Monitoring**
- Enter target domain/IP in the input field
- Set the port number (default: 8080)
- Click "Başlat" (Start) to begin monitoring
- View real-time traffic in the live feed

### 2. **Statistics Tracking**
- **Total Requests** - Count of all monitored requests
- **Active Sessions** - Current monitoring sessions
- **Data Transfer** - Amount of data processed
- **Threat Level** - Dynamic security assessment

### 3. **Interactive Controls**
- **Start/Stop** monitoring
- **Clear logs** to reset data
- **Real-time status** indicators
- **Responsive controls** for mobile devices

## 🛠️ Technical Details

### Frontend Technologies
- **HTML5** with semantic markup
- **CSS3** with advanced animations
- **Vanilla JavaScript** for interactivity
- **CSS Grid & Flexbox** for layout
- **Custom scrollbars** and hover effects

### Backend Technologies (Optional)
- **FastAPI** - Modern Python web framework
- **WebSockets** - Real-time communication
- **Scapy** - Network packet analysis
- **SQLite** - Data storage
- **Docker** - Containerization

### Browser Support
- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+

## 🎨 Design Philosophy

Aspergillus Pro follows a **"Simplicity is Everything"** design principle inspired by Apple's design language:

- **Minimal Interface** - Clean, uncluttered layouts
- **Purposeful Animations** - Smooth, meaningful transitions
- **Semantic Colors** - Green (success), Purple (premium), Black (elegance)
- **Typography** - Inter font family for readability
- **Spacing** - Generous whitespace for visual breathing room

## 🔒 Security Features

### Real-time Threat Detection
- **Port Scan Detection** - Identifies reconnaissance attempts
- **Brute Force Detection** - Monitors authentication attacks
- **Malware Communication** - Detects suspicious connections
- **Data Exfiltration** - Identifies unusual data transfers

### Security Best Practices
- **No external dependencies** in standalone version
- **Local storage only** - No data transmission
- **CSP headers** for XSS protection
- **Input validation** and sanitization

## 📊 Performance

### Optimization Features
- **Lazy loading** for large datasets
- **Efficient DOM manipulation** 
- **CSS animations** over JavaScript
- **Memory management** for long-running sessions
- **Responsive images** and assets

### Browser Performance
- **60 FPS animations** with CSS transforms
- **Minimal JavaScript** footprint
- **Optimized CSS** with vendor prefixes
- **Progressive enhancement** approach

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow the existing code style
- Add comments for complex functionality
- Test on multiple browsers
- Maintain responsive design
- Update documentation

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Acknowledgments

- **Design Inspiration** - Apple Human Interface Guidelines
- **Color Palette** - Cyberpunk and nature themes
- **Icons** - Font Awesome and custom SVGs
- **Fonts** - Inter and JetBrains Mono
- **Animations** - CSS3 and modern web standards

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/kocayinsec/aspergillus-pro/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/kocayinsec/aspergillus-pro/discussions)
- 📖 **Documentation**: [Wiki](https://github.com/kocayinsec/aspergillus-pro/wiki)

## 📈 Roadmap

### v2.2 (Next Release)
- [ ] Real backend integration
- [ ] Advanced filtering options
- [ ] Export functionality
- [ ] Multi-language support

### v3.0 (Future)
- [ ] Machine learning threat detection
- [ ] Cloud deployment options
- [ ] API integrations
- [ ] Advanced analytics

---

**⭐ If you found this project useful, please consider giving it a star!**

Made with ❤️ by [kocayinsec](https://github.com/kocayinsec)
