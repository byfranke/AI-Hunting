# AI-Hunting Dashboard

<div align="center">

```
     █████╗ ██╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
    ██╔══██╗██║      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝
    ███████║██║█████╗███████║██║   ██║██╔██╗ ██║   ██║
    ██╔══██║██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║
    ██║  ██║██║      ██║  ██║╚██████╔╝██║ ╚████║   ██║
    ╚═╝  ╚═╝╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
```

**Enterprise Threat Hunting Web Application**

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/byfranke/AI-Hunting)
[![Python](https://img.shields.io/badge/python-3.9+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

[Features](#features) | [Installation](#installation) | [Usage](#usage) | [API Reference](#api-reference)

</div>

---

## Overview

AI-Hunting Dashboard is an enterprise-grade threat hunting and incident response platform. It provides a modern web interface for automated security forensics, malware detection, and comprehensive reporting.

The dashboard integrates with:
- **VirusTotal API** - Malware reputation checking
- **LOLBAS Project** - Living Off The Land Binaries detection
- **Windows Event Logs** - Security event analysis
- **Registry Analysis** - Persistence mechanism detection

## Features

### Security Analysis
- Windows Services enumeration and analysis
- SHA256 hash computation for service binaries
- VirusTotal integration for malware detection
- LOLBAS pattern detection
- Registry startup entry analysis
- Scheduled tasks enumeration
- Driver enumeration
- Security event log analysis

### Dashboard
- Modern, responsive web interface with dark theme
- Real-time scan progress via WebSocket
- Interactive data tables with search and filtering
- Threat distribution visualization
- Export results to JSON
- Scan history tracking

### Architecture
- **Backend**: Python FastAPI with async support
- **Frontend**: Vanilla HTML5, CSS3, JavaScript
- **Data Collection**: PowerShell modules
- **Communication**: WebSocket for real-time updates
- **API**: RESTful endpoints with OpenAPI documentation

## Installation

### Prerequisites

- Python 3.9 or higher
- Windows 10/11 (for full functionality)
- Administrator privileges (for service enumeration)
- VirusTotal API key (optional, for VT integration)

### Quick Start (Windows)

1. **Clone the repository**
```powershell
git clone https://github.com/byfranke/AI-Hunting.git
cd AI-Hunting
```

2. **Run the setup script**
```powershell
.\setup.ps1
```

This will:
- Check Python installation
- Create a virtual environment
- Install dependencies
- Start the dashboard

3. **Access the dashboard**
```
http://127.0.0.1:8080
```

### Manual Installation

1. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment (optional)**
```bash
cp .env.example .env
# Edit .env with your settings
```

4. **Start the server**
```bash
python start.py
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Server bind address | 127.0.0.1 |
| `--port` | Server port | 8080 |
| `--debug` | Enable debug mode | false |
| `--no-browser` | Don't open browser | false |

Example:
```bash
python start.py --host 0.0.0.0 --port 9000 --debug
```

## Usage

### Starting a Scan

1. Navigate to the **Dashboard** or **Scanner** section
2. Configure scan options (VirusTotal, Registry, Tasks, etc.)
3. Click **Start Scan**
4. Monitor progress in real-time
5. Review results in the **Results** section

### Configuring VirusTotal

1. Go to **Settings**
2. Enter your VirusTotal API key
3. Click **Save API Key**

Get your API key from: https://www.virustotal.com/gui/my-apikey

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+S` | Start quick scan |
| `Escape` | Close modal |

## API Reference

The dashboard exposes a RESTful API. Full documentation available at `/docs` when running.

### Endpoints

#### System
- `GET /api/status` - System status
- `GET /api/config` - Configuration

#### Scanning
- `POST /api/scan/start` - Start new scan
- `GET /api/scan/status` - Current scan status
- `POST /api/scan/cancel` - Cancel scan
- `GET /api/scan/history` - Scan history

#### VirusTotal
- `POST /api/virustotal/check` - Check single hash
- `POST /api/config/virustotal` - Set API key

#### LOLBAS
- `GET /api/lolbas/status` - Database status
- `POST /api/lolbas/reload` - Reload database
- `GET /api/lolbas/search` - Search database

### WebSocket

Connect to `/ws` for real-time updates:

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log(data);
};

// Start scan
ws.send(JSON.stringify({
    type: 'start_scan',
    options: {
        check_virustotal: true,
        check_registry: true
    }
}));
```

## Project Structure

```
AI-Hunting/
├── app/
│   ├── api/
│   │   ├── routes.py       # API endpoints
│   │   └── websocket.py    # WebSocket handlers
│   ├── core/
│   │   ├── config.py       # Configuration
│   │   └── scanner.py      # Scanner orchestration
│   ├── services/
│   │   ├── virustotal.py   # VT integration
│   │   └── lolbas.py       # LOLBAS detection
│   ├── static/
│   │   ├── css/style.css   # Styles
│   │   ├── js/app.js       # JavaScript
│   │   └── index.html      # Dashboard
│   └── main.py             # FastAPI application
├── scripts/
│   └── collector.ps1       # PowerShell collector
├── modules/
│   └── ai-hunting.ps1      # Legacy PowerShell module
├── data/                   # Scan data storage
├── logs/                   # Application logs
├── requirements.txt        # Python dependencies
├── setup.ps1              # PowerShell setup
├── setup.bat              # Windows batch setup
├── start.py               # Application launcher
└── README.md              # Documentation
```

## Detection Capabilities

### VirusTotal Integration
- SHA256 hash reputation checking
- Classification: CLEAN, SUSPICIOUS, CRITICAL
- Detection count from 90+ antivirus engines
- Result caching to minimize API calls

### LOLBAS Detection
- Detection of legitimate binaries used in attacks
- Includes: certutil, mshta, regsvr32, rundll32, etc.
- Regular database updates from LOLBAS project

### Registry Analysis
- Run keys (HKLM and HKCU)
- RunOnce keys
- WOW6432Node entries

### Event Analysis
- Service installation events (7045)
- Service configuration changes (7040)
- Process creation (4688)
- Service installation via Security log (4697)

## Legacy PowerShell Module

The original PowerShell-only version is still available in `modules/ai-hunting.ps1`. To use it directly:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File ".\modules\ai-hunting.ps1"
```

This generates Excel reports with:
- VirusTotal findings
- LOLBAS alerts
- Driver audit
- Recent services
- Startup registry entries
- Scheduled tasks
- Windows Event Log analysis

## Security Considerations

- Run with appropriate privileges for full functionality
- The dashboard binds to localhost by default
- API keys are stored in environment variables
- No sensitive data is transmitted to external services except VirusTotal hashes

## Contributing

Contributions are welcome. Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**byFranke**
- Website: [byfranke.com](https://byfranke.com)
- GitHub: [@byfranke](https://github.com/byfranke)
- Email: contact@byfranke.com

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for malware intelligence
- [LOLBAS Project](https://lolbas-project.github.io/) for attack pattern database
- [FastAPI](https://fastapi.tiangolo.com/) for the web framework

## Donation Support

This tool is maintained through community support. Help keep it active:

[![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://buy.byfranke.com/b/8wM03kb3u7THeIgaEE)

---

<div align="center">

**AI-Hunting Dashboard** - Enterprise Threat Hunting Made Simple

</div>
