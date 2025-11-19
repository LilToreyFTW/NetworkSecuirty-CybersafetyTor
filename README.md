# 🛡️ Network Security Monitor - AI-Powered Threat Detection System

A comprehensive network security monitoring system that detects and alerts you about suspicious IP addresses attempting to attack your network. Built with C# backend and TypeScript/React frontend.

## Features

- **Real-time Network Monitoring**: Continuously monitors all active network connections
- **AI-Powered Threat Detection**: Uses pattern recognition to identify DDoS attacks, port scanning, and brute force attempts
- **Threat Analysis**: Provides risk scores, confidence levels, and AI-generated recommendations
- **Live Dashboard**: Beautiful web interface showing all detected threats in real-time
- **IP Tracking**: Identifies and logs all suspicious IP addresses
- **Automatic Alerts**: Browser notifications when new threats are detected

## Attack Detection Capabilities

The system detects:
- **DDoS Attacks**: Rapid connection attempts from single or multiple IPs
- **Port Scanning**: Systematic scanning of multiple ports
- **Brute Force**: Repeated connection attempts to the same port
- **Suspicious Patterns**: Unusual connection rates and behaviors

## Requirements

- **.NET 8.0 SDK** or later
- **Node.js 18+** and npm
- **Windows 10/11** (for the executable) or Linux/Mac (for development)

## Quick Start

### Option 1: Build from Source

1. **Clone or download this repository**

2. **Build the project:**
   ```powershell
   # Windows
   .\build.ps1
   
   # Linux/Mac
   chmod +x build.sh
   ./build.sh
   ```

3. **Run the executable:**
   ```powershell
   # Windows
   .\dist\NetworkSecurityMonitor.exe
   
   # Linux/Mac
   ./dist/NetworkSecurityMonitor
   ```

4. **Open your browser:**
   - Navigate to `http://localhost:3000` (if frontend is built)
   - Or access the backend API at `http://localhost:5000`

### Option 2: Development Mode

1. **Start the C# backend:**
   ```bash
   cd NetworkSecurityMonitor
   dotnet run
   ```

2. **Start the frontend (in a new terminal):**
   ```bash
   cd Frontend
   npm install
   npm run dev
   ```

3. **Access the dashboard:**
   - Frontend: `http://localhost:3000`
   - Backend API: `http://localhost:5000`

## How It Works

1. **Network Monitoring**: The system continuously monitors all TCP connections on your machine
2. **Pattern Detection**: Analyzes connection patterns to identify suspicious behavior
3. **AI Analysis**: Uses machine learning-like algorithms to calculate risk scores and confidence levels
4. **Real-time Alerts**: Sends instant notifications when threats are detected
5. **Dashboard Display**: Shows all detected threats with detailed information

## Understanding the Dashboard

- **Statistics Cards**: Overview of total threats, critical threats, and unique IPs
- **Threat Cards**: Detailed information about each detected threat including:
  - IP Address (click to copy)
  - Attack Type
  - Severity Level (Low, Medium, High, Critical)
  - Risk Score (0-100%)
  - AI Confidence Level
  - Connection Statistics
  - Targeted Ports
  - AI Recommendations

## Threat Severity Levels

- **Critical**: Immediate action required - Block IP immediately
- **High**: Significant threat - Monitor closely and consider blocking
- **Medium**: Moderate threat - Keep monitoring
- **Low**: Minor suspicious activity - Log for review

## Security Notes

⚠️ **Important**: This tool requires administrator/root privileges to monitor network connections effectively.

⚠️ **Legal Notice**: This tool is for monitoring your own network security. Do not use it to attack or harass others. Unauthorized access to computer systems is illegal.

## Troubleshooting

### "Connection Failed" in Dashboard
- Make sure the backend is running on port 5000
- Check firewall settings
- Verify SignalR hub is accessible

### No Threats Detected
- This is normal if your network is secure
- The system only alerts on suspicious patterns
- Try generating some network activity to test

### Permission Errors
- Run as Administrator (Windows) or with sudo (Linux)
- Network monitoring requires elevated privileges

## Technical Details

### Backend (C#)
- .NET 8.0
- ASP.NET Core with SignalR for real-time communication
- System.Net.NetworkInformation for network monitoring
- AI-powered threat analysis algorithms

### Frontend (TypeScript/React)
- React 18
- TypeScript
- Vite for fast development
- SignalR client for real-time updates
- Modern, responsive UI

## License

This project is provided as-is for educational and personal security monitoring purposes.

## Support

For issues or questions, please review the code comments marked with `// ADDED:` for implementation details.

---

**Stay Secure! 🛡️**

