# Network Security Monitor - User Setup Version

## 🎯 **For New Users - Interactive IP Configuration**

This version of the Network Security Monitor is designed specifically for **new users** who need guidance on configuring their IP addresses. Unlike the main version, this one will:

- **Teach you how to find your IPs** through interactive CMD tutorials
- **Guide you step-by-step** through the configuration process
- **Automatically detect** your network information
- **Save your settings** for future use

## 🚀 **Quick Start**

### Step 1: Run the Application
```batch
# Navigate to the user setup folder
cd NetworkSecurityMonitor-UserSetup

# Run the user setup version
run-user-setup.bat
```

### Step 2: First-Time Setup
When you run it for the first time, you'll see:
- **Educational guides** on how to find your IP addresses
- **Interactive prompts** to enter your local and public IPs
- **Automatic detection** attempts
- **Validation** of your entered IPs

### Step 3: Use the Security Monitor
After setup, you'll get:
- **Professional GUI** with real-time threat monitoring
- **System tray support** (minimize to tray)
- **Enterprise-grade security** features

## 📋 **IP Configuration Guide**

### Finding Your Local IP (Private/Internal)
Your local IP is used for communication within your home/office network.

**Method 1: Windows Command Prompt**
1. Press `Windows Key + R`
2. Type `cmd` and press Enter
3. Type: `ipconfig /all`
4. Look for "IPv4 Address" under your active network adapter
5. **Common formats**: `192.168.1.xxx`, `10.0.0.xxx`, `172.16.xxx.xxx`

**Method 2: Auto-Detection**
- The setup will attempt to detect your local IPs automatically
- Choose from the list or enter manually

### Finding Your Public IP (External/Internet)
Your public IP is what attackers see when targeting you from the internet.

**Method 1: Online Services**
- Visit: `https://whatismyipaddress.com`
- Visit: `https://icanhazip.com` (simplest)
- Visit: `https://www.google.com/search?q=what+is+my+ip`

**Method 2: Auto-Detection**
- The setup will attempt to detect your public IP automatically
- This requires internet connection

## 🔥 Firewall Configuration (REQUIRED)

**CRITICAL**: Windows Firewall MUST be properly configured for the program to work!

### During Setup
The setup wizard will guide you through firewall configuration with two options:

#### Option 1: Automatic Configuration (Recommended)
- AI automatically configures Windows Firewall
- Enables firewall for all network profiles
- Creates necessary rules for network monitoring
- Requires Administrator privileges

#### Option 2: Manual Configuration
- Step-by-step instructions provided
- Command-line and GUI methods included
- Detailed verification steps

### Manual Firewall Setup

**Using Windows Firewall GUI:**
1. Press `Win + R`, type `wf.msc`
2. Enable firewall for Domain/Private/Public profiles
3. Allow NetworkSecurityMonitor.exe through firewall
4. Verify firewall is active in system tray

**Using Command Line (Admin):**
```batch
netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="NetworkSecurityMonitor-Allow" dir=in action=allow program="%SystemRoot%\System32\NetworkSecurityMonitor.exe" enable=yes
```

### Why Firewall Configuration is Required
- Program needs to create outbound rules to block malicious IPs
- Firewall integration enables real-time threat blocking
- Prevents attackers from bypassing network defenses
- Required for enterprise-grade protection

## 🛡️ **Security Features**

Once configured, you get all the enterprise-grade features:

- **Real-time Network Monitoring** - 24/7 connection analysis
- **AI-Powered Threat Detection** - Advanced risk assessment
- **Automatic Firewall Protection** - Blocks malicious IPs
- **DDoS Attack Prevention** - Stops volumetric attacks
- **Port Scanning Detection** - Identifies reconnaissance
- **Professional Incident Response** - Automated handling
- **Multi-Source Threat Intelligence** - AbuseIPDB, VirusTotal, Shodan
- **System Tray Operation** - Background monitoring

## 📁 **File Structure**

```
NetworkSecurityMonitor-UserSetup/
├── Services/
│   ├── UserSetupService.cs      # Interactive IP setup guide
│   └── ... (other services)
├── UserConfiguration.cs         # Global config storage
├── Program.cs                   # Main entry with setup phase
├── MainForm.cs                  # Professional GUI
├── build-user-setup.bat         # Build script
├── run-user-setup.bat           # Run script
├── clean-user-setup.bat         # Clean script
└── README-UserSetup.md          # This file
```

## 🔧 **Building from Source**

```batch
# Build the application
build-user-setup.bat

# This creates: ..\dist-user-setup\NetworkSecurityMonitor.exe
```

## 🎓 **Educational Features**

The setup process teaches you:
- **Network fundamentals** (local vs public IPs)
- **Command line basics** (ipconfig, finding IPs)
- **Security concepts** (why different IP types matter)
- **Online safety** (where to find public IP safely)

## ⚙️ **Configuration Persistence**

Your IP configuration is saved in `UserConfig.json`:
```json
{
  "LocalIP": "YOUR_LOCAL_IP_HERE",
  "PublicIP": "YOUR_PUBLIC_IP_HERE",
  "FirewallConfigured": true,
  "IsConfigured": true,
  "LastConfigured": "2025-11-18T15:30:00"
}
```

## 🆘 **Troubleshooting**

### "Cannot detect public IP"
- Check your internet connection
- Try manual entry using online services
- Firewall might be blocking the detection

### "Firewall configuration failed"
- Run program as Administrator
- Check if Windows Firewall is disabled by third-party software
- Try manual configuration using the provided steps
- Verify User Account Control (UAC) settings

### "Program cannot block malicious IPs"
- Ensure firewall configuration was completed
- Check Windows Firewall is enabled in system tray
- Run program as Administrator
- Verify no third-party firewall is interfering

### "Setup won't complete"
- All three steps must be completed: IP config, firewall config, validation
- Run Command Prompt as Administrator for firewall setup
- Check that entered IPs are valid format
- Ensure internet connection for public IP detection

### "Invalid IP format"
- Local IPs: Must be private range (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- Public IPs: Must be external (not private ranges)

### "Setup runs every time"
- Delete `UserConfig.json` to force re-setup
- Check file permissions if it won't save

## 🔄 **Differences from Main Version**

| Feature | Main Version | User Setup Version |
|---------|-------------|-------------------|
| IP Configuration | Manual code edit | Interactive setup |
| User Guidance | None | Full tutorials |
| Auto-Detection | Basic | Advanced with choices |
| First Run Experience | Raw console | Educational wizard |
| Target User | Developer/Admin | End user |

## 📞 **Support**

This version is designed to be user-friendly. If you encounter issues:
1. Run the setup again (it will reuse existing config)
2. Check the CMD output for error messages
3. Verify your IP addresses are correct
4. Ensure you have administrator privileges

---

**Ready to secure your network? Run `run-user-setup.bat` and follow the interactive guide!** 🛡️⚡
