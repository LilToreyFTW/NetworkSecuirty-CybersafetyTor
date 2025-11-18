using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using NetworkSecurityMonitor.Models;
using NetworkSecurityMonitor.Services;

namespace NetworkSecurityMonitor;

public partial class MainForm : Form
{
    private readonly NetworkMonitorService _networkMonitor;
    private readonly ThreatDetectionService _threatDetection;
    private readonly ActiveDefenseService _activeDefense;
    private readonly NetworkInfoService _networkInfo;

    // UI Controls
    private Label lblTitle;
    private Label lblStatus;
    private Label lblThreatsCount;
    private Label lblBlockedCount;
    private Label lblConnectionsCount;
    private Label lblLocalIP;
    private Label lblPublicIP;
    private ListView lvThreats;
    private TextBox txtLog;
    private System.Windows.Forms.Timer updateTimer;

    // System Tray Components
    private NotifyIcon? trayIcon;
    private ContextMenuStrip? trayMenu;
    private bool isMinimizedToTray = false;

    public MainForm(NetworkMonitorService networkMonitor, ThreatDetectionService threatDetection,
                     ActiveDefenseService activeDefense, NetworkInfoService networkInfo)
    {
        _networkMonitor = networkMonitor;
        _threatDetection = threatDetection;
        _activeDefense = activeDefense;
        _networkInfo = networkInfo;

        InitializeComponent();
        SetupEventHandlers();
        StartMonitoring();
    }

    private void InitializeComponent()
    {
        this.Text = "🛡️ Network Security Monitor - AI-Powered Threat Detection";
        this.Size = new Size(1200, 800);
        this.StartPosition = FormStartPosition.CenterScreen;
        this.BackColor = Color.FromArgb(10, 14, 39);
        this.ShowInTaskbar = true;
        this.WindowState = FormWindowState.Normal;

        // Title
        lblTitle = new Label
        {
            Text = "🛡️ Network Security Monitor",
            Font = new Font("Segoe UI", 18, FontStyle.Bold),
            ForeColor = Color.Cyan,
            Location = new Point(20, 20),
            Size = new Size(400, 40),
            BackColor = Color.Transparent
        };

        lblStatus = new Label
        {
            Text = "🔴 Initializing...",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.Orange,
            Location = new Point(20, 60),
            Size = new Size(300, 20),
            BackColor = Color.Transparent
        };

        // Statistics Panel
        var statsPanel = CreateStatsPanel();

        // Threats List
        lvThreats = new ListView
        {
            Location = new Point(20, 140),
            Size = new Size(560, 300),
            View = View.Details,
            BackColor = Color.FromArgb(20, 24, 49),
            ForeColor = Color.White,
            Font = new Font("Consolas", 9),
            GridLines = true,
            FullRowSelect = true
        };

        lvThreats.Columns.Add("IP Address", 120);
        lvThreats.Columns.Add("Country", 80);
        lvThreats.Columns.Add("Attack Type", 150);
        lvThreats.Columns.Add("Category", 100);
        lvThreats.Columns.Add("Severity", 70);
        lvThreats.Columns.Add("Risk", 60);

        // Log TextBox
        txtLog = new TextBox
        {
            Location = new Point(20, 460),
            Size = new Size(560, 280),
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = Color.FromArgb(20, 24, 49),
            ForeColor = Color.LightGray,
            Font = new Font("Consolas", 8),
            ReadOnly = true
        };

        // Info Panel
        var infoPanel = CreateInfoPanel();

        // Add controls
        this.Controls.AddRange(new Control[] {
            lblTitle, lblStatus, statsPanel, lvThreats, txtLog, infoPanel
        });

        // Initialize System Tray
        InitializeTrayIcon();

        // Update timer
        updateTimer = new System.Windows.Forms.Timer { Interval = 1000 }; // Update every second
        updateTimer.Tick += UpdateTimer_Tick;
        updateTimer.Start();

        // Handle form events
        this.Resize += MainForm_Resize;
        this.FormClosing += MainForm_FormClosing;
    }

    private Panel CreateStatsPanel()
    {
        var panel = new Panel
        {
            Location = new Point(600, 20),
            Size = new Size(560, 100),
            BackColor = Color.FromArgb(20, 24, 49),
            BorderStyle = BorderStyle.FixedSingle
        };

        lblThreatsCount = new Label
        {
            Text = "Active Threats: 0",
            Font = new Font("Segoe UI", 12, FontStyle.Bold),
            ForeColor = Color.Red,
            Location = new Point(20, 10),
            Size = new Size(250, 25),
            BackColor = Color.Transparent
        };

        lblBlockedCount = new Label
        {
            Text = "IPs Blocked: 0",
            Font = new Font("Segoe UI", 12, FontStyle.Bold),
            ForeColor = Color.Yellow,
            Location = new Point(20, 35),
            Size = new Size(250, 25),
            BackColor = Color.Transparent
        };

        lblConnectionsCount = new Label
        {
            Text = "Active Connections: 0",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.Cyan,
            Location = new Point(20, 60),
            Size = new Size(250, 20),
            BackColor = Color.Transparent
        };

        panel.Controls.AddRange(new Control[] { lblThreatsCount, lblBlockedCount, lblConnectionsCount });
        return panel;
    }

    private Panel CreateInfoPanel()
    {
        var panel = new Panel
        {
            Location = new Point(600, 140),
            Size = new Size(560, 600),
            BackColor = Color.FromArgb(20, 24, 49),
            BorderStyle = BorderStyle.FixedSingle
        };

        var lblInfo = new Label
        {
            Text = "🔍 System Information:",
            Font = new Font("Segoe UI", 11, FontStyle.Bold),
            ForeColor = Color.White,
            Location = new Point(20, 20),
            Size = new Size(200, 25),
            BackColor = Color.Transparent
        };

        var lblLocalIP = new Label
        {
            Text = "Configured Local IP: Loading...",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.LightGray,
            Location = new Point(20, 50),
            Size = new Size(520, 40),
            BackColor = Color.Transparent
        };

        var lblPublicIP = new Label
        {
            Text = "Configured Public IP: Loading...",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.LightGray,
            Location = new Point(20, 90),
            Size = new Size(250, 20),
            BackColor = Color.Transparent
        };

        var lblMonitoring = new Label
        {
            Text = "🔴 Monitoring: EXTERNAL IPs only\n   (local network traffic filtered)",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.Orange,
            Location = new Point(20, 120),
            Size = new Size(520, 40),
            BackColor = Color.Transparent
        };

        var lblActiveDefense = new Label
        {
            Text = "🛡️ Active Defense:\n   Attackers automatically blocked\n   Redirected to 999.222.215.9",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.Green,
            Location = new Point(20, 170),
            Size = new Size(520, 60),
            BackColor = Color.Transparent
        };

        var lblHoneypot = new Label
        {
            Text = "🍯 Honeypot: Active on common ports\n   Trapping attackers automatically",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.Magenta,
            Location = new Point(20, 240),
            Size = new Size(520, 40),
            BackColor = Color.Transparent
        };

        panel.Controls.AddRange(new Control[] {
            lblInfo, lblLocalIP, lblPublicIP, lblMonitoring, lblActiveDefense, lblHoneypot
        });

        // Store references for updates
        this.lblLocalIP = lblLocalIP;
        this.lblPublicIP = lblPublicIP;

        return panel;
    }

    /// <summary>
    /// Initialize the system tray icon and context menu
    /// </summary>
    private void InitializeTrayIcon()
    {
        // Create context menu for tray icon
        trayMenu = new ContextMenuStrip();

        // Open Window menu item
        var openItem = new ToolStripMenuItem("Open Window");
        openItem.Click += (s, e) => ShowFromTray();
        trayMenu.Items.Add(openItem);

        // Separator
        trayMenu.Items.Add(new ToolStripSeparator());

        // About menu item
        var aboutItem = new ToolStripMenuItem("About");
        aboutItem.Click += (s, e) => ShowAboutDialog();
        trayMenu.Items.Add(aboutItem);

        // Git Auto Updater menu item (placeholder for future)
        var updaterItem = new ToolStripMenuItem(".gitautoupdater");
        updaterItem.Enabled = false; // Disabled until GitHub integration
        updaterItem.ToolTipText = "GitHub Auto Updater (Coming Soon)";
        trayMenu.Items.Add(updaterItem);

        // Separator
        trayMenu.Items.Add(new ToolStripSeparator());

        // Exit menu item
        var exitItem = new ToolStripMenuItem("Exit");
        exitItem.Click += (s, e) => ExitApplication();
        trayMenu.Items.Add(exitItem);

        // Create tray icon
        trayIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield, // Use Windows shield icon for security
            ContextMenuStrip = trayMenu,
            Text = "Network Security Monitor - Double-click or right-click to open",
            Visible = false // Will be shown when minimized
        };

        // Handle double-click on tray icon
        trayIcon.DoubleClick += (s, e) => ShowFromTray();

        // Show balloon tip when minimized
        trayIcon.BalloonTipTitle = "Network Security Monitor";
        trayIcon.BalloonTipText = "Application minimized to system tray. Right-click for options.";
        trayIcon.BalloonTipIcon = ToolTipIcon.Info;
    }

    /// <summary>
    /// Show the form from system tray
    /// </summary>
    private void ShowFromTray()
    {
        this.Show();
        this.WindowState = FormWindowState.Normal;
        this.ShowInTaskbar = true;
        trayIcon.Visible = false;
        isMinimizedToTray = false;
        this.Activate(); // Bring to front
    }

    /// <summary>
    /// Show about dialog
    /// </summary>
    private void ShowAboutDialog()
    {
        var aboutForm = new Form
        {
            Text = "About Network Security Monitor",
            Size = new Size(400, 300),
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false
        };

        var lblTitle = new Label
        {
            Text = "🛡️ Network Security Monitor",
            Font = new Font("Segoe UI", 14, FontStyle.Bold),
            Location = new Point(20, 20),
            Size = new Size(350, 30),
            TextAlign = ContentAlignment.MiddleCenter
        };

        var lblVersion = new Label
        {
            Text = "Enterprise Edition v2.0",
            Font = new Font("Segoe UI", 10),
            Location = new Point(20, 60),
            Size = new Size(350, 20),
            TextAlign = ContentAlignment.MiddleCenter
        };

        var lblDescription = new Label
        {
            Text = "Professional AI-Powered Threat Detection System\n\n" +
                   "Features:\n" +
                   "• Enterprise Threat Intelligence\n" +
                   "• Advanced Network Forensics\n" +
                   "• Professional Incident Response\n" +
                   "• SIEM-Style Event Correlation\n" +
                   "• Real-time Security Monitoring",
            Font = new Font("Segoe UI", 9),
            Location = new Point(20, 90),
            Size = new Size(350, 120),
            TextAlign = ContentAlignment.TopLeft
        };

        var lblCopyright = new Label
        {
            Text = "© 2025 Network Security Monitor\n" +
                   "Built with 45+ years of cybersecurity expertise",
            Font = new Font("Segoe UI", 8),
            Location = new Point(20, 220),
            Size = new Size(350, 30),
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.Gray
        };

        var btnOK = new Button
        {
            Text = "OK",
            Location = new Point(150, 260),
            Size = new Size(100, 30),
            DialogResult = DialogResult.OK
        };

        aboutForm.Controls.AddRange(new Control[] { lblTitle, lblVersion, lblDescription, lblCopyright, btnOK });
        aboutForm.AcceptButton = btnOK;

        aboutForm.ShowDialog();
    }

    /// <summary>
    /// Exit the application
    /// </summary>
    private void ExitApplication()
    {
        if (MessageBox.Show("Are you sure you want to exit Network Security Monitor?",
                           "Confirm Exit",
                           MessageBoxButtons.YesNo,
                           MessageBoxIcon.Question) == DialogResult.Yes)
        {
            trayIcon.Visible = false;
            Application.Exit();
        }
    }

    /// <summary>
    /// Handle form resize (minimize to tray)
    /// </summary>
    private void MainForm_Resize(object sender, EventArgs e)
    {
        if (this.WindowState == FormWindowState.Minimized)
        {
            if (!isMinimizedToTray)
            {
                // First time minimizing - hide from taskbar and show tray icon
                this.Hide();
                trayIcon.Visible = true;
                trayIcon.ShowBalloonTip(3000);
                isMinimizedToTray = true;
            }
        }
    }

    /// <summary>
    /// Handle form closing
    /// </summary>
    private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing && !isMinimizedToTray)
        {
            // User clicked X - minimize to tray instead of closing
            e.Cancel = true;
            this.WindowState = FormWindowState.Minimized;
            return;
        }

        // Clean up tray icon
        if (trayIcon != null)
        {
            trayIcon.Visible = false;
            trayIcon.Dispose();
        }
    }

    private void SetupEventHandlers()
    {
        _threatDetection.ThreatDetected += OnThreatDetected;
    }

    private void StartMonitoring()
    {
        Task.Run(async () =>
        {
            try
            {
                // Get network info
                var localIPs = _networkInfo.GetLocalIPAddresses();
                var publicIP = await _networkInfo.GetPublicIPAddressAsync();

                Invoke(() =>
                {
                    lblLocalIP.Text = $"Configured Local IP: {_networkInfo.GetConfiguredLocalIP()}";
                    lblPublicIP.Text = $"Configured Public IP: {_networkInfo.GetConfiguredPublicIP()}";
                    lblStatus.Text = "🟢 Monitoring Active";
                    lblStatus.ForeColor = Color.Green;
                });

                LogMessage($"[INFO] Network Security Monitor started");
                LogMessage($"[INFO] Local IPs: {string.Join(", ", localIPs)}");
                LogMessage($"[INFO] Public IP: {publicIP ?? "Unknown"}");
                LogMessage($"[INFO] Monitoring EXTERNAL IPs only (local network filtered)");
                LogMessage($"[INFO] Active defense enabled - attackers will be blocked automatically");
            }
            catch (Exception ex)
            {
                Invoke(() =>
                {
                    lblStatus.Text = "🔴 Error initializing";
                    lblStatus.ForeColor = Color.Red;
                });
                LogMessage($"[ERROR] Failed to initialize: {ex.Message}");
            }
        });
    }

    private void UpdateTimer_Tick(object? sender, EventArgs e)
    {
        try
        {
            var threats = _threatDetection.GetAllThreats();
            var blockedIPs = _activeDefense.GetBlockedIPs();
            var connections = _networkMonitor.GetActiveConnections();

            // Update statistics
            lblThreatsCount.Text = $"Active Threats: {threats.Count}";
            lblBlockedCount.Text = $"IPs Blocked: {blockedIPs.Count}";
            lblConnectionsCount.Text = $"Active Connections: {connections.Count}";

            // Update threats list
            lvThreats.Items.Clear();
            foreach (var threat in threats.OrderByDescending(t => t.LastDetected).Take(50))
            {
                var item = new ListViewItem(threat.IPAddress);
                item.SubItems.Add(threat.Country);
                item.SubItems.Add(threat.AttackType.Replace("🚨 EXTERNAL ATTACK: ", "").Replace("?? EXTERNAL ATTACK: ", ""));
                item.SubItems.Add(threat.ThreatCategory);
                item.SubItems.Add(threat.Severity.ToString());
                item.SubItems.Add($"{threat.RiskScore}%");

                // Color based on severity and malicious status
                if (threat.IsKnownMalicious)
                {
                    item.ForeColor = Color.Red;
                    item.Font = new Font(lvThreats.Font, FontStyle.Bold);
                }
                else
                {
                    item.ForeColor = threat.Severity switch
                    {
                        ThreatSeverity.Critical => Color.Red,
                        ThreatSeverity.High => Color.Orange,
                        ThreatSeverity.Medium => Color.Yellow,
                        _ => Color.LightGray
                    };
                }

                lvThreats.Items.Add(item);
            }
        }
        catch (Exception ex)
        {
            LogMessage($"[ERROR] Update error: {ex.Message}");
        }
    }

    private void OnThreatDetected(object? sender, ThreatDetectedEventArgs e)
    {
        var activity = e.Activity;

        Invoke(() =>
        {
            var location = activity.Country != "Unknown" ? $" ({activity.Country})" : "";
            var malicious = activity.IsKnownMalicious ? " [MALICIOUS]" : "";
            LogMessage($"[🛡️ BLOCKED] {activity.IPAddress}{location}{malicious} - {activity.ThreatCategory}");
            LogMessage($"   Attack: {activity.AttackType.Replace("🚨 EXTERNAL ATTACK: ", "").Replace("?? EXTERNAL ATTACK: ", "")}");
            LogMessage($"   Severity: {activity.Severity} | Connections: {activity.ConnectionCount} | Risk: {activity.RiskScore}%");
            LogMessage($"   Forensic evidence collected and incident logged");
            LogMessage("");
        });
    }

    private void LogMessage(string message)
    {
        if (InvokeRequired)
        {
            Invoke(() => AddLogMessage(message));
        }
        else
        {
            AddLogMessage(message);
        }
    }

    private void AddLogMessage(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        txtLog.AppendText($"[{timestamp}] {message}\r\n");

        // Keep only last 1000 lines
        if (txtLog.Lines.Length > 1000)
        {
            var lines = txtLog.Lines.Skip(100).ToArray();
            txtLog.Lines = lines;
        }

        txtLog.SelectionStart = txtLog.Text.Length;
        txtLog.ScrollToCaret();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        updateTimer?.Stop();
        base.OnFormClosing(e);
    }
}
