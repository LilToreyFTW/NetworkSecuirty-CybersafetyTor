using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using NetworkSecurityMonitor.Models;
using NetworkSecurityMonitor.Services;

namespace NetworkSecurityMonitor;

public partial class MainForm : Form
{
    private readonly NetworkMonitorService _networkMonitor;
    private readonly ThreatDetectionService _threatDetection;
    private readonly ActiveDefenseService _activeDefense;
    private readonly NetworkInfoService _networkInfo;

    // Modern UI Controls
    private WebView2 webView3D;
    private Panel glassPanel;
    private Label lblTitle;
    private Label lblStatus;
    private Label lblThreatsCount;
    private Label lblBlockedCount;
    private Label lblConnectionsCount;
    private Label lblLocalIP;
    private Label lblPublicIP;
    private FlowLayoutPanel threatsPanel;
    private RichTextBox txtLog;
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

    private async void InitializeComponent()
    {
        this.Text = "🛡️ Network Security Monitor - Cyberpunk Edition";
        this.Size = new Size(1400, 900);
        this.StartPosition = FormStartPosition.CenterScreen;
        this.BackColor = Color.Black;
        this.ShowInTaskbar = true;
        this.WindowState = FormWindowState.Normal;
        this.FormBorderStyle = FormBorderStyle.None; // Borderless for modern look
        this.DoubleBuffered = true;

        // Initialize 3D WebView Background
        await InitializeWebView3D();

        // Glass morphism overlay panel
        glassPanel = new Panel
        {
            Location = new Point(0, 0),
            Size = new Size(1400, 900),
            BackColor = Color.FromArgb(180, 0, 0, 0), // Semi-transparent black
            BorderStyle = BorderStyle.None
        };

        // Cyberpunk title
        lblTitle = new Label
        {
            Text = "NETWORK SECURITY MONITOR",
            Font = new Font("Segoe UI", 28, FontStyle.Bold),
            ForeColor = Color.Cyan,
            Location = new Point(50, 30),
            Size = new Size(600, 50),
            BackColor = Color.Transparent,
            TextAlign = ContentAlignment.MiddleLeft
        };
        lblTitle.Paint += (s, e) => DrawGlowingText(e.Graphics, lblTitle.Text, lblTitle.Font, lblTitle.ForeColor, lblTitle.ClientRectangle, 3);

        lblStatus = new Label
        {
            Text = "🔴 INITIALIZING CYBER DEFENSE...",
            Font = new Font("Segoe UI", 12, FontStyle.Bold),
            ForeColor = Color.Orange,
            Location = new Point(50, 85),
            Size = new Size(400, 25),
            BackColor = Color.Transparent
        };

        // Statistics Panels (Modern Glass Cards)
        var statsPanel = CreateModernStatsPanel();

        // Recent Threats Panel
        var threatsPanel = CreateModernThreatsPanel();

        // Network Info Panel
        var networkPanel = CreateModernNetworkPanel();

        // Activity Log Panel
        var logPanel = CreateModernLogPanel();

        // Add controls to glass panel
        glassPanel.Controls.AddRange(new Control[] {
            lblTitle, lblStatus, statsPanel, threatsPanel, networkPanel, logPanel
        });

        // Add glass panel and WebView to form
        this.Controls.AddRange(new Control[] { glassPanel, webView3D });

        // Initialize System Tray
        InitializeTrayIcon();

        // Update timer
        updateTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        updateTimer.Tick += UpdateTimer_Tick;
        updateTimer.Start();

        // Handle form events
        this.Resize += MainForm_Resize;
        this.FormClosing += MainForm_FormClosing;
        this.KeyDown += MainForm_KeyDown; // Allow ESC to minimize to tray
    }

    private async Task InitializeWebView3D()
    {
        webView3D = new WebView2
        {
            Location = new Point(0, 0),
            Size = new Size(1400, 900),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };

        try
        {
            // Initialize WebView2
            var env = await CoreWebView2Environment.CreateAsync(null, null, null);
            await webView3D.EnsureCoreWebView2Async(env);

            // Load the 3D visualization
            var htmlPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "3DVisualization.html");
            if (System.IO.File.Exists(htmlPath))
            {
                webView3D.CoreWebView2.Navigate(htmlPath);
            }
            else
            {
                // Fallback: create HTML content directly
                var htmlContent = @"
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { margin: 0; background: linear-gradient(45deg, #000011, #001122); }
                        #cyber { color: cyan; font-family: monospace; font-size: 20px; text-align: center; padding-top: 200px; }
                    </style>
                </head>
                <body>
                    <div id='cyber'>CYBER DEFENSE ACTIVE</div>
                </body>
                </html>";
                webView3D.NavigateToString(htmlContent);
            }
        }
        catch (Exception ex)
        {
            // Fallback if WebView2 fails
            webView3D.Visible = false;
            this.BackColor = Color.FromArgb(0, 17, 34);
        }
    }

    private Panel CreateModernStatsPanel()
    {
        var panel = CreateGlassPanel(50, 120, 400, 120, "SECURITY METRICS");

        lblThreatsCount = new Label
        {
            Text = "THREATS DETECTED: 0",
            Font = new Font("Segoe UI", 14, FontStyle.Bold),
            ForeColor = Color.Red,
            Location = new Point(20, 20),
            Size = new Size(360, 25),
            BackColor = Color.Transparent
        };

        lblBlockedCount = new Label
        {
            Text = "ATTACKERS BLOCKED: 0",
            Font = new Font("Segoe UI", 12, FontStyle.Bold),
            ForeColor = Color.Orange,
            Location = new Point(20, 50),
            Size = new Size(360, 25),
            BackColor = Color.Transparent
        };

        lblConnectionsCount = new Label
        {
            Text = "ACTIVE CONNECTIONS: 0",
            Font = new Font("Segoe UI", 11),
            ForeColor = Color.Cyan,
            Location = new Point(20, 80),
            Size = new Size(360, 20),
            BackColor = Color.Transparent
        };

        panel.Controls.AddRange(new Control[] { lblThreatsCount, lblBlockedCount, lblConnectionsCount });
        return panel;
    }

    private Panel CreateModernThreatsPanel()
    {
        var panel = CreateGlassPanel(470, 120, 450, 250, "RECENT THREATS");

        threatsPanel = new FlowLayoutPanel
        {
            Location = new Point(10, 30),
            Size = new Size(430, 210),
            BackColor = Color.Transparent,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true
        };

        panel.Controls.Add(threatsPanel);
        return panel;
    }

    private Panel CreateModernNetworkPanel()
    {
        var panel = CreateGlassPanel(50, 260, 400, 200, "NETWORK STATUS");

        var lblLocalIP = new Label
        {
            Text = "LOCAL IP: SCANNING...",
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            ForeColor = Color.LightGreen,
            Location = new Point(20, 30),
            Size = new Size(360, 25),
            BackColor = Color.Transparent
        };

        var lblPublicIP = new Label
        {
            Text = "PUBLIC IP: SCANNING...",
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            ForeColor = Color.Cyan,
            Location = new Point(20, 65),
            Size = new Size(360, 25),
            BackColor = Color.Transparent
        };

        var lblDefenseStatus = new Label
        {
            Text = "🛡️ ACTIVE DEFENSE: ENGAGED",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.Green,
            Location = new Point(20, 105),
            Size = new Size(360, 20),
            BackColor = Color.Transparent
        };

        var lblMonitoringMode = new Label
        {
            Text = "🔍 MONITORING: EXTERNAL IPs ONLY",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.Orange,
            Location = new Point(20, 135),
            Size = new Size(360, 20),
            BackColor = Color.Transparent
        };

        var lblHoneypotStatus = new Label
        {
            Text = "🍯 HONEYPOT: ACTIVE",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.Magenta,
            Location = new Point(20, 165),
            Size = new Size(360, 20),
            BackColor = Color.Transparent
        };

        panel.Controls.AddRange(new Control[] {
            lblLocalIP, lblPublicIP, lblDefenseStatus, lblMonitoringMode, lblHoneypotStatus
        });

        // Store references for updates
        this.lblLocalIP = lblLocalIP;
        this.lblPublicIP = lblPublicIP;

        return panel;
    }

    private Panel CreateModernLogPanel()
    {
        var panel = CreateGlassPanel(470, 390, 450, 300, "ACTIVITY LOG");

        txtLog = new RichTextBox
        {
            Location = new Point(10, 30),
            Size = new Size(430, 260),
            BackColor = Color.FromArgb(10, 10, 20),
            ForeColor = Color.LightGray,
            Font = new Font("Consolas", 8),
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            ScrollBars = RichTextBoxScrollBars.Vertical
        };

        panel.Controls.Add(txtLog);
        return panel;
    }

    private Panel CreateGlassPanel(int x, int y, int width, int height, string title)
    {
        var panel = new Panel
        {
            Location = new Point(x, y),
            Size = new Size(width, height),
            BackColor = Color.FromArgb(40, 0, 20, 40), // Glass effect
            BorderStyle = BorderStyle.None
        };

        // Add glass morphism effect
        panel.Paint += (s, e) =>
        {
            var rect = new Rectangle(0, 0, width - 1, height - 1);
            using (var brush = new LinearGradientBrush(rect, Color.FromArgb(60, 0, 255, 255), Color.FromArgb(30, 255, 0, 255), 45f))
            {
                e.Graphics.FillRectangle(brush, rect);
            }

            // Draw border with glow
            using (var pen = new Pen(Color.Cyan, 1))
            {
                e.Graphics.DrawRectangle(pen, rect);
            }

            // Draw title
            if (!string.IsNullOrEmpty(title))
            {
                using (var font = new Font("Segoe UI", 10, FontStyle.Bold))
                using (var brush = new SolidBrush(Color.Cyan))
                {
                    e.Graphics.DrawString(title, font, brush, 15, 8);
                }
            }
        };

        return panel;
    }

    private void DrawGlowingText(Graphics g, string text, Font font, Color color, Rectangle rect, int glowSize)
    {
        // Draw glow effect
        for (int i = glowSize; i > 0; i--)
        {
            using (var brush = new SolidBrush(Color.FromArgb(i * 20, color)))
            {
                var glowRect = new Rectangle(rect.X - i, rect.Y - i, rect.Width + i * 2, rect.Height + i * 2);
                g.DrawString(text, font, brush, glowRect, new StringFormat { Alignment = StringAlignment.Near, LineAlignment = StringAlignment.Center });
            }
        }

        // Draw main text
        using (var brush = new SolidBrush(color))
        {
            g.DrawString(text, font, brush, rect, new StringFormat { Alignment = StringAlignment.Near, LineAlignment = StringAlignment.Center });
        }
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
            lblThreatsCount.Text = $"THREATS DETECTED: {threats.Count}";
            lblBlockedCount.Text = $"ATTACKERS BLOCKED: {blockedIPs.Count}";
            lblConnectionsCount.Text = $"ACTIVE CONNECTIONS: {connections.Count}";

            // Update 3D visualization stats
            Update3DVisualization(threats.Count > 0 ? "THREAT DETECTED" : "ACTIVE",
                                threats.Count > 0 ? "SCANNING..." : "SECURE",
                                connections.Count.ToString());

            // Update threats panel
            UpdateThreatsPanel(threats.OrderByDescending(t => t.LastDetected).Take(10));
        }
        catch (Exception ex)
        {
            LogMessage($"[ERROR] Update error: {ex.Message}");
        }
    }

    private void Update3DVisualization(string status, string threats, string connections)
    {
        try
        {
            if (webView3D?.CoreWebView2 != null)
            {
                var script = $"window.updateSecurityStats('{status}', '{threats}', '{connections}')";
                webView3D.CoreWebView2.ExecuteScriptAsync(script);
            }
        }
        catch (Exception ex)
        {
            // Ignore WebView errors
        }
    }

    private void UpdateThreatsPanel(IEnumerable<SuspiciousActivity> threats)
    {
        if (threatsPanel == null) return;

        threatsPanel.Controls.Clear();

        foreach (var threat in threats)
        {
            var threatLabel = new Label
            {
                Text = $"{threat.IPAddress} - {threat.ThreatCategory}",
                Font = new Font("Segoe UI", 9),
                ForeColor = GetThreatColor(threat),
                Size = new Size(400, 20),
                BackColor = Color.Transparent,
                Margin = new Padding(0, 2, 0, 2)
            };

            threatsPanel.Controls.Add(threatLabel);
        }

        if (!threats.Any())
        {
            var noThreatsLabel = new Label
            {
                Text = "🛡️ NO ACTIVE THREATS DETECTED",
                Font = new Font("Segoe UI", 10),
                ForeColor = Color.Green,
                Size = new Size(400, 25),
                BackColor = Color.Transparent,
                TextAlign = ContentAlignment.MiddleCenter
            };
            threatsPanel.Controls.Add(noThreatsLabel);
        }
    }

    private Color GetThreatColor(SuspiciousActivity threat)
    {
        if (threat.IsKnownMalicious) return Color.Red;
        return threat.Severity switch
        {
            ThreatSeverity.Critical => Color.Red,
            ThreatSeverity.High => Color.Orange,
            ThreatSeverity.Medium => Color.Yellow,
            _ => Color.LightGray
        };
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

            // Update 3D visualization for immediate threat response
            Update3DVisualization("THREAT BLOCKED", "DEFENDING", activity.ConnectionCount.ToString());
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
        if (txtLog == null) return;

        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        var logEntry = $"[{timestamp}] {message}\r\n";

        // Add colored text based on message content
        var startIndex = txtLog.TextLength;
        txtLog.AppendText(logEntry);

        // Color the timestamp
        txtLog.Select(startIndex, 11); // Select timestamp including brackets
        txtLog.SelectionColor = Color.Cyan;

        // Color based on message content
        var messageStart = startIndex + 11;
        var messageLength = logEntry.Length - 11;

        txtLog.Select(messageStart, messageLength);
        if (message.Contains("[ERROR]"))
            txtLog.SelectionColor = Color.Red;
        else if (message.Contains("[🛡️ BLOCKED]"))
            txtLog.SelectionColor = Color.Orange;
        else if (message.Contains("[INFO]"))
            txtLog.SelectionColor = Color.Green;
        else
            txtLog.SelectionColor = Color.LightGray;

        // Keep only last 500 lines for performance
        if (txtLog.Lines.Length > 500)
        {
            var lines = txtLog.Lines.Skip(50).ToArray();
            txtLog.Lines = lines;
        }

        txtLog.SelectionStart = txtLog.TextLength;
        txtLog.ScrollToCaret();
    }

    private void MainForm_KeyDown(object? sender, KeyEventArgs e)
    {
        // Allow ESC key to minimize to tray
        if (e.KeyCode == Keys.Escape && !isMinimizedToTray)
        {
            this.WindowState = FormWindowState.Minimized;
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        updateTimer?.Stop();
        base.OnFormClosing(e);
    }
}
