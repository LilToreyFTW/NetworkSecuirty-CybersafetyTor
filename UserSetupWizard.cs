using System;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows.Forms;
using NetworkSecurityMonitor.Services;

namespace NetworkSecurityMonitor;

public partial class UserSetupWizard : Form
{
    private readonly NetworkInfoService _networkInfo;
    private UserConfig _config;
    private int _currentStep = 0;
    private readonly string[] _stepTitles = {
        "Welcome to Network Security Monitor",
        "Configure Your Local IP Address",
        "Configure Your Public IP Address",
        "Firewall Configuration",
        "Setup Complete!"
    };

    // UI Controls
    private Panel headerPanel;
    private Label lblTitle;
    private Label lblStepTitle;
    private Panel contentPanel;
    private Button btnBack;
    private Button btnNext;
    private Button btnFinish;
    private ProgressBar progressBar;

    // Step content controls
    private Label lblWelcomeText;
    private Label lblLocalIPInfo;
    private ComboBox cmbLocalIPs;
    private TextBox txtLocalIP;
    private Label lblPublicIPInfo;
    private TextBox txtPublicIP;
    private Button btnDetectPublicIP;
    private Label lblFirewallInfo;
    private RadioButton rbAutoFirewall;
    private RadioButton rbManualFirewall;
    private RichTextBox txtFirewallInstructions;
    private Label lblCompleteMessage;
    private Label lblOr;

    public UserConfig Result => _config;

    public UserSetupWizard(NetworkInfoService networkInfo)
    {
        _networkInfo = networkInfo;
        _config = new UserConfig();

        InitializeComponent();
        ShowStep(0);
    }

    private void InitializeComponent()
    {
        this.Text = "Network Security Monitor - Setup Wizard";
        this.Size = new Size(700, 600);
        this.StartPosition = FormStartPosition.CenterScreen;
        this.FormBorderStyle = FormBorderStyle.FixedDialog;
        this.MaximizeBox = false;
        this.MinimizeBox = false;
        this.BackColor = Color.FromArgb(10, 14, 39);

        // Header Panel
        headerPanel = new Panel
        {
            Location = new Point(0, 0),
            Size = new Size(700, 120),
            BackColor = Color.FromArgb(20, 24, 49)
        };

        lblTitle = new Label
        {
            Text = "🛡️ NETWORK SECURITY MONITOR",
            Font = new Font("Segoe UI", 18, FontStyle.Bold),
            ForeColor = Color.Cyan,
            Location = new Point(20, 20),
            Size = new Size(400, 30),
            BackColor = Color.Transparent
        };

        lblStepTitle = new Label
        {
            Text = "Setup Step",
            Font = new Font("Segoe UI", 12),
            ForeColor = Color.White,
            Location = new Point(20, 60),
            Size = new Size(400, 25),
            BackColor = Color.Transparent
        };

        progressBar = new ProgressBar
        {
            Location = new Point(20, 90),
            Size = new Size(400, 20),
            Style = ProgressBarStyle.Continuous,
            Value = 0,
            Maximum = 100
        };

        headerPanel.Controls.AddRange(new Control[] { lblTitle, lblStepTitle, progressBar });

        // Content Panel
        contentPanel = new Panel
        {
            Location = new Point(0, 120),
            Size = new Size(700, 400),
            BackColor = Color.FromArgb(10, 14, 39)
        };

        // Navigation Buttons
        btnBack = new Button
        {
            Text = "← Back",
            Location = new Point(200, 530),
            Size = new Size(100, 35),
            BackColor = Color.FromArgb(40, 44, 69),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Enabled = false
        };
        btnBack.FlatAppearance.BorderColor = Color.Cyan;
        btnBack.Click += BtnBack_Click;

        btnNext = new Button
        {
            Text = "Next →",
            Location = new Point(320, 530),
            Size = new Size(100, 35),
            BackColor = Color.Cyan,
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat
        };
        btnNext.FlatAppearance.BorderColor = Color.Cyan;
        btnNext.Click += BtnNext_Click;

        btnFinish = new Button
        {
            Text = "Finish Setup",
            Location = new Point(440, 530),
            Size = new Size(120, 35),
            BackColor = Color.LimeGreen,
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat,
            Visible = false
        };
        btnFinish.FlatAppearance.BorderColor = Color.LimeGreen;
        btnFinish.Click += BtnFinish_Click;

        // Add controls to form
        this.Controls.AddRange(new Control[] {
            headerPanel, contentPanel, btnBack, btnNext, btnFinish
        });

        InitializeStepControls();
    }

    private void InitializeStepControls()
    {
        // Welcome Step
        lblWelcomeText = new Label
        {
            Text = "Welcome to Network Security Monitor!\n\n" +
                   "This wizard will help you configure your system for optimal security monitoring.\n\n" +
                   "We'll guide you through:\n" +
                   "• Configuring your IP addresses for monitoring\n" +
                   "• Setting up Windows Firewall rules\n" +
                   "• Enabling enterprise-grade threat detection\n\n" +
                   "Click Next to begin the setup process.",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.White,
            Location = new Point(30, 30),
            Size = new Size(620, 200),
            BackColor = Color.Transparent
        };

        // Local IP Step
        lblLocalIPInfo = new Label
        {
            Text = "Configure Your Local IP Address\n\n" +
                   "This is your computer's private IP address on your home network.\n" +
                   "Usually starts with 192.168.x.x or 10.x.x.x\n\n" +
                   "Auto-detected addresses:",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.White,
            Location = new Point(30, 30),
            Size = new Size(620, 80),
            BackColor = Color.Transparent
        };

        cmbLocalIPs = new ComboBox
        {
            Location = new Point(30, 120),
            Size = new Size(300, 25),
            BackColor = Color.FromArgb(40, 44, 69),
            ForeColor = Color.White,
            DropDownStyle = ComboBoxStyle.DropDownList
        };

        lblOr = new Label
        {
            Text = "Or enter manually:",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.LightGray,
            Location = new Point(30, 160),
            Size = new Size(150, 20),
            BackColor = Color.Transparent
        };

        txtLocalIP = new TextBox
        {
            Location = new Point(30, 185),
            Size = new Size(200, 25),
            BackColor = Color.FromArgb(40, 44, 69),
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle
        };

        // Public IP Step
        lblPublicIPInfo = new Label
        {
            Text = "Configure Your Public IP Address\n\n" +
                   "This is your internet-facing IP address that attackers see.\n" +
                   "You can find this by visiting whatismyipaddress.com or similar sites.\n\n" +
                   "Enter your public IP address:",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.White,
            Location = new Point(30, 30),
            Size = new Size(620, 100),
            BackColor = Color.Transparent
        };

        txtPublicIP = new TextBox
        {
            Location = new Point(30, 140),
            Size = new Size(200, 25),
            BackColor = Color.FromArgb(40, 44, 69),
            ForeColor = Color.White,
            BorderStyle = BorderStyle.FixedSingle
        };

        btnDetectPublicIP = new Button
        {
            Text = "Auto-Detect Public IP",
            Location = new Point(250, 140),
            Size = new Size(150, 25),
            BackColor = Color.FromArgb(40, 44, 69),
            ForeColor = Color.Cyan,
            FlatStyle = FlatStyle.Flat
        };
        btnDetectPublicIP.FlatAppearance.BorderColor = Color.Cyan;
        btnDetectPublicIP.Click += BtnDetectPublicIP_Click;

        // Firewall Step
        lblFirewallInfo = new Label
        {
            Text = "Firewall Configuration (Required)\n\n" +
                   "Windows Firewall must be properly configured for Network Security Monitor to work.\n" +
                   "Choose your preferred setup method:",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.White,
            Location = new Point(30, 30),
            Size = new Size(620, 80),
            BackColor = Color.Transparent
        };

        rbAutoFirewall = new RadioButton
        {
            Text = "Automatic Setup (Recommended)",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.White,
            Location = new Point(50, 120),
            Size = new Size(250, 25),
            BackColor = Color.Transparent,
            Checked = true
        };

        rbManualFirewall = new RadioButton
        {
            Text = "Manual Setup (Advanced)",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.White,
            Location = new Point(50, 150),
            Size = new Size(250, 25),
            BackColor = Color.Transparent
        };

        txtFirewallInstructions = new RichTextBox
        {
            Location = new Point(30, 190),
            Size = new Size(620, 150),
            BackColor = Color.FromArgb(20, 24, 49),
            ForeColor = Color.LightGray,
            Font = new Font("Consolas", 9),
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            Text = "Automatic Setup Instructions:\n" +
                   "• The application will automatically configure Windows Firewall\n" +
                   "• Administrator privileges required\n" +
                   "• Creates necessary inbound/outbound rules\n\n" +
                   "Manual Setup Instructions:\n" +
                   "1. Open Windows Defender Firewall with Advanced Security\n" +
                   "2. Create new inbound rule for NetworkSecurityMonitor.exe\n" +
                   "3. Allow all ports and protocols\n" +
                   "4. Enable the rule for all network types\n" +
                   "5. Create outbound rules if needed"
        };

        // Complete Step
        lblCompleteMessage = new Label
        {
            Text = "🎉 Setup Complete!\n\n" +
                   "Your Network Security Monitor is now fully configured.\n\n" +
                   "Configuration Summary:\n" +
                   "• Local IP: [Loading...]\n" +
                   "• Public IP: [Loading...]\n" +
                   "• Firewall: [Loading...]\n\n" +
                   "Click 'Finish Setup' to start monitoring your network!",
            Font = new Font("Segoe UI", 11),
            ForeColor = Color.LimeGreen,
            Location = new Point(30, 30),
            Size = new Size(620, 300),
            BackColor = Color.Transparent
        };
    }

    private void ShowStep(int step)
    {
        _currentStep = step;
        contentPanel.Controls.Clear();

        lblStepTitle.Text = $"{_currentStep + 1}. {_stepTitles[_currentStep]}";
        progressBar.Value = (_currentStep + 1) * 20; // 20% per step (5 steps)

        btnBack.Enabled = _currentStep > 0;
        btnNext.Visible = _currentStep < 4;
        btnFinish.Visible = _currentStep == 4;

        switch (_currentStep)
        {
            case 0:
                contentPanel.Controls.Add(lblWelcomeText);
                break;
            case 1:
                SetupLocalIPStep();
                contentPanel.Controls.AddRange(new Control[] { lblLocalIPInfo, cmbLocalIPs, lblOr, txtLocalIP });
                break;
            case 2:
                contentPanel.Controls.AddRange(new Control[] { lblPublicIPInfo, txtPublicIP, btnDetectPublicIP });
                break;
            case 3:
                contentPanel.Controls.AddRange(new Control[] { lblFirewallInfo, rbAutoFirewall, rbManualFirewall, txtFirewallInstructions });
                break;
            case 4:
                UpdateCompleteStep();
                contentPanel.Controls.Add(lblCompleteMessage);
                break;
        }
    }

    private void SetupLocalIPStep()
    {
        cmbLocalIPs.Items.Clear();
        var localIPs = _networkInfo.GetLocalIPAddresses();
        foreach (var ip in localIPs)
        {
            cmbLocalIPs.Items.Add(ip);
        }
        if (cmbLocalIPs.Items.Count > 0)
        {
            cmbLocalIPs.SelectedIndex = 0;
        }
    }

    private async void BtnDetectPublicIP_Click(object? sender, EventArgs e)
    {
        btnDetectPublicIP.Enabled = false;
        btnDetectPublicIP.Text = "Detecting...";

        try
        {
            var publicIP = await _networkInfo.GetPublicIPAddressAsync();
            if (!string.IsNullOrEmpty(publicIP))
            {
                txtPublicIP.Text = publicIP;
                MessageBox.Show($"Public IP detected: {publicIP}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Could not detect public IP automatically. Please enter it manually.", "Detection Failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error detecting public IP: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            btnDetectPublicIP.Enabled = true;
            btnDetectPublicIP.Text = "Auto-Detect Public IP";
        }
    }

    private void BtnBack_Click(object? sender, EventArgs e)
    {
        if (_currentStep > 0)
        {
            ShowStep(_currentStep - 1);
        }
    }

    private void BtnNext_Click(object? sender, EventArgs e)
    {
        if (ValidateCurrentStep())
        {
            if (_currentStep < 4)
            {
                ShowStep(_currentStep + 1);
            }
        }
    }

    private void BtnFinish_Click(object? sender, EventArgs e)
    {
        this.DialogResult = DialogResult.OK;
        this.Close();
    }

    private bool ValidateCurrentStep()
    {
        switch (_currentStep)
        {
            case 1: // Local IP
                var localIP = cmbLocalIPs.SelectedItem?.ToString() ?? txtLocalIP.Text;
                if (string.IsNullOrWhiteSpace(localIP))
                {
                    MessageBox.Show("Please select or enter a local IP address.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
                _config.LocalIP = localIP;
                return true;

            case 2: // Public IP
                if (string.IsNullOrWhiteSpace(txtPublicIP.Text))
                {
                    MessageBox.Show("Please enter your public IP address.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
                _config.PublicIP = txtPublicIP.Text;
                return true;

            case 3: // Firewall
                _config.FirewallConfigured = true; // We'll handle this in the service
                return true;

            default:
                return true;
        }
    }

    private void UpdateCompleteStep()
    {
        // Handle firewall configuration choice
        if (rbAutoFirewall.Checked)
        {
            _config.FirewallConfigured = true; // Will be handled automatically later
        }
        else
        {
            // Show manual firewall instructions dialog
            var manualDialog = new Form
            {
                Text = "Manual Firewall Configuration Required",
                Size = new Size(600, 500),
                StartPosition = FormStartPosition.CenterScreen,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false,
                BackColor = Color.FromArgb(10, 14, 39)
            };

            var lblTitle = new Label
            {
                Text = "🔥 MANUAL FIREWALL CONFIGURATION REQUIRED",
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = Color.Orange,
                Location = new Point(20, 20),
                Size = new Size(550, 30),
                BackColor = Color.Transparent
            };

            var txtInstructions = new RichTextBox
            {
                Text = @"CRITICAL: You must manually configure Windows Firewall for Network Security Monitor to work!

WINDOWS DEFENDER FIREWALL CONFIGURATION STEPS:

1. Press Windows Key + R, type 'wf.msc', press Enter
2. In Windows Defender Firewall, click 'Inbound Rules' on the left
3. Click 'New Rule...' on the right
4. Select 'Port', click Next
5. Select 'TCP', 'Specific local ports', enter: 80,443,8080
6. Select 'Allow the connection', click Next
7. Check all three boxes (Domain/Private/Public), click Next
8. Name: 'NetworkSecurityMonitor-Allow'
9. Description: 'Allow Network Security Monitor inbound connections'
10. Click Finish

11. Repeat steps 3-10 for 'Outbound Rules' if needed

ALTERNATIVE - Command Line Method:
1. Open Command Prompt as Administrator
2. Run: netsh advfirewall firewall add rule name=""NetworkSecurityMonitor"" dir=in action=allow protocol=TCP localport=80,443,8080
3. Run: netsh advfirewall firewall add rule name=""NetworkSecurityMonitor-Out"" dir=out action=allow protocol=TCP localport=80,443,8080

IMPORTANT: Without proper firewall configuration, the security monitor cannot block malicious IPs or protect your network!

Click 'I Have Configured Firewall' only after completing these steps.",
                Font = new Font("Consolas", 9),
                ForeColor = Color.LightGray,
                BackColor = Color.FromArgb(20, 24, 49),
                Location = new Point(20, 60),
                Size = new Size(550, 300),
                ReadOnly = true,
                BorderStyle = BorderStyle.None
            };

            var btnConfigured = new Button
            {
                Text = "I Have Configured Firewall",
                Location = new Point(200, 430),
                Size = new Size(200, 35),
                BackColor = Color.LimeGreen,
                ForeColor = Color.Black,
                FlatStyle = FlatStyle.Flat,
                DialogResult = DialogResult.OK
            };
            btnConfigured.FlatAppearance.BorderColor = Color.LimeGreen;

            manualDialog.Controls.AddRange(new Control[] { lblTitle, txtInstructions, btnConfigured });

            var result = manualDialog.ShowDialog();
            if (result == DialogResult.OK)
            {
                _config.FirewallConfigured = true;
            }
            else
            {
                _config.FirewallConfigured = false;
                MessageBox.Show("Firewall configuration is required for the security monitor to work properly.", "Configuration Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        lblCompleteMessage.Text = $"🎉 Setup Complete!\n\n" +
            $"Your Network Security Monitor is now fully configured.\n\n" +
            $"Configuration Summary:\n" +
            $"• Local IP: {_config.LocalIP}\n" +
            $"• Public IP: {_config.PublicIP}\n" +
            $"• Firewall: {(rbAutoFirewall.Checked ? "Automatic Setup" : "Manual Setup")}\n\n" +
            $"Click 'Finish Setup' to start monitoring your network!";
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        // Draw cyberpunk border
        using (var pen = new Pen(Color.Cyan, 2))
        {
            e.Graphics.DrawRectangle(pen, 0, 0, this.Width - 1, this.Height - 1);
        }
    }
}
