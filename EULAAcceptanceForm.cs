using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace NetworkSecurityMonitor
{
    public class EULAAcceptanceForm : Form
    {
        private TextBox txtEULA;
        private Button btnAccept;
        private Button btnDeny;
        private Button btnRequest;
        private Label lblTitle;
        private CheckBox chkAgree;

        public bool Accepted { get; private set; } = false;
        public bool RequestInfo { get; private set; } = false;

        public EULAAcceptanceForm()
        {
            InitializeComponent();
            LoadEULAContent();
        }

        private void InitializeComponent()
        {
            this.Text = "Network Security Monitor - End User License Agreement";
            this.Size = new Size(800, 600);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.BackColor = Color.FromArgb(20, 20, 30);
            this.ForeColor = Color.White;

            // Title Label
            lblTitle = new Label
            {
                Text = "📋 END USER LICENSE AGREEMENT",
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = Color.Cyan,
                Location = new Point(20, 10),
                Size = new Size(760, 30),
                TextAlign = ContentAlignment.MiddleCenter
            };

            // EULA Text Box
            txtEULA = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(30, 30, 40),
                ForeColor = Color.LightGray,
                Font = new Font("Consolas", 9),
                Location = new Point(20, 50),
                Size = new Size(750, 400),
                BorderStyle = BorderStyle.FixedSingle
            };

            // Agreement Checkbox
            chkAgree = new CheckBox
            {
                Text = "I have read and agree to the End User License Agreement",
                Font = new Font("Segoe UI", 10),
                ForeColor = Color.White,
                Location = new Point(20, 470),
                Size = new Size(400, 30),
                BackColor = Color.Transparent
            };

            // Accept Button
            btnAccept = new Button
            {
                Text = "✅ ACCEPT & CONTINUE",
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                BackColor = Color.FromArgb(0, 150, 0),
                ForeColor = Color.White,
                Location = new Point(450, 470),
                Size = new Size(150, 40),
                FlatStyle = FlatStyle.Flat,
                Enabled = false
            };
            btnAccept.FlatAppearance.BorderSize = 0;
            btnAccept.Click += BtnAccept_Click;

            // Request Button
            btnRequest = new Button
            {
                Text = "📧 REQUEST INFO",
                Font = new Font("Segoe UI", 10),
                BackColor = Color.FromArgb(100, 100, 200),
                ForeColor = Color.White,
                Location = new Point(610, 470),
                Size = new Size(150, 40),
                FlatStyle = FlatStyle.Flat
            };
            btnRequest.FlatAppearance.BorderSize = 0;
            btnRequest.Click += BtnRequest_Click;

            // Deny Button
            btnDeny = new Button
            {
                Text = "❌ DENY & EXIT",
                Font = new Font("Segoe UI", 10),
                BackColor = Color.FromArgb(150, 0, 0),
                ForeColor = Color.White,
                Location = new Point(450, 520),
                Size = new Size(310, 40),
                FlatStyle = FlatStyle.Flat
            };
            btnDeny.FlatAppearance.BorderSize = 0;
            btnDeny.Click += BtnDeny_Click;

            // Agreement checkbox event
            chkAgree.CheckedChanged += ChkAgree_CheckedChanged;

            this.Controls.AddRange(new Control[] {
                lblTitle, txtEULA, chkAgree, btnAccept, btnRequest, btnDeny
            });

            // Warning label
            var lblWarning = new Label
            {
                Text = "⚠️  You must accept the EULA to use Network Security Monitor",
                Font = new Font("Segoe UI", 9),
                ForeColor = Color.Yellow,
                Location = new Point(20, 520),
                Size = new Size(400, 20),
                BackColor = Color.Transparent
            };
            this.Controls.Add(lblWarning);
        }

        private void LoadEULAContent()
        {
            try
            {
                string eulaPath = Path.Combine("EULA", "End_User_License_Agreement.txt");
                if (File.Exists(eulaPath))
                {
                    txtEULA.Text = File.ReadAllText(eulaPath);
                }
                else
                {
                    txtEULA.Text = @"END USER LICENSE AGREEMENT

Network Security Monitor - User Setup Version

IMPORTANT: By using this software, you agree to the following terms:

1. LICENSE: Non-exclusive license for lawful cybersecurity use only
2. RESPONSIBILITIES: Legal authorization required, comply with laws
3. WARNINGS: Monitors network traffic, modifies firewall settings
4. LIABILITY: Software provided 'AS IS', maximum liability $100

Contact: LilToreyFTW
Repository: https://github.com/LilToreyFTW/NetworkSecuirty-CybersafetyTor.git

Full EULA should be in EULA/End_User_License_Agreement.txt";
                }
            }
            catch
            {
                txtEULA.Text = "Error loading EULA. Please ensure EULA files are present.";
            }
        }

        private void ChkAgree_CheckedChanged(object sender, EventArgs e)
        {
            btnAccept.Enabled = chkAgree.Checked;
        }

        private void BtnAccept_Click(object sender, EventArgs e)
        {
            if (chkAgree.Checked)
            {
                Accepted = true;
                this.DialogResult = DialogResult.OK;
                this.Close();
            }
        }

        private void BtnRequest_Click(object sender, EventArgs e)
        {
            RequestInfo = true;

            // Show contact information
            MessageBox.Show(
                "For questions about the EULA or Network Security Monitor:\n\n" +
                "Developer: LilToreyFTW\n" +
                "Repository: https://github.com/LilToreyFTW/NetworkSecuirty-CybersafetyTor.git\n\n" +
                "Please review the EULA carefully before accepting.",
                "Contact Information",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );
        }

        private void BtnDeny_Click(object sender, EventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to deny the EULA and exit?\n\n" +
                "You will not be able to use Network Security Monitor.",
                "Confirm Denial",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning
            );

            if (result == DialogResult.Yes)
            {
                Accepted = false;
                this.DialogResult = DialogResult.Cancel;
                this.Close();
            }
        }
    }
}
