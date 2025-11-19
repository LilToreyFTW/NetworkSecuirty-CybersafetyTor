using System;
using System.Threading.Tasks;
using System.Windows.Forms;
using NetworkSecurityMonitor.Services;

namespace NetworkSecurityMonitor;

static class Program
{
    [STAThread]
    static async Task Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        // STEP 1: EULA ACCEPTANCE - REQUIRED BEFORE ANYTHING ELSE
        using (var eulaForm = new EULAAcceptanceForm())
        {
            var result = eulaForm.ShowDialog();

            if (result != DialogResult.OK || !eulaForm.Accepted)
            {
                // User denied EULA or closed the form
                MessageBox.Show(
                    "Network Security Monitor requires EULA acceptance to continue.\n\n" +
                    "The application will now exit.",
                    "EULA Required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
                return;
            }

            if (eulaForm.RequestInfo)
            {
                // User requested more information, show contact details again
                MessageBox.Show(
                    "Contact Information:\n\n" +
                    "Developer: LilToreyFTW\n" +
                    "Repository: https://github.com/LilToreyFTW/NetworkSecuirty-CybersafetyTor.git\n\n" +
                    "Please review the EULA in the EULA folder.",
                    "Contact Information",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
        }

        // STEP 2: USER SETUP - IP CONFIGURATION
        // Initialize basic services for setup
        var networkInfo = new NetworkInfoService();
        var userSetup = new UserSetupService(networkInfo);

        // Check if user has configured their IPs
        if (!userSetup.IsUserConfigured())
        {
            // Show GUI setup wizard for new users
            using (var setupWizard = new UserSetupWizard(networkInfo))
            {
                var result = setupWizard.ShowDialog();
                if (result != DialogResult.OK)
                {
                    // User cancelled setup
                    MessageBox.Show(
                        "Setup was cancelled. Network Security Monitor requires proper configuration.\n\n" +
                        "The application will now exit.",
                        "Setup Required",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information
                    );
                    return;
                }

                var userConfig = setupWizard.Result;

                // Handle firewall configuration
                userConfig.FirewallConfigured = await userSetup.ConfigureFirewallAsync(userConfig);

                // Validate and save configuration
                if (userSetup.ValidateConfiguration(userConfig))
                {
                    userConfig.IsConfigured = true;
                    userSetup.SaveConfig(userConfig);

                    // Store config for services to use
                    UserConfiguration.LocalIP = userConfig.LocalIP;
                    UserConfiguration.PublicIP = userConfig.PublicIP;
                }
                else
                {
                    MessageBox.Show(
                        "Configuration validation failed. Please restart the application and try again.",
                        "Configuration Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return;
                }
            }
        }
        else
        {
            // Load existing configuration
            var config = userSetup.LoadConfig();
            UserConfiguration.LocalIP = config.LocalIP;
            UserConfiguration.PublicIP = config.PublicIP;
        }

        // STEP 3: MAIN APPLICATION - SECURITY SERVICES
        // Initialize enterprise-grade security services
        var networkMonitor = new NetworkMonitorService();
        var aiAnalysis = new AIAnalysisService();
        var activeDefense = new ActiveDefenseService();

        // Professional threat intelligence with multiple feeds
        var threatIntelligence = new EnterpriseThreatIntelligence();

        // Advanced network forensics
        var networkForensics = new AdvancedNetworkForensics();

        // Professional incident response system
        var incidentResponseConfig = new IncidentResponseConfig
        {
            LogDirectory = "Logs",
            EvidenceDirectory = "Evidence",
            // Configure email notifications here
            NotificationEmail = "",
            SmtpServer = "",
            SmtpPort = 587,
            SmtpUseSsl = true
        };
        var incidentResponse = new ProfessionalIncidentResponse(incidentResponseConfig);

        // SIEM-like event correlation
        var eventCorrelation = new SecurityEventCorrelation();

        // Create threat detection service with all professional components
        var threatDetection = new ThreatDetectionService(networkMonitor, aiAnalysis, activeDefense, null);

        // Wire up professional services
        threatDetection.ThreatDetected += async (sender, e) =>
        {
            var activity = e.Activity;

            // Enhanced threat intelligence analysis
            var intelAnalysis = await threatIntelligence.AnalyzeIPAddressAsync(activity.IPAddress);
            activity.Country = intelAnalysis.Country;
            activity.Organization = intelAnalysis.Organization;
            activity.IsKnownMalicious = intelAnalysis.AbuseConfidenceScore > 50;

            // Advanced forensic analysis
            var forensicAnalysis = networkForensics.AnalyzeConnection(
                new System.Net.IPEndPoint(System.Net.IPAddress.Parse(activity.IPAddress), activity.Ports.FirstOrDefault()),
                new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0),
                System.Net.NetworkInformation.TcpState.Established);

            // Correlate security events
            eventCorrelation.IngestEvent(activity);

            // Professional incident response
            await incidentResponse.HandleThreatDetectionAsync(activity);
        };

        // Start background monitoring
        var backgroundService = new NetworkMonitoringBackgroundService(networkMonitor, threatDetection);

        // Start the background service
        Task.Run(() => backgroundService.StartAsync());

        // Create and run the professional GUI
        var mainForm = new MainForm(networkMonitor, threatDetection, activeDefense, networkInfo);
        Application.Run(mainForm);
    }
}

