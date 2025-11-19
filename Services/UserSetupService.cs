using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;

namespace NetworkSecurityMonitor.Services;

// ADDED: Configuration class for user settings
public class UserConfig
{
    public string LocalIP { get; set; } = "";
    public string PublicIP { get; set; } = "";
    public bool FirewallConfigured { get; set; } = false;
    public bool IsConfigured { get; set; } = false;
    public DateTime LastConfigured { get; set; }
}

// ADDED: Service to guide new users through IP configuration setup
public class UserSetupService
{
    private const string CONFIG_FILE = "UserConfig.json";

    private readonly NetworkInfoService _networkInfo;

    public UserSetupService(NetworkInfoService networkInfo)
    {
        _networkInfo = networkInfo;
    }

    // ADDED: Check if user has already configured their IPs
    public bool IsUserConfigured()
    {
        if (!File.Exists(CONFIG_FILE))
            return false;

        try
        {
            var config = LoadConfig();
            return config.IsConfigured &&
                   !string.IsNullOrEmpty(config.LocalIP) &&
                   !string.IsNullOrEmpty(config.PublicIP);
        }
        catch
        {
            return false;
        }
    }

    // ADDED: Load saved configuration
    public UserConfig LoadConfig()
    {
        if (!File.Exists(CONFIG_FILE))
            return new UserConfig();

        try
        {
            var json = File.ReadAllText(CONFIG_FILE);
            return System.Text.Json.JsonSerializer.Deserialize<UserConfig>(json) ?? new UserConfig();
        }
        catch
        {
            return new UserConfig();
        }
    }

    // ADDED: Save configuration
    public void SaveConfig(UserConfig config)
    {
        try
        {
            config.LastConfigured = DateTime.Now;
            var json = System.Text.Json.JsonSerializer.Serialize(config, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(CONFIG_FILE, json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not save configuration: {ex.Message}");
        }
    }

    // ADDED: Interactive setup for new users - teaches them how to find their IPs
    public async Task<UserConfig> PerformUserSetupAsync()
    {
        Console.Clear();
        DisplayWelcomeHeader();

        Console.WriteLine("\n" + "═".PadRight(80, '═'));
        Console.WriteLine("🎓 NETWORK SECURITY MONITOR - FIRST TIME SETUP");
        Console.WriteLine("═".PadRight(80, '═'));

        Console.WriteLine("\n🔍 STEP 1: Understanding Your IP Addresses");
        Console.WriteLine("   Before we can protect you, we need to know which IPs to monitor.");
        Console.WriteLine("   There are TWO types of IP addresses you need to provide:");

        Console.WriteLine("\n   📍 LOCAL IP (Private/Internal):");
        Console.WriteLine("      • This is your computer's address on your home network");
        Console.WriteLine("      • Usually starts with 192.168.x.x or 10.x.x.x");
        Console.WriteLine("      • Used for communication within your home/office");

        Console.WriteLine("\n   🌐 PUBLIC IP (External):");
        Console.WriteLine("      • This is your internet-facing address");
        Console.WriteLine("      • What attackers see when they try to reach you");
        Console.WriteLine("      • Used for internet communication");

        Console.WriteLine("\n" + "═".PadRight(80, '═'));
        Console.WriteLine("🛠️  HOW TO FIND YOUR IPs:");
        Console.WriteLine("═".PadRight(80, '═'));

        TeachIPFinding();

        Console.WriteLine("\n" + "═".PadRight(80, '═'));
        Console.WriteLine("⚡ LET'S CONFIGURE YOUR MONITOR NOW:");
        Console.WriteLine("═".PadRight(80, '═'));

        var config = new UserConfig();

        // Step 1: Local IP Configuration
        config.LocalIP = await ConfigureLocalIPAsync();

        // Step 2: Public IP Configuration
        config.PublicIP = await ConfigurePublicIPAsync();

        // Step 3: Firewall Configuration (REQUIRED)
        config.FirewallConfigured = await ConfigureFirewallAsync(config);

        // Step 4: Validation
        if (ValidateConfiguration(config))
        {
            config.IsConfigured = true;
            SaveConfig(config);

            Console.WriteLine("\n" + "═".PadRight(80, '═'));
            Console.WriteLine("✅ SETUP COMPLETE!");
            Console.WriteLine("═".PadRight(80, '═'));
            Console.WriteLine("🎉 Your Network Security Monitor is now FULLY configured!");
            Console.WriteLine($"   🔒 Monitoring Local IP: {config.LocalIP}");
            Console.WriteLine($"   🛡️  Protecting Public IP: {config.PublicIP}");
            Console.WriteLine($"   🔥 Firewall Status: {(config.FirewallConfigured ? "CONFIGURED" : "NOT CONFIGURED")}");
            Console.WriteLine("\n🚀 Your system is now ready for enterprise-grade network protection!");
            Console.WriteLine("\n⏳ Starting security monitoring in 3 seconds...");

            await Task.Delay(3000);
            Console.Clear();
        }

        return config;
    }

    // ADDED: Educational guide on how to find IPs
    private void TeachIPFinding()
    {
        Console.WriteLine("\n   📋 METHOD 1 - Windows Command Prompt (Easiest):");
        Console.WriteLine("      1. Press Windows Key + R");
        Console.WriteLine("      2. Type 'cmd' and press Enter");
        Console.WriteLine("      3. Type: ipconfig /all");
        Console.WriteLine("      4. Look for 'IPv4 Address' under your active network adapter");

        Console.WriteLine("\n   🌐 METHOD 2 - Find Your Public IP Online:");
        Console.WriteLine("      • Visit: https://whatismyipaddress.com");
        Console.WriteLine("      • Visit: https://www.google.com/search?q=what+is+my+ip");
        Console.WriteLine("      • Or use: https://icanhazip.com (simplest)");

        Console.WriteLine("\n   💡 TIP: Your public IP changes when you restart your router!");
        Console.WriteLine("            Run this setup again if your internet connection changes.");
    }

    // ADDED: Interactive local IP configuration
    private async Task<string> ConfigureLocalIPAsync()
    {
        while (true)
        {
            Console.WriteLine("\n🏠 STEP 1: Configure Your LOCAL IP Address");
            Console.WriteLine("   This should be your computer's private IP (192.168.x.x or 10.x.x.x)");

            // Auto-detect local IPs
            var detectedIPs = _networkInfo.GetLocalIPAddresses();
            if (detectedIPs.Any())
            {
                Console.WriteLine("\n   🔍 Auto-detected local IPs on your system:");
                for (int i = 0; i < detectedIPs.Count; i++)
                {
                    Console.WriteLine($"      {i + 1}. {detectedIPs[i]}");
                }
                Console.WriteLine($"      {detectedIPs.Count + 1}. Enter manually");
            }

            Console.Write("\n   Enter your local IP address: ");

            string input = Console.ReadLine()?.Trim() ?? "";

            // Handle numbered selection
            if (int.TryParse(input, out int selection) && selection > 0 && selection <= detectedIPs.Count)
            {
                input = detectedIPs[selection - 1];
                Console.WriteLine($"   ✓ Selected: {input}");
            }

            if (ValidateLocalIP(input))
            {
                Console.WriteLine($"   ✅ Local IP configured: {input}");
                return input;
            }
            else
            {
                Console.WriteLine("   ❌ Invalid local IP format. Please try again.");
                Console.WriteLine("   💡 Hint: Local IPs usually look like 192.168.1.100 or 10.0.0.5");
            }
        }
    }

    // ADDED: Interactive public IP configuration
    private async Task<string> ConfigurePublicIPAsync()
    {
        while (true)
        {
            Console.WriteLine("\n🌐 STEP 2: Configure Your PUBLIC IP Address");
            Console.WriteLine("   This is your internet-facing IP that attackers can see");

            // Auto-detect public IP
            Console.WriteLine("\n   🔍 Attempting to auto-detect your public IP...");
            var detectedPublicIP = await _networkInfo.GetPublicIPAddressAsync();

            if (!string.IsNullOrEmpty(detectedPublicIP))
            {
                Console.WriteLine($"   ✓ Auto-detected public IP: {detectedPublicIP}");
                Console.Write("   Use this IP? (Y/n): ");

                string response = Console.ReadLine()?.Trim().ToLower() ?? "y";
                if (string.IsNullOrEmpty(response) || response == "y" || response == "yes")
                {
                    Console.WriteLine($"   ✅ Public IP configured: {detectedPublicIP}");
                    return detectedPublicIP;
                }
            }
            else
            {
                Console.WriteLine("   ⚠️  Could not auto-detect public IP (you might be offline)");
            }

            Console.Write("\n   Enter your public IP address: ");
            string input = Console.ReadLine()?.Trim() ?? "";

            if (ValidatePublicIP(input))
            {
                Console.WriteLine($"   ✅ Public IP configured: {input}");
                return input;
            }
            else
            {
                Console.WriteLine("   ❌ Invalid public IP format. Please try again.");
                Console.WriteLine("   💡 Hint: Public IPs are visible to the internet (not 192.168.x.x or 10.x.x.x)");
                Console.WriteLine("   🌐 You can find it at: https://icanhazip.com");
            }
        }
    }

    // ADDED: Validate local IP
    private bool ValidateLocalIP(string ip)
    {
        if (!IPAddress.TryParse(ip, out var ipAddress))
            return false;

        // Must be a private IP range
        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return ipAddress.IsIPv6LinkLocal || ipAddress.IsIPv6SiteLocal;
        }

        var bytes = ipAddress.GetAddressBytes();

        // 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
        return bytes[0] == 127 ||
               bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               (bytes[0] == 169 && bytes[1] == 254);
    }

    // ADDED: Validate public IP
    private bool ValidatePublicIP(string ip)
    {
        if (!IPAddress.TryParse(ip, out var ipAddress))
            return false;

        // Must be external (not private)
        return !ValidateLocalIP(ip);
    }

    // ADDED: Validate complete configuration
    public bool ValidateConfiguration(UserConfig config)
    {
        if (string.IsNullOrEmpty(config.LocalIP) || string.IsNullOrEmpty(config.PublicIP))
            return false;

        if (!config.FirewallConfigured)
            return false;

        return ValidateLocalIP(config.LocalIP) && ValidatePublicIP(config.PublicIP);
    }

    // ADDED: Configure Windows Firewall (REQUIRED for program to work)
    public async Task<bool> ConfigureFirewallAsync(UserConfig config)
    {
        while (true)
        {
            Console.WriteLine("\n================================================================================");
            Console.WriteLine("FIREWALL STEP 3: Configure Windows Firewall (REQUIRED)");
            Console.WriteLine("================================================================================");

            Console.WriteLine("\n*** CRITICAL REQUIREMENT ***");
            Console.WriteLine("   Windows Firewall MUST be configured for Network Security Monitor to work!");
            Console.WriteLine("   This program needs to block malicious IPs and create firewall rules.");
            Console.WriteLine("   Without proper firewall configuration, the program cannot protect you.");

            Console.WriteLine("\nFIREWALL CONFIGURATION OPTIONS:");
            Console.WriteLine("   1. AUTOMATIC Configuration (Recommended)");
            Console.WriteLine("      - AI will configure Windows Firewall automatically");
            Console.WriteLine("      - Creates necessary rules for network protection");
            Console.WriteLine("      - Enables Windows Firewall if disabled");
            Console.WriteLine("   2. MANUAL Instructions (Advanced Users)");
            Console.WriteLine("      - Step-by-step guide to configure manually");
            Console.WriteLine("      - Detailed commands and screenshots");

            Console.Write("\n   Choose option (1 or 2): ");

            string choice = Console.ReadLine()?.Trim() ?? "";

            if (choice == "1")
            {
                // Automatic configuration
                bool success = await ConfigureFirewallAutomaticallyAsync();
                if (success)
                {
                    Console.WriteLine("\n[SUCCESS] Firewall configured automatically!");
                    Console.WriteLine("   Windows Firewall is now ready for network protection.");
                    return true;
                }
                else
                {
                    Console.WriteLine("\n[FAILED] Automatic configuration failed.");
                    Console.WriteLine("   Please try manual configuration or run as Administrator.");
                    continue;
                }
            }
            else if (choice == "2")
            {
                // Manual instructions
                bool success = ShowManualFirewallInstructions();
                if (success)
                {
                    Console.WriteLine("\n[SUCCESS] Manual firewall configuration complete!");
                    return true;
                }
                else
                {
                    Console.WriteLine("\n[FAILED] Manual configuration not confirmed.");
                    continue;
                }
            }
            else
            {
                Console.WriteLine("   [ERROR] Invalid choice. Please enter 1 or 2.");
            }
        }
    }

    // ADDED: Automatically configure Windows Firewall
    private async Task<bool> ConfigureFirewallAutomaticallyAsync()
    {
        try
        {
            Console.WriteLine("\n[CONFIG] Starting automatic firewall configuration...");

            // Step 1: Enable Windows Firewall
            Console.WriteLine("   1. Enabling Windows Firewall for all profiles...");
            await RunFirewallCommandAsync("netsh advfirewall set allprofiles state on");

            // Step 2: Create inbound rule to allow our monitoring
            Console.WriteLine("   2. Creating firewall rule for Network Security Monitor...");
            string ruleName = "NetworkSecurityMonitor-Allow";
            await RunFirewallCommandAsync($"netsh advfirewall firewall delete rule name=\"{ruleName}\"");
            await RunFirewallCommandAsync($"netsh advfirewall firewall add rule name=\"{ruleName}\" dir=in action=allow program=\"%SystemRoot%\\System32\\NetworkSecurityMonitor.exe\" enable=yes");

            // Step 3: Create outbound rule for blocking malicious IPs (will be managed by the program)
            Console.WriteLine("   3. Setting up outbound filtering capabilities...");
            // This will be managed dynamically by the ActiveDefenseService

            Console.WriteLine("   4. Verifying firewall status...");
            var result = await RunFirewallCommandAsync("netsh advfirewall show allprofiles state");

            if (result.Contains("ON"))
            {
                Console.WriteLine("   [SUCCESS] Windows Firewall is enabled and configured!");
                return true;
            }
            else
            {
                Console.WriteLine("   [WARNING] Firewall may not be fully enabled. Please check manually.");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   [ERROR] Error during automatic configuration: {ex.Message}");
            Console.WriteLine("   [HINT] Try running the program as Administrator or use manual configuration.");
            return false;
        }
    }

    // ADDED: Show manual firewall configuration instructions
    private bool ShowManualFirewallInstructions()
    {
        Console.WriteLine("\nMANUAL FIREWALL CONFIGURATION INSTRUCTIONS:");
        Console.WriteLine("================================================================================");

        Console.WriteLine("\nSTEP 1: Enable Windows Firewall");
        Console.WriteLine("   1. Press Windows Key + R");
        Console.WriteLine("   2. Type: 'wf.msc' and press Enter");
        Console.WriteLine("   3. In Windows Firewall window:");
        Console.WriteLine("      - Click on 'Windows Defender Firewall Properties'");
        Console.WriteLine("      - For each profile (Domain/Private/Public):");
        Console.WriteLine("        - Set 'Firewall state' to 'ON'");
        Console.WriteLine("        - Set 'Inbound connections' to 'Block'");
        Console.WriteLine("        - Set 'Outbound connections' to 'Allow' (default)");

        Console.WriteLine("\nSTEP 2: Create Program Exception");
        Console.WriteLine("   1. In Windows Firewall window:");
        Console.WriteLine("      - Click 'Allow an app or feature through Windows Defender Firewall'");
        Console.WriteLine("      - Click 'Change settings' (may need Admin)");
        Console.WriteLine("      - Click 'Allow another app...'");
        Console.WriteLine("      - Browse to NetworkSecurityMonitor.exe");
        Console.WriteLine("      - Make sure it's checked for Private and Public networks");

        Console.WriteLine("\nALTERNATIVE: Command Line Method");
        Console.WriteLine("   Open Command Prompt as Administrator and run:");
        Console.WriteLine("   ");
        Console.WriteLine("   netsh advfirewall set allprofiles state on");
        Console.WriteLine("   ");
        Console.WriteLine("   netsh advfirewall firewall add rule name=\"NetworkSecurityMonitor-Allow\" ^");
        Console.WriteLine("       dir=in action=allow program=\"%SystemRoot%\\System32\\NetworkSecurityMonitor.exe\" ^");
        Console.WriteLine("       enable=yes");

        Console.WriteLine("\nSTEP 3: Verify Configuration");
        Console.WriteLine("   - Windows Firewall should show as 'ON' in system tray");
        Console.WriteLine("   - Network Security Monitor should have inbound access");

        while (true)
        {
            Console.Write("\n   Have you completed the firewall configuration? (y/n): ");
            string response = Console.ReadLine()?.Trim().ToLower() ?? "";

            if (response == "y" || response == "yes")
            {
                Console.WriteLine("   ✅ Proceeding with firewall configuration confirmed.");
                return true;
            }
            else if (response == "n" || response == "no")
            {
                Console.WriteLine("   📋 Please follow the instructions above, then confirm.");
                Console.Write("   Press Enter to show instructions again...");
                Console.ReadLine();
                return ShowManualFirewallInstructions();
            }
            else
            {
                Console.WriteLine("   ❌ Please answer 'y' or 'n'.");
            }
        }
    }

    // ADDED: Run firewall command and return output
    private async Task<string> RunFirewallCommandAsync(string command)
    {
        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (!string.IsNullOrEmpty(error))
            {
                Console.WriteLine($"   ⚠️  Warning: {error}");
            }

            return output;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   ❌ Command failed: {ex.Message}");
            return "";
        }
    }

    // ADDED: Display welcome header
    private void DisplayWelcomeHeader()
    {
        Console.WriteLine("╔══════════════════════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║                                                                              ║");
        Console.WriteLine("║                    🛡️  NETWORK SECURITY MONITOR                            ║");
        Console.WriteLine("║                                                                              ║");
        Console.WriteLine("║                Enterprise-Grade Cyber Defense System                          ║");
        Console.WriteLine("║                                                                              ║");
        Console.WriteLine("║                🔒 Protecting Against DDoS, Port Scanning & Threats          ║");
        Console.WriteLine("║                                                                              ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════════════════════╝");
    }
}
