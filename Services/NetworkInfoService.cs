using System.Net;
using System.Net.NetworkInformation;

namespace NetworkSecurityMonitor.Services;

// ADDED: Service to get network information and public IP
public class NetworkInfoService
{
    // ADDED: Get local IP addresses (returns configured IP first)
    public List<string> GetLocalIPAddresses()
    {
        var localIPs = new List<string>();

        // Add configured local IP first if available
        if (!string.IsNullOrEmpty(UserConfiguration.LocalIP))
        {
            localIPs.Add(UserConfiguration.LocalIP);
        }

        // Then add all detected local IPs
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus == OperationalStatus.Up)
            {
                var properties = networkInterface.GetIPProperties();
                foreach (var address in properties.UnicastAddresses)
                {
                    if (address.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var ip = address.Address.ToString();
                        // Don't duplicate the configured IP
                        if (!localIPs.Contains(ip))
                        {
                            localIPs.Add(ip);
                        }
                    }
                }
            }
        }

        return localIPs;
    }

    // ADDED: Get configured local IP
    public string GetConfiguredLocalIP()
    {
        return UserConfiguration.LocalIP;
    }

    // ADDED: Get configured public IP
    public string GetConfiguredPublicIP()
    {
        return UserConfiguration.PublicIP;
    }

    // ADDED: Get public/external IP address (returns configured IP if available)
    public async Task<string?> GetPublicIPAddressAsync()
    {
        // Return configured public IP if available
        if (!string.IsNullOrEmpty(UserConfiguration.PublicIP))
        {
            return UserConfiguration.PublicIP;
        }

        try
        {
            using var client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(5);

            // ADDED: Try multiple services for reliability
            var services = new[]
            {
                "https://api.ipify.org",
                "https://icanhazip.com",
                "https://ifconfig.me/ip"
            };

            foreach (var service in services)
            {
                try
                {
                    var response = await client.GetStringAsync(service);
                    var ip = response.Trim();
                    if (IPAddress.TryParse(ip, out _))
                    {
                        return ip;
                    }
                }
                catch
                {
                    continue;
                }
            }
        }
        catch
        {
            // ADDED: Silent fail - not critical
        }

        return null;
    }

    // ADDED: Check if IP is external (not private)
    public bool IsExternalIP(string ipAddress)
    {
        if (IPAddress.TryParse(ipAddress, out var ip))
        {
            return !IsPrivateIP(ip);
        }
        return false;
    }

    // ADDED: Check if IP is private
    private bool IsPrivateIP(IPAddress ip)
    {
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
        }

        var bytes = ip.GetAddressBytes();
        
        // 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
        return bytes[0] == 127 ||
               bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               (bytes[0] == 169 && bytes[1] == 254);
    }
}

