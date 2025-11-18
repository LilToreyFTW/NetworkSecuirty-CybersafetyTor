using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetworkSecurityMonitor.Models;

namespace NetworkSecurityMonitor.Services;

// ADDED: Active defense service to block attackers and redirect connections
public class ActiveDefenseService : IDisposable
{
    private readonly HashSet<string> _blockedIPs = new();
    private readonly string _decoyIP = "999.222.215.9"; // ADDED: Fake IP to redirect attackers to
    private readonly List<TcpListener> _honeypotListeners = new();
    private readonly object _lockObject = new();
    private bool _disposed = false;

    public ActiveDefenseService()
    {
        // ADDED: Start honeypot listeners on common attack ports
        StartHoneypotListeners();
    }

    // ADDED: Block attacker IP using Windows Firewall
    public void BlockAttackerIP(string ipAddress, string reason = "Suspicious Activity")
    {
        lock (_lockObject)
        {
            if (_blockedIPs.Contains(ipAddress))
                return; // Already blocked

            _blockedIPs.Add(ipAddress);

            try
            {
                // ADDED: Create Windows Firewall rule to block the IP
                var ruleName = $"BlockAttacker_{ipAddress.Replace(".", "_")}_{DateTime.UtcNow.Ticks}";
                
                // ADDED: Block inbound connections from attacker IP
                var blockCommand = $"netsh advfirewall firewall add rule name=\"{ruleName}\" dir=in action=block remoteip={ipAddress} protocol=any enable=yes";
                
                var processInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {blockCommand}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    Verb = "runas" // ADDED: Run as administrator
                };

                using var process = Process.Start(processInfo);
                if (process != null)
                {
                    process.WaitForExit();
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[🛡️ ACTIVE DEFENSE] Blocked attacker IP: {ipAddress} | Reason: {reason}");
                    Console.WriteLine($"[🛡️ ACTIVE DEFENSE] Firewall rule created: {ruleName}");
                    Console.WriteLine($"[🛡️ ACTIVE DEFENSE] All connections from {ipAddress} are now blocked!");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[⚠️ WARNING] Failed to block IP {ipAddress} via firewall: {ex.Message}");
                Console.WriteLine($"[⚠️ WARNING] Note: Firewall blocking requires administrator privileges");
                Console.ResetColor();
            }
        }
    }

    // ADDED: Start honeypot listeners on common ports to catch attackers
    private void StartHoneypotListeners()
    {
        // ADDED: Common ports that attackers target
        var honeypotPorts = new[] { 80, 443, 3389, 22, 21, 25, 135, 139, 445, 8080, 5000, 3000 };

        foreach (var port in honeypotPorts)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                _honeypotListeners.Add(listener);

                // ADDED: Start accepting connections asynchronously
                _ = Task.Run(() => AcceptHoneypotConnections(listener, port));
            }
            catch (Exception ex)
            {
                // ADDED: Port might be in use, skip it
                Console.WriteLine($"[INFO] Honeypot listener on port {port} not started: {ex.Message}");
            }
        }

        Console.WriteLine($"[🛡️ ACTIVE DEFENSE] Honeypot listeners started on {_honeypotListeners.Count} ports");
    }

    // ADDED: Accept and handle honeypot connections
    private async Task AcceptHoneypotConnections(TcpListener listener, int port)
    {
        while (!_disposed)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync();
                var remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                var attackerIP = remoteEndPoint?.Address.ToString() ?? "Unknown";

                // ADDED: Log the connection attempt
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"[🍯 HONEYPOT] Connection attempt from {attackerIP}:{remoteEndPoint?.Port} on port {port}");
                Console.ResetColor();

                // ADDED: Handle connection in background
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await HandleHoneypotConnection(client, attackerIP, port);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ERROR] Honeypot connection handler error: {ex.Message}");
                    }
                });
            }
            catch (ObjectDisposedException)
            {
                // ADDED: Listener was disposed, exit
                break;
            }
            catch (Exception ex)
            {
                if (!_disposed)
                {
                    Console.WriteLine($"[ERROR] Honeypot listener error on port {port}: {ex.Message}");
                }
            }
        }
    }

    // ADDED: Handle individual honeypot connection - redirect attacker to fake IP
    private async Task HandleHoneypotConnection(TcpClient client, string attackerIP, int port)
    {
        try
        {
            using (client)
            {
                var stream = client.GetStream();
                
                // ADDED: Check if this IP should be blocked
                if (IsSuspiciousIP(attackerIP))
                {
                    // ADDED: Send fake response redirecting to decoy IP
                    var fakeResponse = GenerateFakeResponse(attackerIP, port);
                    var responseBytes = Encoding.UTF8.GetBytes(fakeResponse);
                    
                    await stream.WriteAsync(responseBytes, 0, responseBytes.Length);
                    await stream.FlushAsync();

                    // ADDED: Block the attacker
                    BlockAttackerIP(attackerIP, $"Honeypot connection on port {port}");
                }
                else
                {
                    // ADDED: Send generic fake response
                    var fakeResponse = $"HTTP/1.1 301 Moved Permanently\r\nLocation: http://{_decoyIP}\r\n\r\n";
                    var responseBytes = Encoding.UTF8.GetBytes(fakeResponse);
                    await stream.WriteAsync(responseBytes, 0, responseBytes.Length);
                    await stream.FlushAsync();
                }

                // ADDED: Keep connection open briefly to waste attacker's time
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        }
        catch (Exception ex)
        {
            // ADDED: Connection closed or error - attacker might have disconnected
            Console.WriteLine($"[INFO] Honeypot connection from {attackerIP} closed: {ex.Message}");
        }
    }

    // ADDED: Generate fake response that redirects to decoy IP
    private string GenerateFakeResponse(string attackerIP, int port)
    {
        // ADDED: Create fake HTTP response redirecting to decoy IP
        var response = new StringBuilder();
        response.AppendLine("HTTP/1.1 301 Moved Permanently");
        response.AppendLine($"Location: http://{_decoyIP}");
        response.AppendLine("Server: Fake-Server/1.0");
        response.AppendLine("Connection: close");
        response.AppendLine();
        response.AppendLine($"<html><body><h1>Redirecting to {_decoyIP}</h1></body></html>");
        
        return response.ToString();
    }

    // ADDED: Check if IP is suspicious (external IPs are always suspicious)
    private bool IsSuspiciousIP(string ipAddress)
    {
        if (IPAddress.TryParse(ipAddress, out var ip))
        {
            // ADDED: All external IPs connecting to honeypot are suspicious
            return !IsPrivateIPAddress(ip);
        }
        return true;
    }

    // ADDED: Check if IP address is private/local
    private bool IsPrivateIPAddress(IPAddress ipAddress)
    {
        if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return ipAddress.IsIPv6LinkLocal || ipAddress.IsIPv6SiteLocal;
        }

        var bytes = ipAddress.GetAddressBytes();
        return bytes[0] == 127 || // Loopback
               bytes[0] == 10 || // Private
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || // Private
               (bytes[0] == 192 && bytes[1] == 168) || // Private
               (bytes[0] == 169 && bytes[1] == 254); // Link-local
    }

    // ADDED: Get list of blocked IPs
    public List<string> GetBlockedIPs()
    {
        lock (_lockObject)
        {
            return _blockedIPs.ToList();
        }
    }

    // ADDED: Check if IP is blocked
    public bool IsIPBlocked(string ipAddress)
    {
        lock (_lockObject)
        {
            return _blockedIPs.Contains(ipAddress);
        }
    }

    // ADDED: Dispose resources
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    // ADDED: Protected dispose method
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // ADDED: Stop all honeypot listeners
                foreach (var listener in _honeypotListeners)
                {
                    try
                    {
                        listener.Stop();
                    }
                    catch { }
                }
                _honeypotListeners.Clear();
            }
            _disposed = true;
        }
    }
}

