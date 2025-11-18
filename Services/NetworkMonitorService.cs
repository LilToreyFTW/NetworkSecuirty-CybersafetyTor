using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Collections.Concurrent;
using NetworkSecurityMonitor.Models;

namespace NetworkSecurityMonitor.Services;

// ADDED: Service to monitor network connections and traffic
public class NetworkMonitorService : IDisposable
{
    private readonly ConcurrentDictionary<string, Models.ConnectionInfo> _activeConnections = new();
    private readonly ConcurrentDictionary<string, SuspiciousActivity> _suspiciousIPs = new();
    private readonly System.Threading.Timer _monitoringTimer;
    private readonly object _lockObject = new();
    private bool _disposed = false;

    public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;

    public NetworkMonitorService()
    {
        // ADDED: Start monitoring every 2 seconds
        _monitoringTimer = new System.Threading.Timer(MonitorNetworkConnections, null, TimeSpan.Zero, TimeSpan.FromSeconds(2));
    }

    // ADDED: Monitor all active network connections
    private void MonitorNetworkConnections(object? state)
    {
        try
        {
            var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            var currentTime = DateTime.UtcNow;

            foreach (var connection in connections)
            {
                // ADDED: Focus on incoming connections from EXTERNAL IPs (potential attacks)
                if (connection.State == TcpState.Established && 
                    IsIncomingConnection(connection.LocalEndPoint, connection.RemoteEndPoint))
                {
                    var remoteIP = connection.RemoteEndPoint.Address.ToString();
                    
                    // ADDED: Double-check it's an external IP (not private/local)
                    if (IsPrivateIPAddress(connection.RemoteEndPoint.Address))
                        continue; // Skip local network traffic
                    
                    var key = $"{remoteIP}:{connection.RemoteEndPoint.Port}";

                    if (!_activeConnections.ContainsKey(key))
                    {
                        _activeConnections[key] = new Models.ConnectionInfo
                        {
                            IPAddress = remoteIP,
                            Port = connection.RemoteEndPoint.Port,
                            FirstSeen = currentTime,
                            LastSeen = currentTime,
                            ConnectionCount = 1
                        };
                    }
                    else
                    {
                        var info = _activeConnections[key];
                        info.LastSeen = currentTime;
                        info.ConnectionCount++;
                    }
                }
            }

            // ADDED: Analyze for suspicious patterns
            AnalyzeSuspiciousActivity();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Network monitoring error: {ex.Message}");
        }
    }

    // ADDED: Determine if connection is incoming (remote connects to local)
    private bool IsIncomingConnection(IPEndPoint local, IPEndPoint remote)
    {
        var remoteIP = remote.Address.ToString();
        
        // ADDED: Filter out localhost
        if (remoteIP == "127.0.0.1" || remoteIP == "::1" || remoteIP.StartsWith("::ffff:127."))
            return false;

        // ADDED: Filter out private/local network IPs - focus on EXTERNAL threats only
        if (IsPrivateIPAddress(remote.Address))
            return false;

        // ADDED: Monitor connections to common service ports or high ports (incoming connections)
        var monitoredPorts = new[] { 80, 443, 8080, 3389, 22, 21, 25, 53, 135, 139, 445, 5000, 3000 };
        return monitoredPorts.Contains(local.Port) || local.Port > 49152;
    }

    // ADDED: Check if IP address is private/local (not from internet)
    private bool IsPrivateIPAddress(IPAddress ipAddress)
    {
        if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // ADDED: Filter IPv6 local addresses
            if (ipAddress.IsIPv6LinkLocal || ipAddress.IsIPv6SiteLocal || 
                ipAddress.IsIPv6Multicast || ipAddress.IsIPv6Teredo)
                return true;
            
            // ADDED: Check for IPv6-mapped IPv4 addresses
            if (ipAddress.IsIPv4MappedToIPv6)
            {
                var ipv4 = ipAddress.MapToIPv4();
                return IsPrivateIPv4Address(ipv4);
            }
            return false;
        }

        return IsPrivateIPv4Address(ipAddress);
    }

    // ADDED: Check if IPv4 address is in private ranges
    private bool IsPrivateIPv4Address(IPAddress ipAddress)
    {
        var bytes = ipAddress.GetAddressBytes();
        
        // ADDED: 127.0.0.0/8 - Loopback
        if (bytes[0] == 127)
            return true;
        
        // ADDED: 10.0.0.0/8 - Private network
        if (bytes[0] == 10)
            return true;
        
        // ADDED: 172.16.0.0/12 - Private network (172.16.0.0 to 172.31.255.255)
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            return true;
        
        // ADDED: 192.168.0.0/16 - Private network
        if (bytes[0] == 192 && bytes[1] == 168)
            return true;
        
        // ADDED: 169.254.0.0/16 - Link-local (APIPA)
        if (bytes[0] == 169 && bytes[1] == 254)
            return true;
        
        // ADDED: 224.0.0.0/4 - Multicast
        if (bytes[0] >= 224 && bytes[0] <= 239)
            return true;
        
        return false;
    }

    // ADDED: Analyze connections for suspicious patterns
    private void AnalyzeSuspiciousActivity()
    {
        var currentTime = DateTime.UtcNow;
        var suspiciousThreshold = TimeSpan.FromMinutes(1);

        foreach (var kvp in _activeConnections)
        {
            var connection = kvp.Value;
            var timeSpan = currentTime - connection.FirstSeen;

            // ADDED: Skip analysis for private IPs (already filtered, but double-check)
            if (IPAddress.TryParse(connection.IPAddress, out var ip) && IsPrivateIPAddress(ip))
                continue;

            // ADDED: Detect rapid connection attempts from EXTERNAL IPs (potential DDoS)
            // Aggressive threshold to catch attacks early - block after just 10 connections in 30 seconds
            if (connection.ConnectionCount > 10 && timeSpan.TotalSeconds < 30)
            {
                if (!_suspiciousIPs.ContainsKey(connection.IPAddress))
                {
                    var suspicious = new SuspiciousActivity
                    {
                        IPAddress = connection.IPAddress,
                        FirstDetected = connection.FirstSeen,
                        LastDetected = currentTime,
                        AttackType = "🚨 EXTERNAL ATTACK: Rapid Connection Attempts (DDoS Pattern)",
                        Severity = ThreatSeverity.High,
                        ConnectionCount = connection.ConnectionCount,
                        Ports = new List<int> { connection.Port }
                    };

                    _suspiciousIPs[connection.IPAddress] = suspicious;
                    OnThreatDetected(suspicious);
                }
                else
                {
                    var existing = _suspiciousIPs[connection.IPAddress];
                    existing.LastDetected = currentTime;
                    existing.ConnectionCount += connection.ConnectionCount;
                    if (!existing.Ports.Contains(connection.Port))
                        existing.Ports.Add(connection.Port);
                }
            }

            // ADDED: Detect port scanning from EXTERNAL IPs (multiple ports from same external IP)
            var sameIPConnections = _activeConnections.Values
                .Where(c => c.IPAddress == connection.IPAddress)
                .ToList();

            if (sameIPConnections.Count > 3 && timeSpan.TotalSeconds < 60)
            {
                var uniquePorts = sameIPConnections.Select(c => c.Port).Distinct().Count();
                if (uniquePorts > 2) // Aggressive threshold - block after 2 different ports
                {
                    if (!_suspiciousIPs.ContainsKey(connection.IPAddress))
                    {
                        var suspicious = new SuspiciousActivity
                        {
                            IPAddress = connection.IPAddress,
                            FirstDetected = connection.FirstSeen,
                            LastDetected = currentTime,
                            AttackType = "🚨 EXTERNAL ATTACK: Port Scanning Detected",
                            Severity = ThreatSeverity.Medium,
                            ConnectionCount = sameIPConnections.Sum(c => c.ConnectionCount),
                            Ports = sameIPConnections.Select(c => c.Port).Distinct().ToList()
                        };

                        _suspiciousIPs[connection.IPAddress] = suspicious;
                        OnThreatDetected(suspicious);
                    }
                }
            }
        }

        // ADDED: Clean up old connections
        var expiredKeys = _activeConnections
            .Where(kvp => (currentTime - kvp.Value.LastSeen).TotalMinutes > 5)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredKeys)
        {
            _activeConnections.TryRemove(key, out _);
        }
    }

    // ADDED: Trigger threat detection event
    private void OnThreatDetected(SuspiciousActivity activity)
    {
        ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs { Activity = activity });
        Console.ForegroundColor = activity.Severity == ThreatSeverity.Critical ? ConsoleColor.Red :
                                  activity.Severity == ThreatSeverity.High ? ConsoleColor.Yellow :
                                  ConsoleColor.White;
        Console.WriteLine($"[🚨 EXTERNAL THREAT DETECTED] {activity.AttackType}");
        Console.WriteLine($"   IP Address: {activity.IPAddress}");
        Console.WriteLine($"   Severity: {activity.Severity} | Connections: {activity.ConnectionCount}");
        Console.ResetColor();
    }

    // ADDED: Get all detected threats
    public List<SuspiciousActivity> GetDetectedThreats()
    {
        return _suspiciousIPs.Values.OrderByDescending(t => t.LastDetected).ToList();
    }

    // ADDED: Get active connections
    public List<Models.ConnectionInfo> GetActiveConnections()
    {
        return _activeConnections.Values.ToList();
    }

    // ADDED: Dispose resources properly
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
                // ADDED: Dispose timer
                _monitoringTimer?.Dispose();
            }
            _disposed = true;
        }
    }
}

