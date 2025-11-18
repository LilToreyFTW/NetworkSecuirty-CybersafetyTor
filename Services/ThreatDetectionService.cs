using NetworkSecurityMonitor.Models;
using System.Net;
using Microsoft.AspNetCore.SignalR;
using NetworkSecurityMonitor.Hubs;

namespace NetworkSecurityMonitor.Services;

// ADDED: Advanced threat detection service with pattern recognition
public class ThreatDetectionService
{
    private readonly NetworkMonitorService _networkMonitor;
    private readonly AIAnalysisService _aiAnalysis;
    private readonly ActiveDefenseService _activeDefense;
    private readonly IncidentResponseService _incidentResponse;
    private readonly IHubContext<ThreatHub>? _hubContext;
    private readonly List<ThreatPattern> _knownPatterns = new();

    public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;

    public ThreatDetectionService(
        NetworkMonitorService networkMonitor,
        AIAnalysisService aiAnalysis,
        ActiveDefenseService activeDefense,
        IHubContext<ThreatHub>? hubContext = null)
    {
        _networkMonitor = networkMonitor;
        _aiAnalysis = aiAnalysis;
        _activeDefense = activeDefense;
        _incidentResponse = new IncidentResponseService();
        _hubContext = hubContext;
        InitializeThreatPatterns();

        // ADDED: Subscribe to network monitor events
        _networkMonitor.ThreatDetected += OnNetworkThreatDetected;
    }

    // ADDED: Initialize known attack patterns
    private void InitializeThreatPatterns()
    {
        _knownPatterns.Add(new ThreatPattern
        {
            Name = "DDoS Attack",
            Description = "Distributed Denial of Service - Multiple rapid connections",
            Threshold = 100,
            TimeWindow = TimeSpan.FromMinutes(1)
        });

        _knownPatterns.Add(new ThreatPattern
        {
            Name = "Port Scanning",
            Description = "Systematic scanning of multiple ports",
            Threshold = 10,
            TimeWindow = TimeSpan.FromMinutes(2)
        });

        _knownPatterns.Add(new ThreatPattern
        {
            Name = "Brute Force",
            Description = "Repeated connection attempts to same port",
            Threshold = 20,
            TimeWindow = TimeSpan.FromMinutes(5)
        });
    }

    // ADDED: Handle network threat detection events
    private async void OnNetworkThreatDetected(object? sender, ThreatDetectedEventArgs e)
    {
        var activity = e.Activity;

        // ADDED: Enhance with AI analysis
        var aiAnalysis = _aiAnalysis.AnalyzeThreat(activity);
        activity.AIConfidence = aiAnalysis.Confidence;
        activity.AIRecommendation = aiAnalysis.Recommendation;
        activity.RiskScore = aiAnalysis.RiskScore;

        // ADDED: Perform additional analysis
        await PerformDeepAnalysis(activity);

        // ADDED: Automatically block attacker if not already blocked
        // ADDED: Block ALL external threats immediately (aggressive protection)
        if (!_activeDefense.IsIPBlocked(activity.IPAddress))
        {
            // ADDED: Block ANY suspicious activity from external IPs immediately
            _activeDefense.BlockAttackerIP(activity.IPAddress, activity.AttackType);
            activity.AIRecommendation += " | [AUTO-BLOCKED] Attacker IP has been blocked via Windows Firewall and redirected to decoy IP 999.222.215.9.";
            activity.Severity = ThreatSeverity.Critical; // ADDED: Escalate to critical when blocked
        }

        // ADDED: Log security incident for forensic analysis
        _incidentResponse.LogSecurityIncident(activity);

        // ADDED: Collect forensic evidence
        _incidentResponse.CollectForensicEvidence(activity);

        // ADDED: Raise event for GUI
        ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs { Activity = activity });

        // ADDED: Broadcast to connected clients
        if (_hubContext != null)
        {
            await _hubContext.Clients.All.SendAsync("NewThreatDetected", activity);
        }
    }

    // ADDED: Perform deep analysis on detected threats
    private async Task PerformDeepAnalysis(SuspiciousActivity activity)
    {
        // ADDED: Check if IP is from known malicious ranges
        activity.IsKnownMalicious = IsKnownMaliciousIP(activity.IPAddress);
        if (activity.IsKnownMalicious)
        {
            activity.Severity = ThreatSeverity.Critical;
            activity.AttackType += " (Known Malicious IP Range)";
            activity.ThreatCategory = "Malicious Range";
        }

        // ADDED: Get geolocation information
        activity.Country = await GetIPGeolocationAsync(activity.IPAddress);

        // ADDED: Analyze connection patterns
        var connections = _networkMonitor.GetActiveConnections()
            .Where(c => c.IPAddress == activity.IPAddress)
            .ToList();

        if (connections.Count > 0)
        {
            activity.AverageConnectionsPerSecond = connections.Sum(c => c.ConnectionCount) /
                (DateTime.UtcNow - activity.FirstDetected).TotalSeconds;
        }

        // ADDED: Categorize threat based on patterns
        if (activity.AttackType.Contains("DDoS") || activity.AttackType.Contains("Rapid"))
        {
            activity.ThreatCategory = "DDoS Attack";
        }
        else if (activity.AttackType.Contains("Port Scanning"))
        {
            activity.ThreatCategory = "Reconnaissance";
        }
        else if (activity.AttackType.Contains("Brute Force"))
        {
            activity.ThreatCategory = "Credential Attack";
        }

        // ADDED: Enhanced risk scoring based on multiple factors
        int riskBonus = 0;
        if (activity.IsKnownMalicious) riskBonus += 30;
        if (activity.Country != "Unknown") riskBonus += 10;
        if (activity.ConnectionCount > 50) riskBonus += 20;
        if (activity.AverageConnectionsPerSecond > 10) riskBonus += 25;

        activity.RiskScore = Math.Min(100, activity.RiskScore + riskBonus);
        activity.LastUpdated = DateTime.UtcNow;
    }

    // ADDED: Check if IP is from known malicious ranges (enhanced check)
    private bool IsKnownMaliciousIP(string ipAddress)
    {
        if (IPAddress.TryParse(ipAddress, out var ip))
        {
            var octets = ipAddress.Split('.');

            // ADDED: Check for known malicious IP ranges
            // These are examples of ranges commonly associated with attacks
            if (octets.Length == 4)
            {
                int o1 = int.Parse(octets[0]);
                int o2 = int.Parse(octets[1]);

                // ADDED: Known botnet ranges (examples)
                if ((o1 == 185 && o2 >= 100 && o2 <= 255) || // Some known attack ranges
                    (o1 == 194 && o2 >= 0 && o2 <= 63) ||
                    (o1 == 91 && o2 >= 200 && o2 <= 255))
                {
                    return true;
                }

                // ADDED: Check for TOR exit nodes (common attack source)
                if (o1 == 176 && o2 == 10) return true; // Example TOR range

                // ADDED: Known VPN/proxy services often used for attacks
                if ((o1 == 104 && o2 == 18) || // Cloudflare ranges sometimes abused
                    (o1 == 172 && o2 >= 64 && o2 <= 71)) // Some AWS ranges
                {
                    return true;
                }
            }
        }
        return false;
    }

    // ADDED: Get geolocation info for threat intelligence
    private async Task<string> GetIPGeolocationAsync(string ipAddress)
    {
        try
        {
            // ADDED: Use a free geolocation API (example)
            using var client = new HttpClient();
            var response = await client.GetStringAsync($"http://ip-api.com/json/{ipAddress}");

            // ADDED: Parse basic info (in real implementation, use proper JSON parsing)
            if (response.Contains("\"country\":\""))
            {
                var start = response.IndexOf("\"country\":\"") + 11;
                var end = response.IndexOf("\"", start);
                var country = response.Substring(start, end - start);
                return country;
            }
        }
        catch
        {
            // ADDED: Silently fail if geolocation service unavailable
        }
        return "Unknown";
    }

    // ADDED: Get all detected threats
    public List<SuspiciousActivity> GetAllThreats()
    {
        return _networkMonitor.GetDetectedThreats();
    }

    // ADDED: Get security summary report
    public string GetSecuritySummary()
    {
        return _incidentResponse.GenerateSecuritySummary();
    }
}

// ADDED: Threat pattern definition
public class ThreatPattern
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int Threshold { get; set; }
    public TimeSpan TimeWindow { get; set; }
}

