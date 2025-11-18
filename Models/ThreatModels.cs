namespace NetworkSecurityMonitor.Models;

// ADDED: Suspicious activity model (enhanced with threat intelligence)
public class SuspiciousActivity
{
    public string IPAddress { get; set; } = string.Empty;
    public DateTime FirstDetected { get; set; }
    public DateTime LastDetected { get; set; }
    public string AttackType { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public int ConnectionCount { get; set; }
    public List<int> Ports { get; set; } = new();
    public double AverageConnectionsPerSecond { get; set; }
    public double AIConfidence { get; set; }
    public string AIRecommendation { get; set; } = string.Empty;
    public int RiskScore { get; set; }

    // ADDED: Enhanced threat intelligence
    public string Country { get; set; } = "Unknown";
    public string Organization { get; set; } = "Unknown";
    public string ISP { get; set; } = "Unknown";
    public bool IsKnownMalicious { get; set; }
    public bool IsTorExitNode { get; set; }
    public bool IsVPN { get; set; }
    public string ThreatCategory { get; set; } = "Unknown";
    public List<string> AssociatedMalware { get; set; } = new();
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
}

// ADDED: Threat severity levels
public enum ThreatSeverity
{
    Low,
    Medium,
    High,
    Critical
}

// ADDED: Connection information model
public class ConnectionInfo
{
    public string IPAddress { get; set; } = string.Empty;
    public int Port { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public int ConnectionCount { get; set; }
}

// ADDED: Threat detected event args
public class ThreatDetectedEventArgs : EventArgs
{
    public SuspiciousActivity Activity { get; set; } = new();
}

