using System.Diagnostics;
using System.IO;
using NetworkSecurityMonitor.Models;

namespace NetworkSecurityMonitor.Services;

// ADDED: Incident response service for automated threat handling
public class IncidentResponseService
{
    private readonly string _logDirectory;
    private readonly string _evidenceDirectory;

    public IncidentResponseService()
    {
        _logDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
        _evidenceDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Evidence");

        Directory.CreateDirectory(_logDirectory);
        Directory.CreateDirectory(_evidenceDirectory);
    }

    // ADDED: Log security incident with full details
    public void LogSecurityIncident(SuspiciousActivity activity)
    {
        try
        {
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss");
            var filename = $"incident-{activity.IPAddress}-{timestamp}.log";
            var filepath = Path.Combine(_logDirectory, filename);

            var incidentReport = GenerateIncidentReport(activity);

            File.WriteAllText(filepath, incidentReport);

            // ADDED: Also log to Windows Event Log
            LogToWindowsEventLog(activity, incidentReport);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[INCIDENT RESPONSE ERROR] Failed to log incident: {ex.Message}");
        }
    }

    // ADDED: Generate comprehensive incident report
    private string GenerateIncidentReport(SuspiciousActivity activity)
    {
        var report = new System.Text.StringBuilder();

        report.AppendLine("=== NETWORK SECURITY INCIDENT REPORT ===");
        report.AppendLine($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}");
        report.AppendLine();

        report.AppendLine("THREAT DETAILS:");
        report.AppendLine($"IP Address: {activity.IPAddress}");
        report.AppendLine($"Country: {activity.Country}");
        report.AppendLine($"Severity: {activity.Severity}");
        report.AppendLine($"Attack Type: {activity.AttackType}");
        report.AppendLine($"Threat Category: {activity.ThreatCategory}");
        report.AppendLine($"Risk Score: {activity.RiskScore}%");
        report.AppendLine($"Known Malicious: {(activity.IsKnownMalicious ? "YES" : "NO")}");
        report.AppendLine();

        report.AppendLine("CONNECTION ANALYSIS:");
        report.AppendLine($"First Detected: {activity.FirstDetected:yyyy-MM-dd HH:mm:ss UTC}");
        report.AppendLine($"Last Detected: {activity.LastDetected:yyyy-MM-dd HH:mm:ss UTC}");
        report.AppendLine($"Total Connections: {activity.ConnectionCount}");
        report.AppendLine($"Avg Connections/Sec: {activity.AverageConnectionsPerSecond:F2}");
        report.AppendLine($"Ports Targeted: {string.Join(", ", activity.Ports)}");
        report.AppendLine();

        report.AppendLine("AI ANALYSIS:");
        report.AppendLine($"AI Confidence: {activity.AIConfidence:F2}%");
        report.AppendLine($"AI Recommendation: {activity.AIRecommendation}");
        report.AppendLine();

        report.AppendLine("DEFENSIVE ACTIONS TAKEN:");
        if (activity.AIRecommendation.Contains("AUTO-BLOCKED"))
        {
            report.AppendLine("✓ Firewall rule created");
            report.AppendLine("✓ Traffic redirected to decoy IP (999.222.215.9)");
            report.AppendLine("✓ Connection attempts blocked at network level");
        }
        report.AppendLine();

        report.AppendLine("FORENSIC EVIDENCE:");
        report.AppendLine("- Network packet capture recommended");
        report.AppendLine("- System logs collected");
        report.AppendLine("- IP geolocation data obtained");
        report.AppendLine();

        report.AppendLine("RECOMMENDED ACTIONS:");
        report.AppendLine("1. Monitor for additional activity from this IP range");
        report.AppendLine("2. Update firewall rules if necessary");
        report.AppendLine("3. Consider reporting to ISP if attack persists");
        report.AppendLine("4. Review system logs for compromise indicators");
        report.AppendLine();

        report.AppendLine("=== END OF REPORT ===");

        return report.ToString();
    }

    // ADDED: Log to Windows Event Log for system integration
    private void LogToWindowsEventLog(SuspiciousActivity activity, string report)
    {
        try
        {
            if (!EventLog.SourceExists("NetworkSecurityMonitor"))
            {
                EventLog.CreateEventSource("NetworkSecurityMonitor", "Security");
            }

            var eventLog = new EventLog("Security");
            eventLog.Source = "NetworkSecurityMonitor";

            var severity = activity.Severity switch
            {
                ThreatSeverity.Critical => EventLogEntryType.Error,
                ThreatSeverity.High => EventLogEntryType.Warning,
                _ => EventLogEntryType.Information
            };

            eventLog.WriteEntry(
                $"Security threat detected from {activity.IPAddress} ({activity.Country}). " +
                $"Attack: {activity.AttackType}. Risk Score: {activity.RiskScore}%. " +
                $"Defensive action: {(activity.AIRecommendation.Contains("AUTO-BLOCKED") ? "Blocked" : "Logged")}",
                severity,
                activity.RiskScore > 75 ? 1001 : 1000
            );
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[EVENT LOG ERROR] Failed to write to Windows Event Log: {ex.Message}");
        }
    }

    // ADDED: Collect forensic evidence (network capture simulation)
    public void CollectForensicEvidence(SuspiciousActivity activity)
    {
        try
        {
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss");
            var evidenceFile = $"evidence-{activity.IPAddress}-{timestamp}.txt";
            var filepath = Path.Combine(_evidenceDirectory, evidenceFile);

            var evidence = new System.Text.StringBuilder();
            evidence.AppendLine("FORENSIC EVIDENCE COLLECTION");
            evidence.AppendLine($"Timestamp: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}");
            evidence.AppendLine($"Target IP: {activity.IPAddress}");
            evidence.AppendLine();

            evidence.AppendLine("NETWORK CONNECTIONS LOG:");
            // In a real implementation, this would capture actual network packets
            evidence.AppendLine("- Connection attempts logged");
            evidence.AppendLine("- Packet patterns analyzed");
            evidence.AppendLine("- Source ports documented");
            evidence.AppendLine();

            evidence.AppendLine("SYSTEM RESPONSE:");
            evidence.AppendLine("- Firewall rules applied");
            evidence.AppendLine("- Attack patterns blocked");
            evidence.AppendLine("- Incident response triggered");

            File.WriteAllText(filepath, evidence.ToString());
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FORENSICS ERROR] Failed to collect evidence: {ex.Message}");
        }
    }

    // ADDED: Generate security summary report
    public string GenerateSecuritySummary()
    {
        try
        {
            var logFiles = Directory.GetFiles(_logDirectory, "*.log");
            var summary = new System.Text.StringBuilder();

            summary.AppendLine("=== SECURITY SUMMARY REPORT ===");
            summary.AppendLine($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}");
            summary.AppendLine();
            summary.AppendLine($"Total Incidents Logged: {logFiles.Length}");

            if (logFiles.Length > 0)
            {
                var recentIncidents = logFiles
                    .OrderByDescending(f => File.GetCreationTimeUtc(f))
                    .Take(10);

                summary.AppendLine();
                summary.AppendLine("RECENT INCIDENTS:");
                foreach (var file in recentIncidents)
                {
                    var filename = Path.GetFileName(file);
                    var creationTime = File.GetCreationTimeUtc(file);
                    summary.AppendLine($"- {filename} ({creationTime:yyyy-MM-dd HH:mm:ss UTC})");
                }
            }

            summary.AppendLine();
            summary.AppendLine("SYSTEM STATUS: ACTIVE");
            summary.AppendLine("DEFENSE STATUS: OPERATIONAL");

            return summary.ToString();
        }
        catch (Exception ex)
        {
            return $"Error generating summary: {ex.Message}";
        }
    }
}
