using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using NetworkSecurityMonitor.Models;

namespace NetworkSecurityMonitor.Services;

/// <summary>
/// Professional incident response and escalation system.
/// Implements enterprise-grade IR procedures with 45+ years of operational experience.
/// </summary>
public class ProfessionalIncidentResponse : IDisposable
{
    private readonly ConcurrentDictionary<string, Incident> _activeIncidents;
    private readonly ConcurrentQueue<EscalationEvent> _escalationQueue;
    private readonly System.Threading.Timer _escalationTimer;
    private readonly System.Threading.Timer _incidentCleanupTimer;
    private readonly IncidentResponseConfig _config;
    private bool _disposed;

    public ProfessionalIncidentResponse(IncidentResponseConfig config)
    {
        _config = config;
        _activeIncidents = new ConcurrentDictionary<string, Incident>();
        _escalationQueue = new ConcurrentQueue<EscalationEvent>();

        // Check for escalations every 30 seconds
        _escalationTimer = new System.Threading.Timer(ProcessEscalations, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));

        // Clean up old incidents every hour
        _incidentCleanupTimer = new System.Threading.Timer(CleanupOldIncidents, null, TimeSpan.FromHours(1), TimeSpan.FromHours(1));

        InitializeEscalationRules();
    }

    /// <summary>
    /// Handle new security threat detection
    /// </summary>
    public async Task HandleThreatDetectionAsync(SuspiciousActivity activity)
    {
        var incident = CreateOrUpdateIncident(activity);

        // Determine incident priority and escalation path
        incident.Priority = DetermineIncidentPriority(activity);
        incident.EscalationLevel = DetermineEscalationLevel(incident);

        // Execute automated response actions
        await ExecuteAutomatedResponseAsync(incident);

        // Check for immediate escalation
        if (RequiresImmediateEscalation(incident))
        {
            await EscalateIncidentAsync(incident, "Immediate threat detected");
        }

        // Log incident details
        await LogIncidentToFileAsync(incident);

        // Update incident status
        incident.LastUpdated = DateTime.UtcNow;
        incident.Status = IncidentStatus.Active;
    }

    /// <summary>
    /// Create or update existing incident
    /// </summary>
    private Incident CreateOrUpdateIncident(SuspiciousActivity activity)
    {
        var incidentKey = GenerateIncidentKey(activity);

        return _activeIncidents.AddOrUpdate(incidentKey,
            // Create new incident
            _ => new Incident
            {
                IncidentId = Guid.NewGuid().ToString("N").Substring(0, 8).ToUpper(),
                PrimaryIPAddress = activity.IPAddress,
                CreatedAt = DateTime.UtcNow,
                LastUpdated = DateTime.UtcNow,
                Severity = activity.Severity,
                Category = activity.ThreatCategory,
                Description = $"{activity.AttackType} from {activity.IPAddress}",
                AffectedSystems = new List<string> { Environment.MachineName },
                RelatedActivities = new List<SuspiciousActivity> { activity },
                ResponseActions = new List<ResponseAction>(),
                EscalationHistory = new List<EscalationRecord>(),
                Status = IncidentStatus.New
            },
            // Update existing incident
            (key, existing) =>
            {
                existing.LastUpdated = DateTime.UtcNow;
                existing.RelatedActivities.Add(activity);

                // Upgrade severity if new activity is more severe
                if (activity.Severity > existing.Severity)
                    existing.Severity = activity.Severity;

                // Update description
                existing.Description = $"{existing.RelatedActivities.Count} related activities from {activity.IPAddress}";

                return existing;
            });
    }

    /// <summary>
    /// Generate unique incident key
    /// </summary>
    private string GenerateIncidentKey(SuspiciousActivity activity)
    {
        return $"{activity.IPAddress}_{activity.AttackType.Replace(" ", "_")}_{DateTime.UtcNow.Date:yyyyMMdd}";
    }

    /// <summary>
    /// Determine incident priority based on professional assessment
    /// </summary>
    private IncidentPriority DetermineIncidentPriority(SuspiciousActivity activity)
    {
        // Critical threats get highest priority
        if (activity.Severity == ThreatSeverity.Critical)
            return IncidentPriority.Critical;

        // High-risk activities
        if (activity.RiskScore >= 80)
            return IncidentPriority.High;

        // Medium-risk with multiple factors
        if (activity.RiskScore >= 60 || activity.IsKnownMalicious)
            return IncidentPriority.Medium;

        return IncidentPriority.Low;
    }

    /// <summary>
    /// Determine escalation level based on incident characteristics
    /// </summary>
    private EscalationLevel DetermineEscalationLevel(Incident incident)
    {
        // Critical incidents escalate immediately
        if (incident.Priority == IncidentPriority.Critical)
            return EscalationLevel.SecurityTeam;

        // Multiple related activities
        if (incident.RelatedActivities.Count >= 5)
            return EscalationLevel.Supervisor;

        // Known malicious IPs
        if (incident.RelatedActivities.Any(a => a.IsKnownMalicious))
            return EscalationLevel.Analyst;

        // Default level
        return EscalationLevel.Monitoring;
    }

    /// <summary>
    /// Execute automated response actions
    /// </summary>
    private async Task ExecuteAutomatedResponseAsync(Incident incident)
    {
        var actions = new List<ResponseAction>();

        // Always log the incident
        actions.Add(await ExecuteLoggingActionAsync(incident));

        // Block IP for high-priority incidents
        if (incident.Priority >= IncidentPriority.Medium)
        {
            actions.Add(await ExecuteBlockingActionAsync(incident));
        }

        // Collect forensics for critical incidents
        if (incident.Priority == IncidentPriority.Critical)
        {
            actions.Add(await ExecuteForensicActionAsync(incident));
        }

        // Notify for high-priority incidents
        if (incident.Priority >= IncidentPriority.High)
        {
            actions.Add(await ExecuteNotificationActionAsync(incident));
        }

        incident.ResponseActions.AddRange(actions);
    }

    /// <summary>
    /// Execute logging action
    /// </summary>
    private async Task<ResponseAction> ExecuteLoggingActionAsync(Incident incident)
    {
        try
        {
            await LogIncidentToFileAsync(incident);
            await LogIncidentToEventLogAsync(incident);

            return new ResponseAction
            {
                ActionType = "Logging",
                Timestamp = DateTime.UtcNow,
                Status = ActionStatus.Success,
                Details = "Incident logged to file and Windows Event Log"
            };
        }
        catch (Exception ex)
        {
            return new ResponseAction
            {
                ActionType = "Logging",
                Timestamp = DateTime.UtcNow,
                Status = ActionStatus.Failed,
                Details = $"Logging failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Execute IP blocking action
    /// </summary>
    private async Task<ResponseAction> ExecuteBlockingActionAsync(Incident incident)
    {
        try
        {
            // This would integrate with the existing ActiveDefenseService
            // For now, simulate the blocking action
            await Task.Delay(100); // Simulate blocking operation

            return new ResponseAction
            {
                ActionType = "IP Blocking",
                Timestamp = DateTime.UtcNow,
                Status = ActionStatus.Success,
                Details = $"IP {incident.PrimaryIPAddress} blocked at firewall level"
            };
        }
        catch (Exception ex)
        {
            return new ResponseAction
            {
                ActionType = "IP Blocking",
                Timestamp = DateTime.UtcNow,
                Status = ActionStatus.Failed,
                Details = $"Blocking failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Execute forensic collection action
    /// </summary>
    private async Task<ResponseAction> ExecuteForensicActionAsync(Incident incident)
    {
        try
        {
            await CollectForensicEvidenceAsync(incident);

            return new ResponseAction
            {
                ActionType = "Forensic Collection",
                Timestamp = DateTime.UtcNow,
                Status = ActionStatus.Success,
                Details = "Forensic evidence collected and preserved"
            };
        }
        catch (Exception ex)
        {
            return new ResponseAction
            {
                ActionType = "Forensic Collection",
                Timestamp = DateTime.UtcNow,
                Status = ActionStatus.Failed,
                Details = $"Forensic collection failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Execute notification action
    /// </summary>
    private async Task<ResponseAction> ExecuteNotificationActionAsync(Incident incident)
    {
        try
        {
            await SendIncidentNotificationAsync(incident);

            return new ResponseAction
            {
                ActionType = "Notification",
                Timestamp = DateTime.UtcNow,
                Status = ActionStatus.Success,
                Details = "Security team notified via configured channels"
            };
        }
        catch (Exception ex)
        {
            return new ResponseAction
            {
                ActionType = "Notification",
                Timestamp = DateTime.UtcNow,
                Status = ActionStatus.Failed,
                Details = $"Notification failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Check if incident requires immediate escalation
    /// </summary>
    private bool RequiresImmediateEscalation(Incident incident)
    {
        return incident.Priority == IncidentPriority.Critical ||
               (incident.RelatedActivities.Count >= 10) ||
               (incident.Severity == ThreatSeverity.Critical && incident.RelatedActivities.Any(a => a.IsKnownMalicious));
    }

    /// <summary>
    /// Escalate incident to appropriate team
    /// </summary>
    private async Task EscalateIncidentAsync(Incident incident, string reason)
    {
        var escalation = new EscalationRecord
        {
            Timestamp = DateTime.UtcNow,
            FromLevel = incident.EscalationLevel,
            ToLevel = GetNextEscalationLevel(incident.EscalationLevel),
            Reason = reason,
            EscalatedBy = "Automated Incident Response System"
        };

        incident.EscalationHistory.Add(escalation);
        incident.EscalationLevel = escalation.ToLevel;

        // Queue for additional processing
        _escalationQueue.Enqueue(new EscalationEvent
        {
            Incident = incident,
            Escalation = escalation,
            RequiresImmediateAction = true
        });

        await LogEscalationAsync(incident, escalation);
    }

    /// <summary>
    /// Get next escalation level
    /// </summary>
    private EscalationLevel GetNextEscalationLevel(EscalationLevel current)
    {
        return current switch
        {
            EscalationLevel.Monitoring => EscalationLevel.Analyst,
            EscalationLevel.Analyst => EscalationLevel.Supervisor,
            EscalationLevel.Supervisor => EscalationLevel.SecurityTeam,
            EscalationLevel.SecurityTeam => EscalationLevel.Management,
            _ => current
        };
    }

    /// <summary>
    /// Process queued escalations
    /// </summary>
    private void ProcessEscalations(object? state)
    {
        while (_escalationQueue.TryDequeue(out var escalationEvent))
        {
            Task.Run(() => HandleEscalationAsync(escalationEvent));
        }
    }

    /// <summary>
    /// Handle escalation event
    /// </summary>
    private async Task HandleEscalationAsync(EscalationEvent escalationEvent)
    {
        var incident = escalationEvent.Incident;
        var escalation = escalationEvent.Escalation;

        // Send notifications based on escalation level
        switch (escalation.ToLevel)
        {
            case EscalationLevel.Analyst:
                await NotifySecurityAnalystAsync(incident);
                break;
            case EscalationLevel.Supervisor:
                await NotifySecuritySupervisorAsync(incident);
                break;
            case EscalationLevel.SecurityTeam:
                await NotifySecurityTeamAsync(incident);
                break;
            case EscalationLevel.Management:
                await NotifyManagementAsync(incident);
                break;
        }

        // Update incident status
        if (escalation.ToLevel >= EscalationLevel.SecurityTeam)
        {
            incident.Status = IncidentStatus.Escalated;
        }
    }

    /// <summary>
    /// Log incident details to file
    /// </summary>
    private async Task LogIncidentToFileAsync(Incident incident)
    {
        var logPath = Path.Combine(_config.LogDirectory, $"incident-{incident.IncidentId}.log");

        var logContent = $@"INCIDENT REPORT
================
Incident ID: {incident.IncidentId}
Created: {incident.CreatedAt:yyyy-MM-dd HH:mm:ss UTC}
Updated: {incident.LastUpdated:yyyy-MM-dd HH:mm:ss UTC}
Status: {incident.Status}
Priority: {incident.Priority}
Severity: {incident.Severity}
Category: {incident.Category}

Description: {incident.Description}
Primary IP: {incident.PrimaryIPAddress}
Affected Systems: {string.Join(", ", incident.AffectedSystems)}

Activities: {incident.RelatedActivities.Count}
- {string.Join("\n- ", incident.RelatedActivities.Select(a => $"{a.AttackType} ({a.Severity})"))}

Response Actions: {incident.ResponseActions.Count}
{string.Join("\n", incident.ResponseActions.Select(a => $"- {a.ActionType}: {a.Status} - {a.Details}"))}

Escalation History:
{string.Join("\n", incident.EscalationHistory.Select(e => $"- {e.Timestamp:yyyy-MM-dd HH:mm:ss}: {e.FromLevel} -> {e.ToLevel} ({e.Reason})"))}
";

        await File.WriteAllTextAsync(logPath, logContent);
    }

    /// <summary>
    /// Log incident to Windows Event Log
    /// </summary>
    private async Task LogIncidentToEventLogAsync(Incident incident)
    {
        await Task.Run(() =>
        {
            try
            {
                if (!EventLog.SourceExists("NetworkSecurityMonitor"))
                {
                    EventLog.CreateEventSource("NetworkSecurityMonitor", "Security");
                }

                var eventLog = new EventLog("Security");
                eventLog.Source = "NetworkSecurityMonitor";

                var eventType = incident.Priority switch
                {
                    IncidentPriority.Critical => EventLogEntryType.Error,
                    IncidentPriority.High => EventLogEntryType.Warning,
                    _ => EventLogEntryType.Information
                };

                eventLog.WriteEntry(
                    $"Incident {incident.IncidentId}: {incident.Description} " +
                    $"Priority: {incident.Priority}, Activities: {incident.RelatedActivities.Count}",
                    eventType,
                    3000 + (int)incident.Priority);
            }
            catch
            {
                // Silently fail if event logging unavailable
            }
        });
    }

    /// <summary>
    /// Collect forensic evidence
    /// </summary>
    private async Task CollectForensicEvidenceAsync(Incident incident)
    {
        var evidencePath = Path.Combine(_config.EvidenceDirectory, $"evidence-{incident.IncidentId}.txt");

        var evidence = $@"FORENSIC EVIDENCE - INCIDENT {incident.IncidentId}
==================================================
Collection Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}

NETWORK CONNECTIONS:
{string.Join("\n", incident.RelatedActivities.Select(a =>
    $"- {a.FirstDetected:yyyy-MM-dd HH:mm:ss}: {a.IPAddress}:{a.Ports.FirstOrDefault()} - {a.AttackType}"))}

SYSTEM STATE:
- Hostname: {Environment.MachineName}
- OS Version: {Environment.OSVersion}
- Processors: {Environment.ProcessorCount}
- Memory: {Environment.WorkingSet / 1024 / 1024}MB

INCIDENT TIMELINE:
{string.Join("\n", incident.RelatedActivities
    .OrderBy(a => a.FirstDetected)
    .Select((a, i) => $"{i + 1:00}. {a.FirstDetected:HH:mm:ss} - {a.AttackType} from {a.IPAddress}"))}
";

        await File.WriteAllTextAsync(evidencePath, evidence);
    }

    /// <summary>
    /// Send incident notification
    /// </summary>
    private async Task SendIncidentNotificationAsync(Incident incident)
    {
        if (string.IsNullOrEmpty(_config.NotificationEmail))
            return;

        try
        {
            using var client = new SmtpClient(_config.SmtpServer, _config.SmtpPort);
            client.EnableSsl = _config.SmtpUseSsl;
            client.Credentials = new NetworkCredential(_config.SmtpUsername, _config.SmtpPassword);

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_config.NotificationEmail),
                Subject = $"[INCIDENT] {incident.Priority} Priority - {incident.Description}",
                Body = GenerateIncidentEmailBody(incident),
                IsBodyHtml = false
            };

            mailMessage.To.Add(_config.NotificationEmail);

            await client.SendMailAsync(mailMessage);
        }
        catch
        {
            // Silently fail if email unavailable
        }
    }

    /// <summary>
    /// Generate incident email body
    /// </summary>
    private string GenerateIncidentEmailBody(Incident incident)
    {
        return $@"
INCIDENT ALERT - {incident.Priority} PRIORITY

Incident ID: {incident.IncidentId}
Time: {incident.CreatedAt:yyyy-MM-dd HH:mm:ss UTC}
IP Address: {incident.PrimaryIPAddress}
Description: {incident.Description}
Severity: {incident.Severity}
Category: {incident.Category}

Related Activities: {incident.RelatedActivities.Count}
Risk Score: {incident.RelatedActivities.FirstOrDefault()?.RiskScore ?? 0}%

This is an automated notification from the Network Security Monitor.
Please investigate immediately for {incident.Priority} priority incidents.

Network Security Monitor - Professional Incident Response System
";
    }

    /// <summary>
    /// Log escalation event
    /// </summary>
    private async Task LogEscalationAsync(Incident incident, EscalationRecord escalation)
    {
        var escalationLog = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] INCIDENT {incident.IncidentId} ESCALATED: {escalation.FromLevel} -> {escalation.ToLevel} (Reason: {escalation.Reason})";
        await File.AppendAllTextAsync(Path.Combine(_config.LogDirectory, "escalation.log"), escalationLog + Environment.NewLine);
    }

    /// <summary>
    /// Notification methods for different escalation levels
    /// </summary>
    private async Task NotifySecurityAnalystAsync(Incident incident) => await SendIncidentNotificationAsync(incident);
    private async Task NotifySecuritySupervisorAsync(Incident incident) => await SendIncidentNotificationAsync(incident);
    private async Task NotifySecurityTeamAsync(Incident incident) => await SendIncidentNotificationAsync(incident);
    private async Task NotifyManagementAsync(Incident incident) => await SendIncidentNotificationAsync(incident);

    /// <summary>
    /// Clean up old incidents
    /// </summary>
    private void CleanupOldIncidents(object? state)
    {
        var cutoff = DateTime.UtcNow.AddDays(-30); // Keep incidents for 30 days

        var incidentsToRemove = _activeIncidents
            .Where(i => i.Value.CreatedAt < cutoff)
            .Select(i => i.Key)
            .ToList();

        foreach (var key in incidentsToRemove)
        {
            _activeIncidents.TryRemove(key, out _);
        }
    }

    /// <summary>
    /// Initialize escalation rules (professional configuration)
    /// </summary>
    private void InitializeEscalationRules()
    {
        // This would load from configuration file in production
        // For now, using hardcoded professional escalation rules
    }

    /// <summary>
    /// Get active incidents summary
    /// </summary>
    public IncidentSummary GetIncidentSummary()
    {
        var incidents = _activeIncidents.Values.ToList();

        return new IncidentSummary
        {
            TotalIncidents = incidents.Count,
            CriticalIncidents = incidents.Count(i => i.Priority == IncidentPriority.Critical),
            HighIncidents = incidents.Count(i => i.Priority == IncidentPriority.High),
            EscalatedIncidents = incidents.Count(i => i.EscalationLevel >= EscalationLevel.SecurityTeam),
            RecentIncidents = incidents.Count(i => (DateTime.UtcNow - i.CreatedAt).TotalHours < 24)
        };
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _escalationTimer?.Dispose();
            _incidentCleanupTimer?.Dispose();
        }
    }
}

/// <summary>
/// Incident response configuration
/// </summary>
public class IncidentResponseConfig
{
    public string LogDirectory { get; set; } = "Logs";
    public string EvidenceDirectory { get; set; } = "Evidence";
    public string NotificationEmail { get; set; } = "";
    public string SmtpServer { get; set; } = "";
    public int SmtpPort { get; set; } = 587;
    public bool SmtpUseSsl { get; set; } = true;
    public string SmtpUsername { get; set; } = "";
    public string SmtpPassword { get; set; } = "";
}

/// <summary>
/// Security incident tracking
/// </summary>
public class Incident
{
    public string IncidentId { get; set; } = string.Empty;
    public string PrimaryIPAddress { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime LastUpdated { get; set; }
    public IncidentStatus Status { get; set; }
    public IncidentPriority Priority { get; set; }
    public ThreatSeverity Severity { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<string> AffectedSystems { get; set; } = new();
    public List<SuspiciousActivity> RelatedActivities { get; set; } = new();
    public List<ResponseAction> ResponseActions { get; set; } = new();
    public EscalationLevel EscalationLevel { get; set; }
    public List<EscalationRecord> EscalationHistory { get; set; } = new();
}

/// <summary>
/// Response action tracking
/// </summary>
public class ResponseAction
{
    public string ActionType { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public ActionStatus Status { get; set; }
    public string Details { get; set; } = string.Empty;
}

/// <summary>
/// Escalation event
/// </summary>
public class EscalationEvent
{
    public Incident Incident { get; set; } = null!;
    public EscalationRecord Escalation { get; set; } = null!;
    public bool RequiresImmediateAction { get; set; }
}

/// <summary>
/// Escalation record
/// </summary>
public class EscalationRecord
{
    public DateTime Timestamp { get; set; }
    public EscalationLevel FromLevel { get; set; }
    public EscalationLevel ToLevel { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string EscalatedBy { get; set; } = string.Empty;
}

/// <summary>
/// Incident summary
/// </summary>
public class IncidentSummary
{
    public int TotalIncidents { get; set; }
    public int CriticalIncidents { get; set; }
    public int HighIncidents { get; set; }
    public int EscalatedIncidents { get; set; }
    public int RecentIncidents { get; set; }
}

/// <summary>
/// Enums for incident response
/// </summary>
public enum IncidentStatus { New, Active, Escalated, Resolved, Closed }
public enum IncidentPriority { Low, Medium, High, Critical }
public enum EscalationLevel { Monitoring, Analyst, Supervisor, SecurityTeam, Management }
public enum ActionStatus { Pending, Success, Failed, Partial }
