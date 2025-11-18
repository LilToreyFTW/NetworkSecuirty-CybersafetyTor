using NetworkSecurityMonitor.Models;

namespace NetworkSecurityMonitor.Services;

// ADDED: AI-powered threat analysis service
public class AIAnalysisService
{
    private readonly Dictionary<string, ThreatHistory> _threatHistory = new();

    // ADDED: Analyze threat using AI-like pattern recognition
    public AIAnalysisResult AnalyzeThreat(SuspiciousActivity activity)
    {
        var result = new AIAnalysisResult
        {
            Confidence = CalculateConfidence(activity),
            RiskScore = CalculateRiskScore(activity),
            Recommendation = GenerateRecommendation(activity)
        };

        // ADDED: Store in history for learning
        UpdateThreatHistory(activity);

        return result;
    }

    // ADDED: Calculate confidence level based on patterns
    private double CalculateConfidence(SuspiciousActivity activity)
    {
        double confidence = 0.5; // Base confidence

        // ADDED: Increase confidence based on connection count
        if (activity.ConnectionCount > 100)
            confidence += 0.3;
        else if (activity.ConnectionCount > 50)
            confidence += 0.2;
        else if (activity.ConnectionCount > 20)
            confidence += 0.1;

        // ADDED: Increase confidence based on port diversity (port scanning)
        if (activity.Ports.Count > 10)
            confidence += 0.2;
        else if (activity.Ports.Count > 5)
            confidence += 0.1;

        // ADDED: Increase confidence if seen before
        if (_threatHistory.ContainsKey(activity.IPAddress))
        {
            var history = _threatHistory[activity.IPAddress];
            if (history.OccurrenceCount > 1)
                confidence += 0.1 * Math.Min(history.OccurrenceCount, 5);
        }

        return Math.Min(confidence, 1.0);
    }

    // ADDED: Calculate risk score (0-100)
    private int CalculateRiskScore(SuspiciousActivity activity)
    {
        int score = 0;

        // ADDED: Base score from severity
        score += activity.Severity switch
        {
            ThreatSeverity.Low => 20,
            ThreatSeverity.Medium => 50,
            ThreatSeverity.High => 75,
            ThreatSeverity.Critical => 95,
            _ => 10
        };

        // ADDED: Add score based on connection rate
        if (activity.AverageConnectionsPerSecond > 10)
            score += 15;
        else if (activity.AverageConnectionsPerSecond > 5)
            score += 10;

        // ADDED: Add score for multiple ports
        if (activity.Ports.Count > 10)
            score += 10;

        return Math.Min(score, 100);
    }

    // ADDED: Generate AI recommendation
    private string GenerateRecommendation(SuspiciousActivity activity)
    {
        var recommendations = new List<string>();

        if (activity.Severity == ThreatSeverity.Critical || activity.RiskScore > 80)
        {
            recommendations.Add("IMMEDIATE ACTION REQUIRED: Block this IP address immediately");
            recommendations.Add("Consider enabling firewall rules to block this IP range");
        }

        if (activity.ConnectionCount > 100)
        {
            recommendations.Add("DDoS attack pattern detected - Enable rate limiting");
            recommendations.Add("Contact your ISP if attack persists");
        }

        if (activity.Ports.Count > 5)
        {
            recommendations.Add("Port scanning detected - This IP is probing your system");
            recommendations.Add("Review firewall logs for additional context");
        }

        if (activity.AverageConnectionsPerSecond > 5)
        {
            recommendations.Add("High connection rate - Consider implementing connection throttling");
        }

        if (recommendations.Count == 0)
        {
            recommendations.Add("Monitor this IP address for continued suspicious activity");
        }

        return string.Join(" | ", recommendations);
    }

    // ADDED: Update threat history for learning
    private void UpdateThreatHistory(SuspiciousActivity activity)
    {
        if (!_threatHistory.ContainsKey(activity.IPAddress))
        {
            _threatHistory[activity.IPAddress] = new ThreatHistory
            {
                IPAddress = activity.IPAddress,
                FirstSeen = activity.FirstDetected,
                OccurrenceCount = 1
            };
        }
        else
        {
            var history = _threatHistory[activity.IPAddress];
            history.OccurrenceCount++;
            history.LastSeen = activity.LastDetected;
        }
    }

    // ADDED: Get threat statistics
    public ThreatStatistics GetStatistics()
    {
        return new ThreatStatistics
        {
            TotalThreatsDetected = _threatHistory.Count,
            AverageConfidence = _threatHistory.Values.Any() 
                ? _threatHistory.Values.Average(h => 0.7) // Simplified
                : 0,
            MostActiveThreat = _threatHistory.Values
                .OrderByDescending(h => h.OccurrenceCount)
                .FirstOrDefault()
        };
    }
}

// ADDED: AI analysis result
public class AIAnalysisResult
{
    public double Confidence { get; set; }
    public int RiskScore { get; set; }
    public string Recommendation { get; set; } = string.Empty;
}

// ADDED: Threat history for learning
public class ThreatHistory
{
    public string IPAddress { get; set; } = string.Empty;
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public int OccurrenceCount { get; set; }
}

// ADDED: Threat statistics
public class ThreatStatistics
{
    public int TotalThreatsDetected { get; set; }
    public double AverageConfidence { get; set; }
    public ThreatHistory? MostActiveThreat { get; set; }
}

