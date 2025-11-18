namespace NetworkSecurityMonitor.Services;

// ADDED: Background monitoring service for GUI version
public class NetworkMonitoringBackgroundService
{
    private readonly NetworkMonitorService _networkMonitor;
    private readonly ThreatDetectionService _threatDetection;
    private CancellationTokenSource? _cancellationTokenSource;

    public NetworkMonitoringBackgroundService(
        NetworkMonitorService networkMonitor,
        ThreatDetectionService threatDetection)
    {
        _networkMonitor = networkMonitor;
        _threatDetection = threatDetection;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        await ExecuteAsync(_cancellationTokenSource.Token);
    }

    public void Stop()
    {
        _cancellationTokenSource?.Cancel();
    }

    private async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Console.WriteLine("[INFO] Background monitoring service started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // ADDED: Get current threats and log them
                var threats = _threatDetection.GetAllThreats();

                if (threats.Any())
                {
                    var recentThreats = threats.Where(t =>
                        (DateTime.UtcNow - t.LastDetected).TotalMinutes < 5).ToList();

                    if (recentThreats.Any())
                    {
                        Console.WriteLine($"[MONITOR] Active threats: {recentThreats.Count}");
                        foreach (var threat in recentThreats.Take(5))
                        {
                            Console.WriteLine($"  - {threat.IPAddress}: {threat.AttackType} (Risk: {threat.RiskScore}%)");
                        }
                    }
                }

                // ADDED: Wait before next check
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Background service error: {ex.Message}");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }
}

