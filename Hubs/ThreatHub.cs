using Microsoft.AspNetCore.SignalR;
using NetworkSecurityMonitor.Services;
using NetworkSecurityMonitor.Models;

namespace NetworkSecurityMonitor.Hubs;

// ADDED: SignalR hub for real-time threat notifications
public class ThreatHub : Hub
{
    private readonly ThreatDetectionService _threatDetection;

    public ThreatHub(ThreatDetectionService threatDetection)
    {
        _threatDetection = threatDetection;
    }

    // ADDED: Get all current threats
    public async Task<List<SuspiciousActivity>> GetCurrentThreats()
    {
        return _threatDetection.GetAllThreats();
    }

    // ADDED: Client connection handler
    public override async Task OnConnectedAsync()
    {
        await base.OnConnectedAsync();
        Console.WriteLine($"[HUB] Client connected: {Context.ConnectionId}");
        
        // ADDED: Send current threats to newly connected client
        var threats = _threatDetection.GetAllThreats();
        await Clients.Caller.SendAsync("ReceiveThreats", threats);
    }

    // ADDED: Client disconnection handler
    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        Console.WriteLine($"[HUB] Client disconnected: {Context.ConnectionId}");
        await base.OnDisconnectedAsync(exception);
    }
}

// ADDED: Extension to broadcast threats
public static class ThreatHubExtensions
{
    public static async Task BroadcastThreat(this IHubContext<ThreatHub> hub, SuspiciousActivity threat)
    {
        await hub.Clients.All.SendAsync("NewThreatDetected", threat);
    }
}

