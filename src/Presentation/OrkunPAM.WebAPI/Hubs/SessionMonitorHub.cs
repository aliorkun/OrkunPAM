using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.WebAPI.Hubs;

/// <summary>
/// SignalR hub for admin session live monitoring (#125).
/// Clients in the "monitor" group receive real-time session events.
/// Admins can also terminate sessions directly via hub without a separate HTTP call.
/// </summary>
[Authorize]
public sealed class SessionMonitorHub : Hub
{
    private const int MaxReasonLength = 500;

    private readonly OrkunPamDbContext _db;
    private readonly ILogger<SessionMonitorHub> _log;
    private readonly IEventBus _eventBus;

    public SessionMonitorHub(OrkunPamDbContext db, ILogger<SessionMonitorHub> log, IEventBus eventBus)
    {
        _db = db;
        _log = log;
        _eventBus = eventBus;
    }

    public override async Task OnConnectedAsync()
    {
        if (IsMonitor())
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, "monitor");

            var userId = Context.User?.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = Context.User?.FindFirstValue(ClaimTypes.Name);

            // Audit: who connected to the monitor group and when (fixes #148)
            await _eventBus.PublishAsync(new MonitoringStartedEvent
            {
                ActorUserId = Guid.TryParse(userId, out var uid) ? uid : null,
                ActorUsername = username,
                ConnectionId = Context.ConnectionId
            });
        }
        await base.OnConnectedAsync();
    }

    /// <summary>Terminate an active session via hub (avoids a separate HTTP round-trip from monitor UI).</summary>
    public async Task TerminateSession(string sessionId, string reason)
    {
        if (!IsAdmin()) { await Clients.Caller.SendAsync("Error", "Insufficient permissions"); return; }
        if (!Guid.TryParse(sessionId, out var id)) { await Clients.Caller.SendAsync("Error", "Invalid session ID"); return; }

        // Validate reason length to prevent oversized payloads and DB column overflow (fixes #149)
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > MaxReasonLength)
        {
            await Clients.Caller.SendAsync("Error", $"Reason must be 1-{MaxReasonLength} characters");
            return;
        }
        reason = reason.Trim();

        var adminIdStr = Context.User?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (adminIdStr == null || !Guid.TryParse(adminIdStr, out var adminId))
        { await Clients.Caller.SendAsync("Error", "Unauthenticated"); return; }

        var adminUsername = Context.User?.FindFirstValue(ClaimTypes.Name);

        var session = await _db.ProxySessions.FindAsync(id);
        if (session == null) { await Clients.Caller.SendAsync("Error", "Session not found"); return; }
        if (session.Status != SessionStatus.Active) { await Clients.Caller.SendAsync("Error", "Session not active"); return; }

        session.Terminate(adminId, reason);
        await _db.SaveChangesAsync();

        // Publish to event bus → tamper-proof audit chain (fixes #148)
        await _eventBus.PublishAsync(new SessionTerminatedEvent
        {
            SessionId = id,
            Reason = reason,
            ActorUserId = adminId,
            ActorUsername = adminUsername
        });

        await Clients.Group("monitor").SendAsync("SessionUpdate", new
        {
            sessionId = id,
            eventType = "Terminated",
            reason,
            timestamp = DateTime.UtcNow
        });
    }

    private bool IsAdmin() =>
        Context.User?.IsInRole("GlobalAdmin") == true || Context.User?.IsInRole("SessionAdmin") == true;

    private bool IsMonitor() =>
        IsAdmin() || Context.User?.IsInRole("Auditor") == true;
}
