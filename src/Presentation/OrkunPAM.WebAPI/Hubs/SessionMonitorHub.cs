using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Hubs;

/// <summary>
/// SignalR hub for admin session live monitoring (#125).
/// Clients in the "monitor" group receive real-time session events.
/// Admins can also terminate sessions directly via hub without a separate HTTP call.
/// </summary>
[Authorize]
public sealed class SessionMonitorHub : Hub
{
    private readonly OrkunPamDbContext _db;
    private readonly ILogger<SessionMonitorHub> _log;

    public SessionMonitorHub(OrkunPamDbContext db, ILogger<SessionMonitorHub> log)
    {
        _db = db;
        _log = log;
    }

    public override async Task OnConnectedAsync()
    {
        if (IsMonitor())
            await Groups.AddToGroupAsync(Context.ConnectionId, "monitor");
        await base.OnConnectedAsync();
    }

    /// <summary>Terminate an active session via hub (avoids a separate HTTP round-trip from monitor UI).</summary>
    public async Task TerminateSession(string sessionId, string reason)
    {
        if (!IsAdmin()) { await Clients.Caller.SendAsync("Error", "Insufficient permissions"); return; }
        if (!Guid.TryParse(sessionId, out var id)) { await Clients.Caller.SendAsync("Error", "Invalid session ID"); return; }

        var adminIdStr = Context.User?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (adminIdStr == null || !Guid.TryParse(adminIdStr, out var adminId))
        { await Clients.Caller.SendAsync("Error", "Unauthenticated"); return; }

        var session = await _db.ProxySessions.FindAsync(id);
        if (session == null) { await Clients.Caller.SendAsync("Error", "Session not found"); return; }
        if (session.Status != SessionStatus.Active) { await Clients.Caller.SendAsync("Error", "Session not active"); return; }

        session.Terminate(adminId, reason);
        await _db.SaveChangesAsync();
        _log.LogWarning("Session {SessionId} terminated via hub by admin {AdminId}: {Reason}", id, adminId, reason);

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
