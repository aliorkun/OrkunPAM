using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Grpc.Session;
using OrkunPAM.Persistence;

namespace OrkunPAM.Grpc.Services;

/// <summary>
/// gRPC service for proxy session management.
/// Thin wrapper — delegates to DbContext and MemoryCache (same stores used by REST endpoints).
/// </summary>
public sealed class SessionGrpcService : SessionService.SessionServiceBase
{
    private readonly OrkunPamDbContext _db;
    private readonly IMemoryCache _cache;
    private readonly Persistence.Services.IAuditService _audit;
    private readonly ILogger<SessionGrpcService> _logger;

    public SessionGrpcService(
        OrkunPamDbContext db,
        IMemoryCache cache,
        Persistence.Services.IAuditService audit,
        ILogger<SessionGrpcService> logger)
    {
        _db = db;
        _cache = cache;
        _audit = audit;
        _logger = logger;
    }

    public override async Task<SessionInfo> ValidateSessionToken(
        TokenRequest request, ServerCallContext context)
    {
        var cacheKey = $"rdp:token:{request.SessionToken}";

        // Try memory cache first (RDP tokens are stored here by SessionEndpoints)
        if (_cache.TryGetValue(cacheKey, out object? cached) && cached != null)
        {
            // Single-use: remove immediately
            _cache.Remove(cacheKey);

            // Use reflection-free dynamic: the cached type is an internal record in SessionEndpoints.
            // We access it via the well-known property names.
            var t = cached.GetType();
            var sessionId = t.GetProperty("SessionId")?.GetValue(cached)?.ToString() ?? "";
            var targetIp = t.GetProperty("TargetIp")?.GetValue(cached)?.ToString() ?? "";
            var targetPort = (int)(t.GetProperty("TargetPort")?.GetValue(cached) ?? 0);
            var targetUsername = t.GetProperty("TargetUsername")?.GetValue(cached)?.ToString() ?? "";
            var targetPasswordBytes = t.GetProperty("TargetPasswordBytes")?.GetValue(cached) as byte[] ?? [];
            var targetDomain = t.GetProperty("TargetDomain")?.GetValue(cached)?.ToString() ?? "";

            _logger.LogInformation("gRPC: Session token validated for session {SessionId}", sessionId);

            return new SessionInfo
            {
                SessionId = sessionId,
                TargetIp = targetIp,
                TargetPort = targetPort,
                TargetUsername = targetUsername,
                TargetPassword = Google.Protobuf.ByteString.CopyFrom(targetPasswordBytes),
                TargetDomain = targetDomain,
                IdleTimeoutMinutes = 30,
                RecordingEnabled = true
            };
        }

        // Fallback: look up session in database
        var session = await _db.Set<Domain.Entities.Session.ProxySession>()
            .FirstOrDefaultAsync(s => s.Status == SessionStatus.Active,
                context.CancellationToken);

        if (session == null)
        {
            throw new RpcException(new Status(StatusCode.NotFound,
                "Session token not found or expired"));
        }

        _logger.LogInformation("gRPC: Session validated from DB for session {SessionId}", session.Id);

        return new SessionInfo
        {
            SessionId = session.Id.ToString(),
            TargetIp = session.TargetIpAddress ?? "",
            TargetPort = session.TargetPort ?? 0,
            IdleTimeoutMinutes = 30,
            RecordingEnabled = true
        };
    }

    public override async Task<Empty> ReportSessionEnd(
        SessionEndRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.SessionId, out var sessionId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid session_id format"));

        var session = await _db.Set<Domain.Entities.Session.ProxySession>()
            .FindAsync([sessionId], context.CancellationToken);

        if (session != null)
        {
            session.Status = SessionStatus.Completed;
            session.EndedAtUtc = request.EndedAt?.ToDateTime() ?? DateTime.UtcNow;
            session.DurationSeconds = (int)(session.EndedAtUtc.Value - session.StartedAtUtc).TotalSeconds;
            await _db.SaveChangesAsync(context.CancellationToken);

            _logger.LogInformation("gRPC: Session {SessionId} ended. Reason={Reason}, Bytes={Bytes}, Commands={Cmds}",
                request.SessionId, request.Reason, request.BytesTransferred, request.CommandsExecuted);
        }

        await _audit.LogAsync("Session", "SessionEnd", null, null, null,
            "Session", request.SessionId,
            new { request.Reason, request.BytesTransferred, request.CommandsExecuted },
            ct: context.CancellationToken);

        return new Empty();
    }

    public override async Task<Empty> ReportSessionActivity(
        ActivityRequest request, ServerCallContext context)
    {
        _logger.LogDebug("gRPC: Session {SessionId} activity: {Type}",
            request.SessionId, request.ActivityType);

        await _audit.LogAsync("Session", $"Activity:{request.ActivityType}", null, null,
            request.SourceIp, "Session", request.SessionId,
            new { request.ActivityType, request.Data },
            ct: context.CancellationToken);

        return new Empty();
    }
}
