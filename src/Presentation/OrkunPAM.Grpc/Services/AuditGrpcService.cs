using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Grpc.Audit;

namespace OrkunPAM.Grpc.Services;

/// <summary>
/// gRPC service for audit logging from proxy services.
/// Thin wrapper around IAuditService — no business logic duplication.
/// </summary>
public sealed class AuditGrpcService : OrkunPAM.Grpc.Audit.AuditService.AuditServiceBase
{
    private readonly Persistence.Services.IAuditService _audit;
    private readonly ILogger<AuditGrpcService> _logger;

    public AuditGrpcService(
        Persistence.Services.IAuditService audit,
        ILogger<AuditGrpcService> logger)
    {
        _audit = audit;
        _logger = logger;
    }

    public override async Task<Empty> LogEvent(
        AuditEventRequest request, ServerCallContext context)
    {
        Guid? actorId = Guid.TryParse(request.ActorUserId, out var parsed) ? parsed : null;

        var outcome = request.Outcome?.ToLowerInvariant() switch
        {
            "failure" => AuditOutcome.Failure,
            "denied" => AuditOutcome.Denied,
            _ => AuditOutcome.Success
        };

        await _audit.LogAsync(
            request.Category,
            request.EventType,
            actorId,
            request.ActorUsername,
            request.ActorIp,
            request.TargetType,
            request.TargetId,
            request.DetailsJson,  // Stored as-is; IAuditService serializes objects, string passes through
            outcome,
            context.CancellationToken);

        _logger.LogDebug("gRPC: Audit event logged: {Category}/{EventType} by {Actor}",
            request.Category, request.EventType, request.ActorUsername);

        return new Empty();
    }

    public override async Task<Empty> LogCommand(
        CommandLogRequest request, ServerCallContext context)
    {
        await _audit.LogAsync(
            "Session",
            "CommandExecuted",
            null,
            null,
            null,
            "Session",
            request.SessionId,
            new
            {
                request.Command,
                Output = request.Output.Length > 4096
                    ? request.Output[..4096] + "...[truncated]"
                    : request.Output,
                request.IsDangerous,
                request.RiskLevel
            },
            AuditOutcome.Success,
            context.CancellationToken);

        if (request.IsDangerous)
        {
            _logger.LogWarning("gRPC: Dangerous command in session {SessionId}: {Command} (risk={Risk})",
                request.SessionId, request.Command, request.RiskLevel);
        }

        return new Empty();
    }
}
