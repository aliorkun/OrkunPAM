using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SessionEndpoints
{
    public static void MapSessionEndpoints(this WebApplication app)
    {
        var sessions = app.MapGroup("/api/v1/sessions").WithTags("Sessions").RequireAuthorization();

        // === Connect (request new session) ===
        sessions.MapPost("/ssh/connect", async (ConnectRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, ILogger<Program> logger, HttpContext context) =>
        {
            return await CreateSession(req, SessionType.Ssh, 2222, db, vault, logger, context);
        });

        sessions.MapPost("/rdp/connect", async (ConnectRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, ILogger<Program> logger, HttpContext context) =>
        {
            return await CreateSession(req, SessionType.Rdp, 3389, db, vault, logger, context);
        });

        sessions.MapPost("/vnc/connect", async (ConnectRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, ILogger<Program> logger, HttpContext context) =>
        {
            return await CreateSession(req, SessionType.Vnc, 5900, db, vault, logger, context);
        });

        sessions.MapPost("/sql/connect", async (ConnectRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, ILogger<Program> logger, HttpContext context) =>
        {
            return await CreateSession(req, SessionType.Sql, 1433, db, vault, logger, context);
        });

        // === List Sessions ===
        sessions.MapGet("/", async (OrkunPamDbContext db, string? status, Guid? userId,
            SessionType? type, DateTime? from, DateTime? to, int page = 1, int pageSize = 50) =>
        {
            var query = db.ProxySessions.AsQueryable();

            if (!string.IsNullOrEmpty(status) && Enum.TryParse<SessionStatus>(status, true, out var s))
                query = query.Where(ps => ps.Status == s);
            if (userId.HasValue) query = query.Where(ps => ps.UserId == userId.Value);
            if (type.HasValue) query = query.Where(ps => ps.SessionType == type.Value);
            if (from.HasValue) query = query.Where(ps => ps.StartedAtUtc >= from.Value);
            if (to.HasValue) query = query.Where(ps => ps.StartedAtUtc <= to.Value);

            var total = await query.CountAsync();
            var list = await query
                .OrderByDescending(ps => ps.StartedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(ps => new
                {
                    ps.Id, ps.UserId, ps.DeviceId, ps.CredentialId,
                    Type = ps.SessionType.ToString(),
                    Status = ps.Status.ToString(),
                    ps.StartedAtUtc, ps.EndedAtUtc, ps.DurationSeconds,
                    ps.ClientIpAddress, ps.TargetIpAddress, ps.TargetPort,
                    ps.RiskScore, ps.HasKeystrokeLog, ps.HasOcrData,
                    ps.Reason, ps.TicketNumber, ps.Tags
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        // === Active Sessions ===
        sessions.MapGet("/active", async (OrkunPamDbContext db) =>
        {
            var active = await db.ProxySessions
                .Where(ps => ps.Status == SessionStatus.Active)
                .Select(ps => new
                {
                    ps.Id, ps.UserId, ps.DeviceId,
                    Type = ps.SessionType.ToString(),
                    ps.StartedAtUtc,
                    DurationMinutes = (int)(DateTime.UtcNow - ps.StartedAtUtc).TotalMinutes,
                    ps.ClientIpAddress, ps.TargetIpAddress, ps.TargetPort,
                    ps.RiskScore, ps.Reason
                }).ToListAsync();

            return Results.Ok(new { success = true, data = active, meta = new { activeCount = active.Count } });
        });

        // === Session Detail ===
        sessions.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var ps = await db.ProxySessions.FindAsync(id);
            if (ps == null) return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    ps.Id, ps.UserId, ps.DeviceId, ps.CredentialId, ps.SessionPolicyId,
                    Type = ps.SessionType.ToString(),
                    Status = ps.Status.ToString(),
                    ps.StartedAtUtc, ps.EndedAtUtc, ps.DurationSeconds,
                    ps.ClientIpAddress, ps.TargetIpAddress, ps.TargetPort,
                    ps.TerminatedBy, ps.TerminationReason,
                    ps.Reason, ps.TicketNumber,
                    ps.RecordingPath, ps.RecordingSizeBytes,
                    ps.HasKeystrokeLog, ps.HasOcrData,
                    ps.RiskScore, ps.Tags
                }
            });
        });

        // === Terminate Session ===
        sessions.MapPost("/{id:guid}/terminate", async (Guid id, TerminateSessionRequest req,
            OrkunPamDbContext db, ILogger<Program> logger, HttpContext context) =>
        {
            var adminIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (adminIdStr == null || !Guid.TryParse(adminIdStr, out var adminId))
                return Results.Unauthorized();

            var ps = await db.ProxySessions.FindAsync(id);
            if (ps == null) return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            if (ps.Status != SessionStatus.Active)
                return Results.Conflict(new { success = false, errors = new[] { $"Session is not active (status: {ps.Status})" } });

            ps.Terminate(adminId, req.Reason);
            await db.SaveChangesAsync();

            logger.LogWarning("Session {SessionId} terminated by admin {AdminId}: {Reason}",
                id, adminId, req.Reason);

            return Results.Ok(new { success = true, message = "Session terminated" });
        }).RequireAuthorization();

        // === Command Logs ===
        sessions.MapGet("/{id:guid}/commands", async (Guid id, OrkunPamDbContext db, int page = 1, int pageSize = 100) =>
        {
            var total = await db.CommandLogs.Where(cl => cl.SessionId == id).CountAsync();
            var commands = await db.CommandLogs
                .Where(cl => cl.SessionId == id)
                .OrderBy(cl => cl.Timestamp)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(cl => new
                {
                    cl.Id, cl.Timestamp, cl.Command, cl.RiskScore, cl.WasBlocked, cl.BlockReason
                }).ToListAsync();

            return Results.Ok(new { success = true, data = commands, meta = new { page, pageSize, totalCount = total } });
        });

        // === Session Policies ===
        var policies = app.MapGroup("/api/v1/session-policies").WithTags("Sessions");

        policies.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.SessionPolicies
                .Select(p => new
                {
                    p.Id, p.Name, p.MaxDurationMinutes, p.IdleTimeoutMinutes,
                    p.AllowClipboard, p.AllowFileTransfer, p.AllowDriveMapping,
                    p.RecordingEnabled, p.KeystrokeLogging, p.EnableWatermark,
                    p.RequireReason, p.RequireTicket, p.TwoPersonRule,
                    CommandFilter = p.CommandFilterMode.ToString()
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        policies.MapPost("/", async (CreateSessionPolicyRequest req, OrkunPamDbContext db) =>
        {
            var policy = new SessionPolicy
            {
                Name = req.Name,
                MaxDurationMinutes = req.MaxDurationMinutes,
                IdleTimeoutMinutes = req.IdleTimeoutMinutes,
                AllowClipboard = req.AllowClipboard,
                AllowFileTransfer = req.AllowFileTransfer,
                AllowDriveMapping = req.AllowDriveMapping,
                AllowPrinting = req.AllowPrinting,
                RecordingEnabled = req.RecordingEnabled ?? true,
                KeystrokeLogging = req.KeystrokeLogging ?? true,
                RequireReason = req.RequireReason,
                RequireTicket = req.RequireTicket,
                TwoPersonRule = req.TwoPersonRule,
                EnableWatermark = req.EnableWatermark,
                CommandFilterMode = req.CommandFilterMode ?? CommandFilterMode.None,
                CommandFilterRulesJson = req.CommandFilterRulesJson
            };

            db.SessionPolicies.Add(policy);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/session-policies/{policy.Id}",
                new { success = true, data = new { policy.Id, policy.Name } });
        });

        policies.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var p = await db.SessionPolicies.FindAsync(id);
            if (p == null) return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });
            return Results.Ok(new { success = true, data = p });
        });

        policies.MapPut("/{id:guid}", async (Guid id, UpdateSessionPolicyRequest req, OrkunPamDbContext db) =>
        {
            var p = await db.SessionPolicies.FindAsync(id);
            if (p == null) return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            if (req.Name != null) p.Name = req.Name;
            if (req.MaxDurationMinutes.HasValue) p.MaxDurationMinutes = req.MaxDurationMinutes;
            if (req.IdleTimeoutMinutes.HasValue) p.IdleTimeoutMinutes = req.IdleTimeoutMinutes;
            if (req.AllowClipboard.HasValue) p.AllowClipboard = req.AllowClipboard.Value;
            if (req.AllowFileTransfer.HasValue) p.AllowFileTransfer = req.AllowFileTransfer.Value;
            if (req.AllowDriveMapping.HasValue) p.AllowDriveMapping = req.AllowDriveMapping.Value;
            if (req.RecordingEnabled.HasValue) p.RecordingEnabled = req.RecordingEnabled.Value;
            if (req.KeystrokeLogging.HasValue) p.KeystrokeLogging = req.KeystrokeLogging.Value;
            if (req.EnableWatermark.HasValue) p.EnableWatermark = req.EnableWatermark.Value;
            if (req.CommandFilterMode.HasValue) p.CommandFilterMode = req.CommandFilterMode.Value;
            if (req.CommandFilterRulesJson != null) p.CommandFilterRulesJson = req.CommandFilterRulesJson;

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });
    }

    private static async Task<IResult> CreateSession(ConnectRequest req, SessionType type, int defaultPort,
        OrkunPamDbContext db, IVaultEncryptionService vault, ILogger<Program> logger, HttpContext context)
    {
        var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
            return Results.Unauthorized();

        // Validate device
        var device = await db.Devices.FindAsync(req.DeviceId);
        if (device == null)
            return Results.NotFound(new { success = false, errors = new[] { $"Device not found: {req.DeviceId}" } });

        // Validate credential
        var cred = await db.Credentials.FindAsync(req.CredentialId);
        if (cred == null)
            return Results.NotFound(new { success = false, errors = new[] { $"Credential not found: {req.CredentialId}" } });

        // Decrypt credential for proxy (in real implementation, this goes to proxy via gRPC)
        string? password = null;
        if (cred.PasswordEnc != null)
        {
            var decResult = vault.DecryptString(cred.PasswordEnc);
            if (decResult.IsFailure)
            {
                logger.LogError("Session connect failed: cannot decrypt credential {CredId} for device {DeviceId}: {Error}",
                    req.CredentialId, req.DeviceId, decResult.Error.Message);
                return Results.Problem("Credential decryption failed. Check server logs.");
            }
            password = decResult.Value;
        }

        // Generate session token
        var sessionToken = Guid.NewGuid().ToString("N");

        // Create session record
        var session = new ProxySession
        {
            UserId = userId,
            DeviceId = req.DeviceId,
            CredentialId = req.CredentialId,
            SessionPolicyId = req.SessionPolicyId,
            SessionType = type,
            ClientIpAddress = req.ClientIp,
            TargetIpAddress = device.IpAddress,
            TargetPort = device.ConnectionPort ?? defaultPort,
            Reason = req.Reason,
            TicketNumber = req.TicketNumber
        };

        db.ProxySessions.Add(session);
        await db.SaveChangesAsync();

        logger.LogInformation("Session {SessionId} ({Type}) started: user {UserId} → {Target}:{Port} via credential '{CredName}'",
            session.Id, type, userId, device.IpAddress ?? device.Hostname, session.TargetPort, cred.Name);

        return Results.Ok(new
        {
            success = true,
            data = new
            {
                sessionId = session.Id,
                sessionToken,
                type = type.ToString(),
                target = new
                {
                    hostname = device.Hostname,
                    ip = device.IpAddress,
                    port = session.TargetPort
                },
                proxy = new
                {
                    host = "localhost", // In production: PAM proxy hostname
                    port = type switch
                    {
                        SessionType.Ssh => 2222,
                        SessionType.Rdp => 3389,
                        SessionType.Vnc => 5900,
                        SessionType.Sql => 1433,
                        _ => defaultPort
                    }
                },
                credential = new { cred.Username }, // Password NEVER sent to client
                message = $"Connect your {type} client to proxy. Credential injected server-side."
            }
        });
    }
}

public record ConnectRequest(Guid DeviceId, Guid CredentialId,
    Guid? SessionPolicyId, string? Reason, string? TicketNumber, string? ClientIp);
public record TerminateSessionRequest(string Reason);
public record CreateSessionPolicyRequest(string Name, int? MaxDurationMinutes, int? IdleTimeoutMinutes,
    bool AllowClipboard, bool AllowFileTransfer, bool AllowDriveMapping, bool AllowPrinting,
    bool? RecordingEnabled, bool? KeystrokeLogging, bool RequireReason, bool RequireTicket,
    bool TwoPersonRule, bool EnableWatermark, CommandFilterMode? CommandFilterMode, string? CommandFilterRulesJson);
public record UpdateSessionPolicyRequest(string? Name, int? MaxDurationMinutes, int? IdleTimeoutMinutes,
    bool? AllowClipboard, bool? AllowFileTransfer, bool? AllowDriveMapping,
    bool? RecordingEnabled, bool? KeystrokeLogging, bool? EnableWatermark,
    CommandFilterMode? CommandFilterMode, string? CommandFilterRulesJson);
