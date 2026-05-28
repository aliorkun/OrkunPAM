using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SessionEndpoints
{
    public static void MapSessionEndpoints(this IEndpointRouteBuilder app)
    {
        var sessions = app.MapGroup("/api/v1/sessions").WithTags("Sessions").RequireAuthorization();

        sessions.MapPost("/ssh/connect", async (ConnectRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, ILogger<Program> logger, IMemoryCache cache, HttpContext context) =>
        {
            return await CreateSession(req, SessionType.Ssh, 2222, db, vault, logger, cache, context);
        });

        sessions.MapPost("/rdp/connect", async (ConnectRequest req, OrkunPamDbContext db,
            ILogger<Program> logger, IMemoryCache cache, IConfiguration config, HttpContext context) =>
        {
            return await CreateRdpSession(req, db, logger, cache, config, context);
        });

        // Called by the RDP proxy service to exchange a session token for target credentials.
        // Authenticated via X-Proxy-Secret header (not JWT).
        app.MapPost("/api/v1/sessions/rdp/validate-token",
            async (ValidateRdpTokenRequest req, IMemoryCache cache, IConfiguration config,
                   HttpContext context, OrkunPamDbContext db, IVaultEncryptionService vault,
                   ILogger<Program> logger) =>
        {
            var secret = config["ProxyService:Secret"] ?? "";
            var headerValue = context.Request.Headers["X-Proxy-Secret"].FirstOrDefault() ?? "";
            if (secret.Length < 32 || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.UTF8.GetBytes(secret),
                    System.Text.Encoding.UTF8.GetBytes(headerValue)))
                return Results.Unauthorized();

            if (!cache.TryGetValue($"rdp:token:{req.SessionToken}", out RdpTokenData? info) || info == null)
                return Results.NotFound(new { success = false, errors = new[] { "Session token not found or expired" } });

            // Single-use token: remove from cache immediately after first use
            cache.Remove($"rdp:token:{req.SessionToken}");

            // Credential is decrypted on-demand here; never cached as plaintext
            var rdpCred = await db.Credentials.FindAsync(info.CredentialId);
            if (rdpCred?.PasswordEnc == null)
            {
                logger.LogError("RDP validate-token: credential {CredId} not found for session {SessionId}",
                    info.CredentialId, info.SessionId);
                return Results.Problem("Credential not found");
            }

            var rdpDecResult = vault.Decrypt(rdpCred.PasswordEnc);
            if (rdpDecResult.IsFailure)
            {
                logger.LogError("RDP validate-token: cannot decrypt credential {CredId}: {Error}",
                    info.CredentialId, rdpDecResult.Error.Message);
                return Results.Problem("Credential decryption failed");
            }

            try
            {
                return Results.Ok(new
                {
                    success = true,
                    data = new
                    {
                        sessionId = info.SessionId,
                        targetIp = info.TargetIp,
                        targetPort = info.TargetPort,
                        targetUsername = info.TargetUsername,
                        targetPasswordBytes = rdpDecResult.Value,
                        targetDomain = info.TargetDomain
                    }
                });
            }
            finally
            {
                Array.Clear(rdpDecResult.Value, 0, rdpDecResult.Value.Length);
            }
        }).WithTags("Sessions").AllowAnonymous();

        // Called by the RDP proxy to mark a session as completed.
        app.MapPost("/api/v1/sessions/{id:guid}/end",
            async (Guid id, EndSessionRequest req, OrkunPamDbContext db, IConfiguration config, HttpContext context) =>
        {
            var secret = config["ProxyService:Secret"] ?? "";
            var endHeaderValue = context.Request.Headers["X-Proxy-Secret"].FirstOrDefault() ?? "";
            if (secret.Length < 32 || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.UTF8.GetBytes(secret),
                    System.Text.Encoding.UTF8.GetBytes(endHeaderValue)))
                return Results.Unauthorized();

            var session = await db.ProxySessions.FindAsync(id);
            if (session == null) return Results.NotFound();

            session.EndedAtUtc = DateTime.UtcNow;
            session.DurationSeconds = req.DurationSeconds;
            session.RecordingPath = req.RecordingPath;
            session.Status = OrkunPAM.Domain.Enums.SessionStatus.Completed;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        }).WithTags("Sessions").AllowAnonymous();

        sessions.MapPost("/vnc/connect", async (ConnectRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, ILogger<Program> logger, IMemoryCache cache, HttpContext context) =>
        {
            return await CreateSession(req, SessionType.Vnc, 5900, db, vault, logger, cache, context);
        });

        sessions.MapPost("/sql/connect", async (ConnectRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, ILogger<Program> logger, IMemoryCache cache, HttpContext context) =>
        {
            return await CreateSession(req, SessionType.Sql, 1433, db, vault, logger, cache, context);
        });

        sessions.MapGet("/", async (OrkunPamDbContext db, HttpContext context, string? status, Guid? userId,
            SessionType? type, DateTime? from, DateTime? to, int page = 1, int pageSize = 50) =>
        {
            var callerIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isPrivileged = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("Auditor") || context.User.IsInRole("SessionAdmin");

            var query = db.ProxySessions.AsQueryable();

            if (!isPrivileged)
            {
                if (!Guid.TryParse(callerIdStr, out var callerId)) return Results.Unauthorized();
                query = query.Where(ps => ps.UserId == callerId);
            }
            else
            {
                if (userId.HasValue) query = query.Where(ps => ps.UserId == userId.Value);
            }

            if (!string.IsNullOrEmpty(status) && Enum.TryParse<SessionStatus>(status, true, out var s))
                query = query.Where(ps => ps.Status == s);
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

        sessions.MapGet("/active", async (OrkunPamDbContext db, HttpContext context) =>
        {
            var callerIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isPrivileged = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("Auditor") || context.User.IsInRole("SessionAdmin");

            var query = db.ProxySessions.Where(ps => ps.Status == SessionStatus.Active);

            if (!isPrivileged)
            {
                if (!Guid.TryParse(callerIdStr, out var callerId)) return Results.Unauthorized();
                query = query.Where(ps => ps.UserId == callerId);
            }

            var active = await query
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

        sessions.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db, HttpContext context) =>
        {
            var ps = await db.ProxySessions.FindAsync(id);
            if (ps == null) return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            var callerIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isPrivileged = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("Auditor") || context.User.IsInRole("SessionAdmin");
            if (!isPrivileged && ps.UserId.ToString() != callerIdStr)
                return Results.Forbid();

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

        sessions.MapGet("/{id:guid}/commands", async (Guid id, OrkunPamDbContext db, HttpContext context, int page = 1, int pageSize = 100) =>
        {
            var isPrivileged = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("Auditor") || context.User.IsInRole("SessionAdmin");
            if (!isPrivileged)
                return Results.Forbid();

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

        // ── Recording Playback endpoints ─────────────────────────────────────────────
        sessions.MapGet("/{id:guid}/recording", async (Guid id, OrkunPamDbContext db,
            IRecordingPlaybackService playback, HttpContext context) =>
        {
            var isPrivileged = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("Auditor") || context.User.IsInRole("SessionAdmin");
            if (!isPrivileged) return Results.Forbid();

            var ps = await db.ProxySessions.FindAsync(id);
            if (ps == null) return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            if (string.IsNullOrEmpty(ps.RecordingPath))
                return Results.NotFound(new { success = false, errors = new[] { "No recording available for this session" } });

            var metadata = await playback.GetMetadataAsync(ps.RecordingPath, ps.SessionType.ToString());
            if (metadata == null)
                return Results.NotFound(new { success = false, errors = new[] { "Recording file not found or unreadable" } });

            var integrity = await playback.VerifyIntegrityAsync(ps.RecordingPath);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    sessionId = id,
                    format = metadata.Format.ToString(),
                    fileSizeBytes = metadata.FileSizeBytes,
                    durationSeconds = metadata.DurationSeconds,
                    terminalWidth = metadata.TerminalWidth,
                    terminalHeight = metadata.TerminalHeight,
                    createdAtUtc = metadata.CreatedAtUtc,
                    integrityValid = integrity.IsValid,
                    integrityMessage = integrity.Message,
                    fileHash = integrity.FileHash,
                    watermarkTitle = metadata.WatermarkTitle
                }
            });
        });

        sessions.MapGet("/{id:guid}/recording/stream", async (Guid id, OrkunPamDbContext db,
            IRecordingPlaybackService playback, HttpContext context) =>
        {
            var isPrivileged = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("Auditor") || context.User.IsInRole("SessionAdmin");
            if (!isPrivileged) return Results.Forbid();

            var ps = await db.ProxySessions.FindAsync(id);
            if (ps == null) return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            if (string.IsNullOrEmpty(ps.RecordingPath))
                return Results.NotFound(new { success = false, errors = new[] { "No recording available" } });

            // Return parsed content based on session type
            if (ps.SessionType == SessionType.Ssh)
            {
                var recording = await playback.ParseSshRecordingAsync(ps.RecordingPath);
                if (recording == null)
                    return Results.Problem("Failed to decrypt or parse SSH recording.");

                return Results.Ok(new
                {
                    success = true,
                    data = new
                    {
                        format = "asciinema_v2",
                        header = new
                        {
                            recording.Header.Version,
                            recording.Header.Width,
                            recording.Header.Height,
                            recording.Header.Duration,
                            recording.Header.Title,
                            recording.Header.Command
                        },
                        events = recording.Events.Select(e => new
                        {
                            t = e.TimestampSeconds,
                            type = e.EventType,
                            data = e.Data
                        })
                    }
                });
            }

            if (ps.SessionType == SessionType.Http)
            {
                var entries = await playback.ParseHttpRecordingAsync(ps.RecordingPath);
                if (entries == null)
                    return Results.Problem("Failed to decrypt or parse HTTP recording.");

                return Results.Ok(new
                {
                    success = true,
                    data = new
                    {
                        format = "http_jsonl",
                        entries = entries.Select(e => new
                        {
                            t = e.TimestampSeconds,
                            method = e.Method,
                            url = e.Url,
                            statusCode = e.StatusCode,
                            requestHeaders = e.RequestHeaders,
                            requestBody = e.RequestBody,
                            responseHeaders = e.ResponseHeaders,
                            responseBody = e.ResponseBody,
                            durationMs = e.DurationMs
                        })
                    }
                });
            }

            // RDP / VNC / SQL — return raw decrypted bytes for download
            var content = await playback.GetDecryptedContentAsync(ps.RecordingPath);
            if (content == null)
                return Results.Problem("Failed to decrypt recording.");

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    format = ps.SessionType.ToString().ToLowerInvariant() + "_binary",
                    contentBase64 = Convert.ToBase64String(content),
                    sizeBytes = content.Length
                }
            });
        });

        sessions.MapGet("/{id:guid}/recording/search", async (Guid id, string? q,
            OrkunPamDbContext db, IRecordingPlaybackService playback, HttpContext context) =>
        {
            var isPrivileged = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("Auditor") || context.User.IsInRole("SessionAdmin");
            if (!isPrivileged) return Results.Forbid();

            if (string.IsNullOrEmpty(q))
                return Results.BadRequest(new { success = false, errors = new[] { "Query parameter 'q' is required" } });

            var ps = await db.ProxySessions.FindAsync(id);
            if (ps == null) return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            if (string.IsNullOrEmpty(ps.RecordingPath))
                return Results.NotFound(new { success = false, errors = new[] { "No recording available" } });

            if (ps.SessionType != SessionType.Ssh)
                return Results.BadRequest(new { success = false, errors = new[] { "Search is only supported for SSH recordings" } });

            var results = await playback.SearchSshRecordingAsync(ps.RecordingPath, q);

            return Results.Ok(new
            {
                success = true,
                data = results.Select(r => new
                {
                    timestampSeconds = r.TimestampSeconds,
                    matchedText = r.MatchedText,
                    eventIndex = r.EventIndex
                }),
                meta = new { query = q, matchCount = results.Count }
            });
        });

        var policies = app.MapGroup("/api/v1/session-policies").WithTags("Sessions").RequireAuthorization();

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
            if (!string.IsNullOrEmpty(req.CommandFilterRulesJson))
            {
                try { System.Text.Json.JsonDocument.Parse(req.CommandFilterRulesJson); }
                catch (System.Text.Json.JsonException)
                {
                    return Results.BadRequest(new { success = false, errors = new[] { "CommandFilterRulesJson must be valid JSON" } });
                }
            }

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
            if (!string.IsNullOrEmpty(req.CommandFilterRulesJson))
            {
                try { System.Text.Json.JsonDocument.Parse(req.CommandFilterRulesJson); }
                catch (System.Text.Json.JsonException)
                {
                    return Results.BadRequest(new { success = false, errors = new[] { "CommandFilterRulesJson must be valid JSON" } });
                }
            }

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
        OrkunPamDbContext db, IVaultEncryptionService vault, ILogger<Program> logger,
        IMemoryCache cache, HttpContext context)
    {
        var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
            return Results.Unauthorized();

        var device = await db.Devices.FindAsync(req.DeviceId);
        if (device == null)
            return Results.NotFound(new { success = false, errors = new[] { $"Device not found: {req.DeviceId}" } });

        var cred = await db.Credentials.FindAsync(req.CredentialId);
        if (cred == null)
            return Results.NotFound(new { success = false, errors = new[] { $"Credential not found: {req.CredentialId}" } });

        // Concurrent session limit check
        var concurrentLimit = await GetMaxConcurrentSessionsAsync(db, cache);
        var activeCount = await db.ProxySessions
            .CountAsync(ps => ps.UserId == userId && ps.Status == SessionStatus.Active);
        if (activeCount >= concurrentLimit)
        {
            logger.LogWarning("Session rejected for user {UserId}: concurrent limit {Limit} reached (active={Active})",
                userId, concurrentLimit, activeCount);
            return Results.Json(
                new { success = false, errors = new[] { $"Concurrent session limit ({concurrentLimit}) reached" } },
                statusCode: 429);
        }

        var isAdmin = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("VaultAdmin") || context.User.IsInRole("SessionAdmin");

        // Credential must be Active, or CheckedOut by the requesting user
        if (!isAdmin && cred.Status != CredentialStatus.Active &&
            !(cred.Status == CredentialStatus.CheckedOut && cred.CheckedOutByUserId == userId))
        {
            logger.LogWarning("Session rejected: credential {CredId} status={Status} (user {UserId})",
                req.CredentialId, cred.Status, userId);
            return Results.Json(
                new { success = false, errors = new[] { "Credential is not available (status: " + cred.Status.ToString() + ")" } },
                statusCode: 403);
        }

        // Access check: realm-based (Kron PAM model) takes priority over legacy AccessAssignment.
        bool isRealmCovered = false;
        if (!isAdmin)
        {
            isRealmCovered = await DeviceRealmEndpoints.IsDeviceCoveredByRealmAsync(db, req.DeviceId);
            if (isRealmCovered)
            {
                if (!await DeviceRealmEndpoints.HasRealmAccessAsync(db, userId, req.DeviceId))
                {
                    logger.LogWarning("Session rejected: user {UserId} has no realm access for device {DeviceId}",
                        userId, req.DeviceId);
                    return Results.Json(
                        new { success = false, errors = new[] { "No realm access for this device" } },
                        statusCode: 403);
                }
            }
            else if (!await AccessAssignmentEndpoints.HasAccessAssignmentAsync(db, userId, req.DeviceId, req.CredentialId))
            {
                logger.LogWarning("Session rejected: user {UserId} has no access assignment for device {DeviceId} + credential {CredId}",
                    userId, req.DeviceId, req.CredentialId);
                return Results.Json(
                    new { success = false, errors = new[] { "No access assignment for this device/credential combination" } },
                    statusCode: 403);
            }
        }

        if (!await HasCredentialAccessAsync(db, userId, isAdmin, cred, skipPermissionCheck: isRealmCovered))
            return Results.Forbid();

        // DeviceCredential: realm-covered devices require explicit link (fail-secure).
        // Legacy devices: enforce only when links are configured.
        if (!isAdmin)
        {
            var credentialLinked = await db.DeviceCredentials.AnyAsync(dc => dc.DeviceId == req.DeviceId && dc.CredentialId == req.CredentialId);
            var deviceHasLinks = isRealmCovered || await db.DeviceCredentials.AnyAsync(dc => dc.DeviceId == req.DeviceId);
            if (deviceHasLinks && !credentialLinked)
            {
                logger.LogWarning("Session rejected: credential {CredId} not assigned to device {DeviceId} (user {UserId})",
                    req.CredentialId, req.DeviceId, userId);
                return Results.Json(
                    new { success = false, errors = new[] { "Credential is not assigned to this device" } },
                    statusCode: 403);
            }
        }

        // Vendor device restriction: vendor users may only connect to their authorized devices
        var connectingUser = await db.Users.FindAsync(userId);
        if (connectingUser?.UserType == UserType.Vendor)
        {
            List<Guid> vendorDevices = [];
            if (!string.IsNullOrEmpty(connectingUser.VendorDeviceIdsJson))
            {
                try { vendorDevices = JsonSerializer.Deserialize<List<Guid>>(connectingUser.VendorDeviceIdsJson) ?? []; }
                catch { vendorDevices = []; }
            }
            if (!vendorDevices.Contains(req.DeviceId))
            {
                logger.LogWarning("Vendor {UserId} blocked: device {DeviceId} not in authorized device list", userId, req.DeviceId);
                return Results.Forbid();
            }
        }

        // Device MFA step-up check: if an active DeviceMfaPolicy requires step-up for this device,
        // verify the user completed step-up MFA (stored in IMemoryCache by /sessions/step-up-verify).
        if (!isAdmin)
        {
            var stepUpCacheKey = $"stepup:{userId}:{req.DeviceId}";
            if (!cache.TryGetValue(stepUpCacheKey, out bool _))
            {
                var mfaPolicy = await DeviceMfaPolicyEndpoints.GetEffectivePolicyAsync(db, req.DeviceId);
                if (mfaPolicy != null && mfaPolicy.IsEnabled && mfaPolicy.EnforceAtSessionStart
                    && mfaPolicy.RequiredMfaLevel != "None")
                {
                    var audit = context.RequestServices.GetRequiredService<IAuditService>();
                    var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    var stepUpToken = Guid.NewGuid().ToString("N");
                    cache.Set($"stepup-token:{stepUpToken}",
                        new StepUpTokenData(userId, req.DeviceId, mfaPolicy.RequiredMfaLevel),
                        new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15) });
                    await audit.LogAsync("Session", "SESSION_MFA_STEP_UP_REQUIRED",
                        userId, null, clientIp, "Device", req.DeviceId.ToString(),
                        new { mfaPolicy.RequiredMfaLevel });
                    return Results.Json(new
                    {
                        success = false,
                        mfaRequired = true,
                        requiredLevel = mfaPolicy.RequiredMfaLevel,
                        stepUpToken,
                        errors = new[] { $"Step-up MFA required: {mfaPolicy.RequiredMfaLevel}" }
                    }, statusCode: 403);
                }
            }
        }

        var sessionToken = Guid.NewGuid().ToString("N");

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

        logger.LogInformation("Session {SessionId} ({Type}) started: user {UserId} -> {Target}:{Port} via credential '{CredName}'",
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
                    host = "localhost",
                    port = type switch
                    {
                        SessionType.Ssh => 2222,
                        SessionType.Rdp => 3389,
                        SessionType.Vnc => 5900,
                        SessionType.Sql => 1433,
                        _ => defaultPort
                    }
                },
                credential = new { cred.Username },
                message = $"Connect your {type} client to proxy. Credential injected server-side."
            }
        });
    }

    // -----------------------------------------------------------------------
    // RDP session: generates a session token + .rdp launch file
    // -----------------------------------------------------------------------

    private static async Task<IResult> CreateRdpSession(
        ConnectRequest req, OrkunPamDbContext db,
        ILogger<Program> logger, IMemoryCache cache, IConfiguration config, HttpContext context)
    {
        var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
            return Results.Unauthorized();

        var device = await db.Devices.FindAsync(req.DeviceId);
        if (device == null)
            return Results.NotFound(new { success = false, errors = new[] { $"Device not found: {req.DeviceId}" } });

        var cred = await db.Credentials.FindAsync(req.CredentialId);
        if (cred == null)
            return Results.NotFound(new { success = false, errors = new[] { $"Credential not found: {req.CredentialId}" } });

        var isAdmin = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("VaultAdmin") || context.User.IsInRole("SessionAdmin");

        // Credential must be Active, or CheckedOut by the requesting user
        if (!isAdmin && cred.Status != CredentialStatus.Active &&
            !(cred.Status == CredentialStatus.CheckedOut && cred.CheckedOutByUserId == userId))
        {
            logger.LogWarning("RDP session rejected: credential {CredId} status={Status} (user {UserId})",
                req.CredentialId, cred.Status, userId);
            return Results.Json(
                new { success = false, errors = new[] { "Credential is not available (status: " + cred.Status.ToString() + ")" } },
                statusCode: 403);
        }

        // Access check: realm-based takes priority; fall back to legacy AccessAssignment.
        bool isRdpRealmCovered = false;
        if (!isAdmin)
        {
            isRdpRealmCovered = await DeviceRealmEndpoints.IsDeviceCoveredByRealmAsync(db, req.DeviceId);
            if (isRdpRealmCovered)
            {
                if (!await DeviceRealmEndpoints.HasRealmAccessAsync(db, userId, req.DeviceId))
                {
                    logger.LogWarning("RDP session rejected: user {UserId} has no realm access for device {DeviceId}",
                        userId, req.DeviceId);
                    return Results.Json(
                        new { success = false, errors = new[] { "No realm access for this device" } },
                        statusCode: 403);
                }
            }
            else if (!await AccessAssignmentEndpoints.HasAccessAssignmentAsync(db, userId, req.DeviceId, req.CredentialId))
            {
                logger.LogWarning("RDP session rejected: user {UserId} has no access assignment for device {DeviceId} + credential {CredId}",
                    userId, req.DeviceId, req.CredentialId);
                return Results.Json(
                    new { success = false, errors = new[] { "No access assignment for this device/credential combination" } },
                    statusCode: 403);
            }
        }

        if (!await HasCredentialAccessAsync(db, userId, isAdmin, cred, skipPermissionCheck: isRdpRealmCovered))
            return Results.Forbid();

        // Device MFA step-up check for RDP (mirrors CreateSession logic)
        if (!isAdmin)
        {
            var stepUpCacheKey = "stepup:" + userId + ":" + req.DeviceId;
            if (!cache.TryGetValue(stepUpCacheKey, out bool _))
            {
                var mfaPolicy = await DeviceMfaPolicyEndpoints.GetEffectivePolicyAsync(db, req.DeviceId);
                if (mfaPolicy != null && mfaPolicy.IsEnabled && mfaPolicy.EnforceAtSessionStart
                    && mfaPolicy.RequiredMfaLevel != "None")
                {
                    var audit = context.RequestServices.GetRequiredService<IAuditService>();
                    var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    var stepUpToken = Guid.NewGuid().ToString("N");
                    cache.Set("stepup-token:" + stepUpToken,
                        new StepUpTokenData(userId, req.DeviceId, mfaPolicy.RequiredMfaLevel),
                        new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15) });
                    await audit.LogAsync("Session", "SESSION_MFA_STEP_UP_REQUIRED",
                        userId, null, clientIp, "Device", req.DeviceId.ToString(),
                        new { mfaPolicy.RequiredMfaLevel });
                    return Results.Json(new
                    {
                        success = false,
                        mfaRequired = true,
                        requiredLevel = mfaPolicy.RequiredMfaLevel,
                        stepUpToken,
                        errors = new[] { "Step-up MFA required: " + mfaPolicy.RequiredMfaLevel }
                    }, statusCode: 403);
                }
            }
        }

        // DeviceCredential: realm-covered devices require explicit link (fail-secure).
        if (!isAdmin)
        {
            var rdpCredentialLinked = await db.DeviceCredentials.AnyAsync(dc => dc.DeviceId == req.DeviceId && dc.CredentialId == req.CredentialId);
            var rdpDeviceHasLinks = isRdpRealmCovered || await db.DeviceCredentials.AnyAsync(dc => dc.DeviceId == req.DeviceId);
            if (rdpDeviceHasLinks && !rdpCredentialLinked)
            {
                logger.LogWarning("RDP session rejected: credential {CredId} not assigned to device {DeviceId} (user {UserId})",
                    req.CredentialId, req.DeviceId, userId);
                return Results.Json(
                    new { success = false, errors = new[] { "Credential is not assigned to this device" } },
                    statusCode: 403);
            }
        }

        // Vendor device restriction for RDP sessions
        var rdpConnectingUser = await db.Users.FindAsync(userId);
        if (rdpConnectingUser?.UserType == UserType.Vendor)
        {
            List<Guid> rdpVendorDevices = [];
            if (!string.IsNullOrEmpty(rdpConnectingUser.VendorDeviceIdsJson))
            {
                try { rdpVendorDevices = JsonSerializer.Deserialize<List<Guid>>(rdpConnectingUser.VendorDeviceIdsJson) ?? []; }
                catch { rdpVendorDevices = []; }
            }
            if (!rdpVendorDevices.Contains(req.DeviceId))
            {
                logger.LogWarning("Vendor {UserId} blocked RDP: device {DeviceId} not in authorized device list", userId, req.DeviceId);
                return Results.Forbid();
            }
        }

        // Concurrent session limit check
        var rdpConcurrentLimit = await GetMaxConcurrentSessionsAsync(db, cache);
        var rdpActiveCount = await db.ProxySessions
            .CountAsync(ps => ps.UserId == userId && ps.Status == SessionStatus.Active);
        if (rdpActiveCount >= rdpConcurrentLimit)
        {
            logger.LogWarning("RDP session rejected for user {UserId}: concurrent limit {Limit} reached (active={Active})",
                userId, rdpConcurrentLimit, rdpActiveCount);
            return Results.Json(
                new { success = false, errors = new[] { $"Concurrent session limit ({rdpConcurrentLimit}) reached" } },
                statusCode: 429);
        }

        if (cred.PasswordEnc == null)
            return Results.BadRequest(new { success = false, errors = new[] { "Credential has no password" } });

        var session = new ProxySession
        {
            UserId     = userId,
            DeviceId   = req.DeviceId,
            CredentialId = req.CredentialId,
            SessionPolicyId = req.SessionPolicyId,
            SessionType = SessionType.Rdp,
            ClientIpAddress = req.ClientIp,
            TargetIpAddress = device.IpAddress,
            TargetPort  = device.ConnectionPort ?? 3389,
            Reason      = req.Reason,
            TicketNumber = req.TicketNumber
        };

        db.ProxySessions.Add(session);
        await db.SaveChangesAsync();

        var sessionToken = Guid.NewGuid().ToString("N");

        // Cache token for one-time use by the RDP proxy — credential ID stored, not plaintext bytes
        var tokenData = new RdpTokenData(
            session.Id.ToString(),
            device.IpAddress ?? device.Hostname,
            device.ConnectionPort ?? 3389,
            cred.Username ?? "",
            cred.Id,
            null);

        cache.Set($"rdp:token:{sessionToken}", tokenData,
            TimeSpan.FromSeconds(300));

        // Determine proxy address for the .rdp file
        var proxyHost = config["RdpProxy:PublicHostname"] ?? context.Request.Host.Host;
        var proxyPort = int.TryParse(config["RdpProxy:ListenPort"], out var pp) ? pp : 3389;

        var rdpFileContent = BuildRdpFile(proxyHost, proxyPort, sessionToken, device.Hostname);
        var rdpFileBytes = Encoding.UTF8.GetBytes(rdpFileContent);

        logger.LogInformation("RDP session {SessionId} created for user {UserId} → {Target}",
            session.Id, userId, device.IpAddress ?? device.Hostname);

        return Results.Ok(new
        {
            success = true,
            data = new
            {
                sessionId   = session.Id,
                sessionToken,
                proxyHost,
                proxyPort,
                rdpFile = new
                {
                    filename = $"PAM-{device.Hostname}.rdp",
                    contentBase64 = Convert.ToBase64String(rdpFileBytes)
                }
            }
        });
    }

    private static readonly System.Text.Json.JsonSerializerOptions PolicyJsonOpts =
        new() { PropertyNameCaseInsensitive = true };

    private static async Task<int> GetMaxConcurrentSessionsAsync(OrkunPamDbContext db, IMemoryCache cache)
    {
        const string CacheKey = "policy:session:global:concurrent";
        if (cache.TryGetValue<int>(CacheKey, out var cached) && cached > 0)
            return cached;

        var p = await db.Policies.FirstOrDefaultAsync(
            x => x.PolicyType == "Session" && x.Scope == PolicyScope.Global);
        var limit = 3;
        if (p?.PolicyJson != null)
        {
            try
            {
                var s = System.Text.Json.JsonSerializer.Deserialize<SessionPolicySettings>(p.PolicyJson, PolicyJsonOpts);
                if (s?.MaxConcurrentSessions > 0) limit = s.MaxConcurrentSessions;
            }
            catch { }
        }
        cache.Set(CacheKey, limit, TimeSpan.FromMinutes(5));
        return limit;
    }

    private static async Task<bool> HasCredentialAccessAsync(
        OrkunPamDbContext db, Guid userId, bool isAdmin, Credential cred, bool skipPermissionCheck = false)
    {
        if (isAdmin) return true;

        if (!skipPermissionCheck)
        {
            var userGroupIds = await db.UserGroups
                .Where(ug => ug.UserId == userId)
                .Select(ug => ug.GroupId)
                .ToListAsync();

            var hasAccess = await db.CredentialPermissions.AnyAsync(p =>
                (p.CredentialId == cred.Id || p.FolderId == cred.FolderId)
                && ((p.PrincipalType == PrincipalType.User && p.PrincipalId == userId)
                    || (p.PrincipalType == PrincipalType.Group && userGroupIds.Contains(p.PrincipalId))));

            if (!hasAccess) return false;
        }

        if (cred.RequiresApproval &&
            !(cred.CheckedOutByUserId == userId && cred.Status == CredentialStatus.CheckedOut))
            return false;

        return true;
    }

    private static string BuildRdpFile(string proxyHost, int proxyPort, string sessionToken, string deviceHostname)
    {
        // Session token is passed as the username so the PAM RDP proxy can identify the pre-authenticated session.
        // NLA/CredSSP is disabled on the client side (enablecredsspsupport:i:0) because the proxy handles
        // credential injection at the target side using vault credentials.
        var sb = new StringBuilder();
        sb.AppendLine($"full address:s:{proxyHost}:{proxyPort}");
        sb.AppendLine($"username:s:{sessionToken}");
        sb.AppendLine($"server port:i:{proxyPort}");
        sb.AppendLine("enablecredsspsupport:i:0");
        sb.AppendLine("authentication level:i:2");
        sb.AppendLine("prompt for credentials:i:0");
        sb.AppendLine("negotiate security layer:i:0");
        sb.AppendLine("use redirection server name:i:0");
        sb.AppendLine("alternate shell:s:");
        sb.AppendLine("shell working directory:s:");
        sb.AppendLine($"remoteapplicationprogram:s:");
        sb.AppendLine("screen mode id:i:2");
        sb.AppendLine("use multimon:i:0");
        sb.AppendLine("session bpp:i:32");
        sb.AppendLine("compression:i:1");
        sb.AppendLine("keyboardhook:i:2");
        sb.AppendLine("audiocapturemode:i:0");
        sb.AppendLine("videoplaybackmode:i:1");
        sb.AppendLine("connection type:i:7");
        sb.AppendLine("allow font smoothing:i:1");
        sb.AppendLine("allow desktop composition:i:1");
        sb.AppendLine("disable wallpaper:i:0");
        sb.AppendLine("disable full window drag:i:1");
        sb.AppendLine("disable menu anims:i:1");
        sb.AppendLine("disable themes:i:0");
        sb.AppendLine("bitmapcachepersistenable:i:1");
        sb.AppendLine($"description:s:PAM Session - {deviceHostname}");
        return sb.ToString();
    }
}

public record ConnectRequest(Guid DeviceId, Guid CredentialId,
    Guid? SessionPolicyId, string? Reason, string? TicketNumber, string? ClientIp);
public record TerminateSessionRequest(string Reason);
public record ValidateRdpTokenRequest(string SessionToken);
public record EndSessionRequest(int DurationSeconds, string? RecordingPath);
public record RdpTokenData(string SessionId, string TargetIp, int TargetPort,
    string TargetUsername, Guid CredentialId, string? TargetDomain);
public record CreateSessionPolicyRequest(string Name, int? MaxDurationMinutes, int? IdleTimeoutMinutes,
    bool AllowClipboard, bool AllowFileTransfer, bool AllowDriveMapping, bool AllowPrinting,
    bool? RecordingEnabled, bool? KeystrokeLogging, bool RequireReason, bool RequireTicket,
    bool TwoPersonRule, bool EnableWatermark, CommandFilterMode? CommandFilterMode, string? CommandFilterRulesJson);
public record UpdateSessionPolicyRequest(string? Name, int? MaxDurationMinutes, int? IdleTimeoutMinutes,
    bool? AllowClipboard, bool? AllowFileTransfer, bool? AllowDriveMapping,
    bool? RecordingEnabled, bool? KeystrokeLogging, bool? EnableWatermark,
    CommandFilterMode? CommandFilterMode, string? CommandFilterRulesJson);
