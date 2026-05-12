using System.IdentityModel.Tokens.Jwt;
using System.Net.WebSockets;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.WebAPI.WebSsh;

namespace OrkunPAM.WebAPI.Endpoints;

public static class WebSshEndpoints
{
    public static void MapWebSshEndpoints(this IEndpointRouteBuilder app)
    {
        // WebSocket SSH bridge:
        // GET /ws/ssh?deviceId={guid}&credentialId={guid}&token={jwt}&cols={n}&rows={n}
        //
        // JWT is passed as a query parameter because the browser WebSocket API
        // does not support custom request headers during the upgrade handshake.
        app.Map("/ws/ssh", async (HttpContext ctx) =>
        {
            if (!ctx.WebSockets.IsWebSocketRequest)
            {
                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                await ctx.Response.WriteAsync("WebSocket upgrade required");
                return;
            }

            // Authenticate (JWT in query param)
            var token = ctx.Request.Query["token"].FirstOrDefault();
            if (string.IsNullOrEmpty(token)) { ctx.Response.StatusCode = 401; return; }

            var tvp = ctx.RequestServices.GetRequiredService<TokenValidationParameters>();
            var jwtHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal;
            try { principal = jwtHandler.ValidateToken(token, tvp, out _); }
            catch { ctx.Response.StatusCode = 401; return; }

            if (!Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            { ctx.Response.StatusCode = 401; return; }

            // Parse query params
            if (!Guid.TryParse(ctx.Request.Query["deviceId"].FirstOrDefault(), out var deviceId) ||
                !Guid.TryParse(ctx.Request.Query["credentialId"].FirstOrDefault(), out var credentialId))
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsync("deviceId and credentialId are required");
                return;
            }

            ushort cols = ushort.TryParse(ctx.Request.Query["cols"], out var c) ? c : (ushort)220;
            ushort rows = ushort.TryParse(ctx.Request.Query["rows"], out var r) ? r : (ushort)50;

            // Look up device + credential
            var db     = ctx.RequestServices.GetRequiredService<OrkunPamDbContext>();
            var vault  = ctx.RequestServices.GetRequiredService<IVaultEncryptionService>();
            var logger = ctx.RequestServices.GetRequiredService<ILogger<Program>>();

            var device = await db.Devices.FindAsync(deviceId);
            if (device == null) { ctx.Response.StatusCode = 404; return; }

            var cred = await db.Credentials.FindAsync(credentialId);
            if (cred == null || cred.DeviceId != deviceId || cred.PasswordEnc == null)
            { ctx.Response.StatusCode = 404; return; }

            // Authorization: admin roles bypass; all others need explicit credential/folder permission
            var isAdmin = principal.IsInRole("GlobalAdmin")
                       || principal.IsInRole("VaultAdmin")
                       || principal.IsInRole("SessionAdmin");
            if (!isAdmin)
            {
                var hasPermission = await db.CredentialPermissions.AnyAsync(
                    p => p.PrincipalType == PrincipalType.User
                         && p.PrincipalId == userId
                         && ((p.CredentialId == credentialId) || (p.FolderId == cred.FolderId))
                         && p.PermissionLevel >= PermissionLevel.Use);
                if (!hasPermission)
                {
                    logger.LogWarning(
                        "WebSSH: user {UserId} unauthorized access attempt to credential {CredId}", userId, credentialId);
                    ctx.Response.StatusCode = 403;
                    await ctx.Response.WriteAsync("Access denied");
                    return;
                }
            }

            var decResult = vault.DecryptString(cred.PasswordEnc);
            if (decResult.IsFailure)
            {
                logger.LogError("WebSSH: credential decryption failed for {CredId}", credentialId);
                ctx.Response.StatusCode = 500; return;
            }

            var targetHost = device.IpAddress ?? device.Hostname;
            if (string.IsNullOrEmpty(targetHost))
            { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("Device has no IP or hostname"); return; }

            var targetPort = device.ConnectionPort ?? 22;
            var targetUser = cred.Username;
            if (string.IsNullOrEmpty(targetUser))
            { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("Credential has no username"); return; }

            // Convert to byte[] immediately so WebSshClient can zero it after auth (#70)
            var targetPasswordBytes = System.Text.Encoding.UTF8.GetBytes(decResult.Value);

            // Accept WebSocket upgrade
            var ws = await ctx.WebSockets.AcceptWebSocketAsync();

            // Create session audit record
            var session = new ProxySession
            {
                UserId          = userId,
                DeviceId        = deviceId,
                CredentialId    = credentialId,
                SessionType     = SessionType.Ssh,
                ClientIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetIpAddress = device.IpAddress,
                TargetPort      = targetPort
            };
            db.ProxySessions.Add(session);
            await db.SaveChangesAsync();

            logger.LogInformation("WebSSH session {SessId}: user {UserId} -> {Host}:{Port}",
                session.Id, userId, targetHost, targetPort);

            // Run SSH bridge
            var client = new WebSshClient(targetHost, targetPort, targetUser, targetPasswordBytes, logger,
                device.SshHostKeyFingerprint);
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromHours(8));

                await client.ConnectAsync(cts.Token);

                // TOFU: save fingerprint on first connection
                if (device.SshHostKeyFingerprint == null && client.ObservedFingerprint != null)
                {
                    device.SshHostKeyFingerprint = client.ObservedFingerprint;
                    await db.SaveChangesAsync();
                }

                await client.OpenShellAsync(cols, rows, cts.Token);

                var connMsg = System.Text.Encoding.UTF8.GetBytes("{\"t\":\"connected\"}");
                await ws.SendAsync(connMsg, WebSocketMessageType.Text, true, cts.Token);

                await client.RelayAsync(ws, cts.Token);
            }
            catch (SshWebException ex)
            {
                logger.LogWarning("WebSSH session {SessId} SSH error: {Msg}", session.Id, ex.Message);
                if (ws.State == WebSocketState.Open)
                {
                    try
                    {
                        var safe = ex.Message.Replace("\"", "'");
                        var errMsg = System.Text.Encoding.UTF8.GetBytes($"{{\"t\":\"error\",\"msg\":\"{safe}\"}}");
                        await ws.SendAsync(errMsg, WebSocketMessageType.Text, true, CancellationToken.None);
                        await ws.CloseAsync(WebSocketCloseStatus.InternalServerError, ex.Message, CancellationToken.None);
                    }
                    catch { /* ignore close errors */ }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "WebSSH session {SessId} unexpected error", session.Id);
                if (ws.State == WebSocketState.Open)
                    try { await ws.CloseAsync(WebSocketCloseStatus.InternalServerError, "Internal error", CancellationToken.None); } catch { }
            }
            finally
            {
                await client.DisposeAsync();

                try
                {
                    session.End();
                    await db.SaveChangesAsync();
                }
                catch (Exception ex) { logger.LogWarning(ex, "WebSSH: failed to finalize session record {SessId}", session.Id); }

                if (ws.State == WebSocketState.Open)
                    try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Session ended", CancellationToken.None); } catch { }
            }
        }).AllowAnonymous(); // Auth handled manually - JWT in query param (WebSocket limitation)
    }
}
