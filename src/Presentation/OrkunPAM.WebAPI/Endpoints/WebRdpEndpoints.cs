using System.IdentityModel.Tokens.Jwt;
using System.Net.WebSockets;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.WebAPI.WebRdp;

namespace OrkunPAM.WebAPI.Endpoints;

public static class WebRdpEndpoints
{
    public static void MapWebRdpEndpoints(this IEndpointRouteBuilder app)
    {
        // GET /ws/rdp?deviceId={guid}&credentialId={guid}&token={jwt}&width={n}&height={n}
        // Browser WebSocket RDP terminal — native C# RDP client, no external library.
        app.Map("/ws/rdp", async (HttpContext ctx) =>
        {
            if (!ctx.WebSockets.IsWebSocketRequest)
            {
                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                await ctx.Response.WriteAsync("WebSocket upgrade required");
                return;
            }

            // JWT auth via query param (WebSocket upgrade cannot send custom headers)
            var token = ctx.Request.Query["token"].FirstOrDefault();
            if (string.IsNullOrEmpty(token)) { ctx.Response.StatusCode = 401; return; }

            var tvp = ctx.RequestServices.GetRequiredService<TokenValidationParameters>();
            var jwtHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal;
            try { principal = jwtHandler.ValidateToken(token, tvp, out _); }
            catch { ctx.Response.StatusCode = 401; return; }

            if (!Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            { ctx.Response.StatusCode = 401; return; }

            if (!Guid.TryParse(ctx.Request.Query["deviceId"].FirstOrDefault(), out var deviceId) ||
                !Guid.TryParse(ctx.Request.Query["credentialId"].FirstOrDefault(), out var credentialId))
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsync("deviceId and credentialId are required");
                return;
            }

            int width  = int.TryParse(ctx.Request.Query["width"],  out var w) ? Math.Clamp(w, 640, 3840) : 1280;
            int height = int.TryParse(ctx.Request.Query["height"], out var h) ? Math.Clamp(h, 480, 2160) : 800;

            var db     = ctx.RequestServices.GetRequiredService<OrkunPamDbContext>();
            var vault  = ctx.RequestServices.GetRequiredService<IVaultEncryptionService>();
            var logger = ctx.RequestServices.GetRequiredService<ILogger<Program>>();

            var device = await db.Devices.FindAsync(deviceId);
            if (device == null) { ctx.Response.StatusCode = 404; return; }

            if (!string.Equals(device.Protocol, "rdp", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(device.Protocol, "Rdp", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsync("Device protocol is not RDP");
                return;
            }

            var cred = await db.Credentials.FindAsync(credentialId);
            if (cred == null || cred.DeviceId != deviceId || cred.PasswordEnc == null)
            { ctx.Response.StatusCode = 404; return; }

            // Authorization check
            var isAdmin = principal.IsInRole("GlobalAdmin")
                       || principal.IsInRole("VaultAdmin")
                       || principal.IsInRole("SessionAdmin");
            if (!isAdmin)
            {
                var hasPerm = await db.CredentialPermissions.AnyAsync(
                    p => p.PrincipalType == PrincipalType.User
                         && p.PrincipalId == userId
                         && ((p.CredentialId == credentialId) || (p.FolderId == cred.FolderId))
                         && p.PermissionLevel >= PermissionLevel.Use);
                if (!hasPerm)
                {
                    logger.LogWarning("WebRDP: user {UserId} unauthorized access to credential {CredId}", userId, credentialId);
                    ctx.Response.StatusCode = 403;
                    return;
                }
            }

            var decResult = vault.DecryptString(cred.PasswordEnc);
            if (decResult.IsFailure)
            {
                logger.LogError("WebRDP: credential decryption failed for {CredId}", credentialId);
                ctx.Response.StatusCode = 500; return;
            }

            var targetHost = device.IpAddress ?? device.Hostname;
            if (string.IsNullOrEmpty(targetHost))
            { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("Device has no IP or hostname"); return; }

            var targetPort   = device.ConnectionPort ?? 3389;
            var targetDomain = ""; // domain from cred or device, if stored
            var targetUser   = cred.Username ?? "";
            var targetPasswd = System.Text.Encoding.UTF8.GetBytes(decResult.Value);

            var ws = await ctx.WebSockets.AcceptWebSocketAsync();

            // Create audit session record
            var session = new ProxySession
            {
                UserId          = userId,
                DeviceId        = deviceId,
                CredentialId    = credentialId,
                SessionType     = SessionType.Rdp,
                ClientIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetIpAddress = device.IpAddress,
                TargetPort      = targetPort
            };
            db.ProxySessions.Add(session);
            await db.SaveChangesAsync();

            logger.LogInformation("WebRDP session {SessId}: user {UserId} -> {Host}:{Port} ({Width}x{Height})",
                session.Id, userId, targetHost, targetPort, width, height);

            var client = new WebRdpClient(targetHost, targetPort, targetDomain, targetUser,
                targetPasswd, width, height, logger);
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromHours(8));

                await client.ConnectAsync(cts.Token);

                var connMsg = System.Text.Encoding.UTF8.GetBytes("{\"t\":\"connected\"}");
                await ws.SendAsync(connMsg, WebSocketMessageType.Text, true, cts.Token);

                await client.RelayAsync(ws, cts.Token);
            }
            catch (WebRdpException ex)
            {
                logger.LogWarning("WebRDP session {SessId} RDP error: {Msg}", session.Id, ex.Message);
                if (ws.State == WebSocketState.Open)
                {
                    try
                    {
                        var safe = ex.Message.Replace("\"", "'");
                        var errMsg = System.Text.Encoding.UTF8.GetBytes($"{{\"t\":\"error\",\"msg\":\"{safe}\"}}");
                        await ws.SendAsync(errMsg, WebSocketMessageType.Text, true, CancellationToken.None);
                        await ws.CloseAsync(WebSocketCloseStatus.InternalServerError, ex.Message, CancellationToken.None);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "WebRDP session {SessId} unexpected error", session.Id);
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
                catch (Exception ex) { logger.LogWarning(ex, "WebRDP: failed to finalize session {SessId}", session.Id); }

                if (ws.State == WebSocketState.Open)
                    try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Session ended", CancellationToken.None); } catch { }
            }
        }).AllowAnonymous();
    }
}
