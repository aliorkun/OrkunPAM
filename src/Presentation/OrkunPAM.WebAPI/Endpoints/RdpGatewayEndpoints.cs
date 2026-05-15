using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class RdpGatewayEndpoints
{
    public static void MapRdpGatewayEndpoints(this IEndpointRouteBuilder app)
    {
        var rdp = app.MapGroup("/api/v1/rdp").WithTags("RDP Gateway").RequireAuthorization();

        // GET /api/v1/rdp/ha-nodes — TCP health-check each configured RDS/RDP proxy node
        rdp.MapGet("/ha-nodes", async (IConfiguration config, CancellationToken ct) =>
        {
            var rdpPort = int.TryParse(config["RdpProxy:ListenPort"], out var p) ? p : 3389;
            var hosts = config.GetSection("RdpProxy:RdsHosts").Get<string[]>() ?? [];

            var tasks = hosts.Select(async host =>
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var healthy = false;
                var error = "";
                try
                {
                    using var tcp = new System.Net.Sockets.TcpClient();
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(3000);
                    await tcp.ConnectAsync(host, rdpPort, cts.Token);
                    healthy = true;
                }
                catch (Exception ex) { error = ex.Message; }
                sw.Stop();
                return new { host, healthy, latencyMs = (int)sw.ElapsedMilliseconds, error };
            });

            var results = await Task.WhenAll(tasks);
            return Results.Ok(new
            {
                success = true,
                data = results,
                meta = new { totalNodes = results.Length, healthyNodes = results.Count(r => r.healthy) }
            });
        });

        // GET /api/v1/rdp/remoteapps — list published RemoteApps from config
        rdp.MapGet("/remoteapps", (IConfiguration config) =>
        {
            var apps = config.GetSection("RemoteApps").Get<RemoteAppConfig[]>() ?? [];
            return Results.Ok(new { success = true, data = apps, meta = new { count = apps.Length } });
        });

        // POST /api/v1/rdp/remoteapp/connect — create a RemoteApp session token + .rdp file
        rdp.MapPost("/remoteapp/connect", async (RemoteAppConnectRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, IMemoryCache cache, IConfiguration config, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var apps = config.GetSection("RemoteApps").Get<RemoteAppConfig[]>() ?? [];
            var remoteApp = apps.FirstOrDefault(a =>
                string.Equals(a.Name, req.AppName, StringComparison.OrdinalIgnoreCase));
            if (remoteApp == null)
                return Results.NotFound(new { success = false, errors = new[] { "RemoteApp '" + req.AppName + "' not found in configuration" } });

            var device = await db.Devices.FindAsync(req.DeviceId);
            if (device == null)
                return Results.NotFound(new { success = false, errors = new[] { "Device not found: " + req.DeviceId } });

            var cred = await db.Credentials.FindAsync(req.CredentialId);
            if (cred?.PasswordEnc == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found or has no password" } });

            var isAdmin = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("VaultAdmin");
            if (!await HasCredentialAccessAsync(db, userId, isAdmin, cred))
                return Results.Forbid();

            var decResult = vault.DecryptString(cred.PasswordEnc);
            if (decResult.IsFailure)
                return Results.Problem("Credential decryption failed.");

            var session = new ProxySession
            {
                UserId = userId,
                DeviceId = req.DeviceId,
                CredentialId = req.CredentialId,
                SessionType = SessionType.Rdp,
                TargetIpAddress = device.IpAddress,
                TargetPort = device.ConnectionPort ?? 3389,
                Reason = req.Reason ?? ("RemoteApp: " + remoteApp.Name),
                Tags = "remoteapp:" + remoteApp.Name
            };
            db.ProxySessions.Add(session);
            await db.SaveChangesAsync();

            var sessionToken = Guid.NewGuid().ToString("N");
            cache.Set("rdp:token:" + sessionToken, new RdpTokenData(
                session.Id.ToString(),
                device.IpAddress ?? device.Hostname,
                device.ConnectionPort ?? 3389,
                cred.Username ?? "",
                Encoding.UTF8.GetBytes(decResult.Value),
                null), TimeSpan.FromSeconds(300));

            var proxyHost = config["RdpProxy:PublicHostname"] ?? context.Request.Host.Host;
            var proxyPort = int.TryParse(config["RdpProxy:ListenPort"], out var pp) ? pp : 3389;

            var rdpContent = BuildRemoteAppRdpFile(
                proxyHost, proxyPort, sessionToken,
                remoteApp.AppPath, remoteApp.Name, remoteApp.AppArgs ?? "");

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    sessionId = session.Id,
                    sessionToken,
                    rdpFile = new
                    {
                        filename = "PAM-" + remoteApp.Name + ".rdp",
                        contentBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(rdpContent))
                    }
                }
            });
        });

        // POST /api/v1/rdp/sessions/{id}/shadow — admin creates a shadow (monitor) session
        rdp.MapPost("/sessions/{id:guid}/shadow", async (Guid id, OrkunPamDbContext db,
            IVaultEncryptionService vault, IMemoryCache cache, IConfiguration config, HttpContext context) =>
        {
            var isAdmin = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("SessionAdmin");
            if (!isAdmin) return Results.Forbid();

            var adminIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (adminIdStr == null || !Guid.TryParse(adminIdStr, out var adminId))
                return Results.Unauthorized();

            var original = await db.ProxySessions.FindAsync(id);
            if (original == null)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });
            if (original.Status != SessionStatus.Active)
                return Results.Conflict(new { success = false, errors = new[] { "Session is not active (status: " + original.Status + ")" } });
            if (original.SessionType != SessionType.Rdp)
                return Results.BadRequest(new { success = false, errors = new[] { "Shadow is only supported for RDP sessions" } });

            var cred = await db.Credentials.FindAsync(original.CredentialId);
            if (cred?.PasswordEnc == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var decResult = vault.DecryptString(cred.PasswordEnc);
            if (decResult.IsFailure)
                return Results.Problem("Credential decryption failed.");

            var shadowSession = new ProxySession
            {
                UserId = adminId,
                DeviceId = original.DeviceId,
                CredentialId = original.CredentialId,
                SessionType = SessionType.Rdp,
                TargetIpAddress = original.TargetIpAddress,
                TargetPort = original.TargetPort ?? 3389,
                Reason = "Shadow of session " + id,
                Tags = "shadow:" + id.ToString()
            };
            db.ProxySessions.Add(shadowSession);
            await db.SaveChangesAsync();

            var shadowToken = Guid.NewGuid().ToString("N");
            cache.Set("rdp:token:" + shadowToken, new RdpTokenData(
                shadowSession.Id.ToString(),
                original.TargetIpAddress ?? "",
                original.TargetPort ?? 3389,
                cred.Username ?? "",
                Encoding.UTF8.GetBytes(decResult.Value),
                null), TimeSpan.FromSeconds(300));

            var proxyHost = config["RdpProxy:PublicHostname"] ?? context.Request.Host.Host;
            var proxyPort = int.TryParse(config["RdpProxy:ListenPort"], out var pp2) ? pp2 : 3389;

            var rdpContent = BuildShadowRdpFile(proxyHost, proxyPort, shadowToken, original.TargetIpAddress ?? "");
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    shadowSessionId = shadowSession.Id,
                    originalSessionId = id,
                    rdpFile = new
                    {
                        filename = "PAM-Shadow-" + id.ToString("N")[..8] + ".rdp",
                        contentBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(rdpContent))
                    }
                }
            });
        });
    }

    private static string BuildShadowRdpFile(string proxyHost, int proxyPort, string token, string targetHost)
    {
        var sb = new StringBuilder();
        sb.AppendLine("full address:s:" + proxyHost + ":" + proxyPort);
        sb.AppendLine("username:s:" + token);
        sb.AppendLine("server port:i:" + proxyPort);
        sb.AppendLine("enablecredsspsupport:i:0");
        sb.AppendLine("authentication level:i:2");
        sb.AppendLine("prompt for credentials:i:0");
        sb.AppendLine("negotiate security layer:i:0");
        sb.AppendLine("screen mode id:i:2");
        sb.AppendLine("session bpp:i:32");
        sb.AppendLine("compression:i:1");
        sb.AppendLine("description:s:PAM Shadow - " + targetHost);
        return sb.ToString();
    }

    private static string BuildRemoteAppRdpFile(
        string proxyHost, int proxyPort, string token, string appPath, string appName, string appArgs)
    {
        var sb = new StringBuilder();
        sb.AppendLine("full address:s:" + proxyHost + ":" + proxyPort);
        sb.AppendLine("username:s:" + token);
        sb.AppendLine("server port:i:" + proxyPort);
        sb.AppendLine("remoteapplicationmode:i:1");
        sb.AppendLine("remoteapplicationprogram:s:" + appPath);
        sb.AppendLine("remoteapplicationname:s:" + appName);
        sb.AppendLine("remoteapplicationcmdline:s:" + appArgs);
        sb.AppendLine("enablecredsspsupport:i:0");
        sb.AppendLine("authentication level:i:2");
        sb.AppendLine("prompt for credentials:i:0");
        sb.AppendLine("negotiate security layer:i:0");
        sb.AppendLine("screen mode id:i:2");
        sb.AppendLine("session bpp:i:32");
        sb.AppendLine("compression:i:1");
        sb.AppendLine("description:s:PAM RemoteApp - " + appName);
        return sb.ToString();
    }

    private static async Task<bool> HasCredentialAccessAsync(
        OrkunPamDbContext db, Guid userId, bool isAdmin, Credential cred)
    {
        if (isAdmin) return true;

        var userGroupIds = await db.UserGroups
            .Where(ug => ug.UserId == userId)
            .Select(ug => ug.GroupId)
            .ToListAsync();

        var hasAccess = await db.CredentialPermissions.AnyAsync(p =>
            (p.CredentialId == cred.Id || p.FolderId == cred.FolderId)
            && ((p.PrincipalType == PrincipalType.User && p.PrincipalId == userId)
                || (p.PrincipalType == PrincipalType.Group && userGroupIds.Contains(p.PrincipalId))));

        if (!hasAccess) return false;

        if (cred.RequiresApproval &&
            !(cred.CheckedOutByUserId == userId && cred.Status == CredentialStatus.CheckedOut))
            return false;

        return true;
    }
}

public record RemoteAppConfig(
    string Name,
    string AppPath,
    string? Description,
    string? AppArgs,
    string? Category,
    Guid? DefaultDeviceId);

public record RemoteAppConnectRequest(
    Guid DeviceId,
    Guid CredentialId,
    string AppName,
    string? Reason);
