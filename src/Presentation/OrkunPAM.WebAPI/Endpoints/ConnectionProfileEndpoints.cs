using Microsoft.EntityFrameworkCore;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ConnectionProfileEndpoints
{
    public static void MapConnectionProfileEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/sessions/connection-profile",
            async (OrkunPamDbContext db, string? deviceId, string? credentialId,
                   string? client, HttpContext context) =>
        {
            if (string.IsNullOrWhiteSpace(deviceId) || !Guid.TryParse(deviceId, out var devId))
                return Results.BadRequest(new { success = false, errors = new[] { "deviceId is required" } });
            if (string.IsNullOrWhiteSpace(credentialId) || !Guid.TryParse(credentialId, out var credId))
                return Results.BadRequest(new { success = false, errors = new[] { "credentialId is required" } });

            var device = await db.Devices
                .Where(d => d.Id == devId)
                .Select(d => new { d.Id, d.Hostname, d.IpAddress })
                .FirstOrDefaultAsync();
            if (device == null)
                return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            var cred = await db.Credentials
                .Where(c => c.Id == credId)
                .Select(c => new { c.Id, c.Username })
                .FirstOrDefaultAsync();
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var pamHost    = context.Request.Host.Host;
            const int pamPort = 2222;
            var username   = cred.Username ?? "pamuser";
            var hostname   = device.Hostname;
            var safeName   = hostname.Replace(" ", "-").Replace(".", "-");
            var sessionName = "OrkunPAM-" + safeName;
            var sshCommand = $"ssh {username}@{pamHost} -p {pamPort}";

            var (filename, content, mimeType) = (client?.ToLowerInvariant()) switch
            {
                "putty"     => GeneratePuttyProfile(sessionName, pamHost, pamPort, username),
                "mobaxterm" => GenerateMobaXtermProfile(sessionName, pamHost, pamPort, username),
                "securecrt" => GenerateSecureCrtProfile(hostname, pamHost, pamPort, username),
                "sshconfig" => GenerateSshConfigProfile(sessionName, pamHost, pamPort, username),
                _           => GenerateSshConfigProfile(sessionName, pamHost, pamPort, username)
            };

            return Results.Ok(new
            {
                success = true,
                data = new { filename, content, mimeType, sshCommand }
            });
        }).WithTags("Sessions").RequireAuthorization();
    }

    private static (string, string, string) GeneratePuttyProfile(
        string sessionName, string pamHost, int pamPort, string username)
    {
        var portHex = pamPort.ToString("X8").ToLowerInvariant();
        var content =
$@"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\{sessionName}]
""HostName""=""{pamHost}""
""PortNumber""=dword:{portHex}
""Protocol""=""ssh""
""UserName""=""{username}""
""TerminalType""=""xterm-256color""
""RemoteCommand""=""""
";
        return ($"{sessionName}.reg", content, "text/plain");
    }

    private static (string, string, string) GenerateMobaXtermProfile(
        string sessionName, string pamHost, int pamPort, string username)
    {
        // MobaXterm SSH session format: #109#1#hostname#port#username#-1###-1#0#0#0#######
        var content =
$@"[Bookmarks]
SubRep=OrkunPAM
ImgNum=41

{sessionName}=#109#1#{pamHost}#{pamPort}#{username}#-1###-1#0#0#0#######
";
        return ($"{sessionName}.mxtsessions", content, "text/plain");
    }

    private static (string, string, string) GenerateSecureCrtProfile(
        string deviceHostname, string pamHost, int pamPort, string username)
    {
        var content =
$@"[/SSH2]
S:""Hostname""={pamHost}
D:""Port""={pamPort:D8}
S:""Username""={username}
S:""Description""=OrkunPAM - {deviceHostname}
S:""Cipher List""=aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc
S:""Protocol Name""=SSH2
D:""Force Close On Exit""=00000001
";
        return ($"OrkunPAM-{deviceHostname}.ini", content, "text/plain");
    }

    private static (string, string, string) GenerateSshConfigProfile(
        string sessionName, string pamHost, int pamPort, string username)
    {
        var alias = sessionName.ToLowerInvariant();
        var content =
$@"# OrkunPAM SSH Config Snippet
# Paste into ~/.ssh/config, then connect with: ssh {alias}

Host {alias}
    HostName {pamHost}
    Port {pamPort}
    User {username}
    ServerAliveInterval 60
    ServerAliveCountMax 3
";
        return ("orkunpam_ssh_config.txt", content, "text/plain");
    }
}
