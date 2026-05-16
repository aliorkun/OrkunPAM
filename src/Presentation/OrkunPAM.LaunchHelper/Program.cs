// OrkunPAM.LaunchHelper — Windows URI scheme handler for orkunpam://
//
// Install: registered by MSI via registry key:
//   HKCR\orkunpam\shell\open\command → "OrkunPAM.LaunchHelper.exe" "%1"
//
// Invoked by browser as: orkunpam://launch?token=GUID&protocol=ssh
//
// Flow:
//   1. Parse URI from argv[1]
//   2. Call PAM API redeem endpoint (GET /api/v1/sessions/launch-token/{token}/redeem)
//   3. Launch ssh.exe or mstsc.exe with returned credentials

using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

if (args.Length == 0)
{
    RegisterUriScheme();
    Console.WriteLine("OrkunPAM LaunchHelper — URI scheme registered.");
    return 0;
}

var rawUri = args[0];

Uri uri;
try { uri = new Uri(rawUri); }
catch
{
    Error($"Invalid URI: {rawUri}");
    return 1;
}

if (!string.Equals(uri.Scheme, "orkunpam", StringComparison.OrdinalIgnoreCase))
{
    Error($"Unknown scheme: {uri.Scheme}");
    return 1;
}

var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
var tokenStr = query["token"];
if (string.IsNullOrEmpty(tokenStr) || !Guid.TryParse(tokenStr, out _))
{
    Error("Missing or invalid token parameter.");
    return 1;
}

// Read PAM API base URL from registry (set during MSI install)
var apiBase = ReadApiBase() ?? "https://localhost:5001";

using var http = new HttpClient();
http.Timeout = TimeSpan.FromSeconds(10);

RedeemResult? redeem;
try
{
    var redeemUrl = $"{apiBase.TrimEnd('/')}/api/v1/sessions/launch-token/{tokenStr}/redeem";
    var resp = await http.GetAsync(redeemUrl);
    if (!resp.IsSuccessStatusCode)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Error($"Redeem failed ({(int)resp.StatusCode}): {body}");
        return 1;
    }
    var wrapper = await resp.Content.ReadFromJsonAsync<RedeemWrapper>(
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    redeem = wrapper?.Data;
}
catch (Exception ex)
{
    Error($"Network error: {ex.Message}");
    return 1;
}

if (redeem == null)
{
    Error("Empty response from redeem endpoint.");
    return 1;
}

// Zero memory after use (best effort — GC may have already moved values)
try
{
    if (redeem.Protocol == "rdp")
        LaunchRdp(redeem);
    else
        LaunchSsh(redeem);
}
catch (Exception ex)
{
    Error($"Launch failed: {ex.Message}");
    return 1;
}

return 0;

// ── Helpers ─────────────────────────────────────────────────────────────────────────────────

static void LaunchRdp(RedeemResult r)
{
    // Write a temporary .rdp file and open it with mstsc
    var rdpContent = $"""
        full address:s:{r.Host}:{r.Port}
        username:s:{r.Username}
        prompt for credentials:i:0
        authentication level:i:2
        """;
    var tmpRdp = Path.Combine(Path.GetTempPath(), $"orkunpam-{Guid.NewGuid():N}.rdp");
    File.WriteAllText(tmpRdp, rdpContent);

    // Schedule temp file deletion after 10 seconds
    Task.Run(async () =>
    {
        await Task.Delay(10_000);
        try { File.Delete(tmpRdp); } catch { }
    });

    Process.Start(new ProcessStartInfo
    {
        FileName  = "mstsc.exe",
        Arguments = $"\"{ tmpRdp}\"",
        UseShellExecute = true
    });
}

static void LaunchSsh(RedeemResult r)
{
    // Try Windows OpenSSH client first, fall back to PuTTY
    var sshExe = FindExecutable("ssh.exe") ?? FindExecutable("putty.exe");
    if (sshExe == null)
    {
        Error("No SSH client found. Install OpenSSH or PuTTY.");
        return;
    }

    string args;
    if (sshExe.EndsWith("putty.exe", StringComparison.OrdinalIgnoreCase))
    {
        args = $"-ssh -l {r.Username} -P {r.Port}";
        if (!string.IsNullOrEmpty(r.Password))
            args += $" -pw \"{r.Password}\"";
        args += $" {r.Host}";
    }
    else
    {
        // Windows OpenSSH — password must be supplied interactively unless SSH key
        args = $"-p {r.Port} {r.Username}@{r.Host}";
        if (!string.IsNullOrEmpty(r.PrivateKey))
        {
            var tmpKey = Path.Combine(Path.GetTempPath(), $"orkunpam-key-{Guid.NewGuid():N}.pem");
            File.WriteAllText(tmpKey, r.PrivateKey);
            args = $"-i \"{tmpKey}\" {args}";
            Task.Run(async () => { await Task.Delay(30_000); try { File.Delete(tmpKey); } catch { } });
        }
    }

    Process.Start(new ProcessStartInfo
    {
        FileName        = sshExe,
        Arguments       = args,
        UseShellExecute = true
    });
}

static string? FindExecutable(string name)
{
    var paths = new[]
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System32), "OpenSSH", name),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PuTTY", name),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "PuTTY", name),
        name  // PATH
    };
    foreach (var p in paths)
        if (File.Exists(p) || (p == name && ExistsOnPath(name)))
            return p;
    return null;
}

static bool ExistsOnPath(string name)
{
    try
    {
        var r = Process.Start(new ProcessStartInfo("where", name) { RedirectStandardOutput = true, UseShellExecute = false });
        r?.WaitForExit(2000);
        return r?.ExitCode == 0;
    }
    catch { return false; }
}

static string? ReadApiBase()
{
    try
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OrkunPAM\LaunchHelper");
        return key?.GetValue("ApiBaseUrl") as string;
    }
    catch { return null; }
}

static void RegisterUriScheme()
{
    try
    {
        var exe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "";
        using var root = Registry.ClassesRoot.CreateSubKey("orkunpam");
        root.SetValue("", "URL:orkunpam Protocol");
        root.SetValue("URL Protocol", "");
        using var cmd = root.CreateSubKey(@"shell\open\command");
        cmd.SetValue("", $"\"{ exe}\" \"%1\"");
    }
    catch (UnauthorizedAccessException)
    {
        Console.Error.WriteLine("Run as Administrator to register the URI scheme.");
    }
}

static void Error(string msg)
{
    Console.Error.WriteLine($"[OrkunPAM LaunchHelper] {msg}");
    try { MessageBox(IntPtr.Zero, msg, "OrkunPAM LaunchHelper", 0x10); } catch { }
}

// Minimal P/Invoke for MessageBox (avoids WinForms dependency)
[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

internal record RedeemWrapper(bool Success, RedeemResult? Data);
internal record RedeemResult(
    string  Protocol,
    string  Host,
    int     Port,
    string? Username,
    string? Password,
    string? PrivateKey);
