using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OrkunPAM.SshProxy.Session;

/// <summary>
/// Records SSH session terminal output in asciinema v2 format, then encrypts
/// the recording with AES-256-GCM using a per-session DEK.
///
/// File layout on disk:
///   {sessionId}.ascrec  — nonce(12) + AES-256-GCM ciphertext + tag(16)
///   {sessionId}.dek     — DPAPI-protected DEK (Windows) or raw DEK with restricted permissions (non-Windows)
///
/// Only the target→client direction (terminal output) is recorded; the client→target
/// direction (user keystrokes) is intentionally omitted to avoid capturing passwords
/// typed before PAM processes them.
/// </summary>
internal sealed class SessionRecorder
{
    private readonly string _recDir;
    private readonly ILogger _log;
    private readonly PtyParams? _pty;

    private readonly List<(double Elapsed, string Data)> _events = new();
    private DateTime _startUtc;
    private string? _recId;
    private bool _started;
    private bool _stopped;

    internal SessionRecorder(string recDir, ILogger log, PtyParams? pty)
    {
        _recDir = recDir;
        _log = log;
        _pty = pty;
    }

    internal void Start(byte[]? sessionId)
    {
        _startUtc = DateTime.UtcNow;
        var ts = new DateTimeOffset(_startUtc).ToUnixTimeSeconds();
        var shortId = sessionId != null
            ? Convert.ToHexString(sessionId)[..Math.Min(12, sessionId.Length * 2)]
            : Guid.NewGuid().ToString("N")[..12];
        _recId = $"{ts}_{shortId}";
        _started = true;
    }

    internal void WriteOutput(byte[] data)
    {
        if (!_started || _stopped || data.Length == 0) return;
        var elapsed = (DateTime.UtcNow - _startUtc).TotalSeconds;
        _events.Add((elapsed, Encoding.UTF8.GetString(data)));
    }

    internal void Stop() => _stopped = true;

    internal async Task FlushAsync()
    {
        if (!_started || _recId == null || _events.Count == 0) return;

        try
        {
            Directory.CreateDirectory(_recDir);

            var plaintext = BuildAsciinema();

            var dek = new byte[32];
            RandomNumberGenerator.Fill(dek);
            var nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using (var gcm = new AesGcm(dek, 16))
                gcm.Encrypt(nonce, plaintext, ciphertext, tag);

            var recPath = Path.Combine(_recDir, $"{_recId}.ascrec");
            await using (var f = File.Create(recPath))
            {
                await f.WriteAsync(nonce);
                await f.WriteAsync(ciphertext);
                await f.WriteAsync(tag);
            }

            var dekPath = Path.Combine(_recDir, $"{_recId}.dek");
            byte[] dekToStore;
            if (OperatingSystem.IsWindows())
            {
                // DPAPI-protect the DEK so only the local machine service account can decrypt it
                dekToStore = ProtectDekWindows(dek);
            }
            else
            {
                dekToStore = (byte[])dek.Clone();
            }

            await File.WriteAllBytesAsync(dekPath, dekToStore);

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(dekPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(dekToStore);

            _log.LogInformation("Recording saved: {Path} ({Events} events, {Bytes}B plaintext)",
                recPath, _events.Count, plaintext.Length);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to save recording for session {Id}", _recId);
        }
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ProtectDekWindows(byte[] dek) =>
        System.Security.Cryptography.ProtectedData.Protect(
            dek, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);

    private byte[] BuildAsciinema()
    {
        var sb = new StringBuilder();

        var header = new
        {
            version = 2,
            width  = (int)(_pty?.WidthChars  ?? 80),
            height = (int)(_pty?.HeightRows   ?? 24),
            timestamp = new DateTimeOffset(_startUtc).ToUnixTimeSeconds(),
            title = _recId,
            env = new { TERM = _pty?.TermType ?? "xterm-256color" }
        };
        // Anonymous type property names are already lowercase; env.TERM stays uppercase — correct for asciinema v2
        sb.AppendLine(JsonSerializer.Serialize(header));

        foreach (var (elapsed, data) in _events)
            sb.AppendLine($"[{elapsed:F6},\"o\",{JsonSerializer.Serialize(data)}]");

        return Encoding.UTF8.GetBytes(sb.ToString());
    }
}
