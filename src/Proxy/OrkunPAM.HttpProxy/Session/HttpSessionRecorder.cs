using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OrkunPAM.HttpProxy.Session;

/// <summary>
/// Records HTTP proxy session activity (request/response metadata) with AES-256-GCM encryption.
///
/// File layout on disk:
///   {sessionId}.httprec  — nonce(12) + AES-256-GCM ciphertext + tag(16)
///   {sessionId}.dek      — DPAPI-protected DEK (Windows) or restricted-permission raw DEK
///
/// Security: Only metadata is recorded (method, URL, status, headers, body hash).
/// Full request/response bodies are NOT stored to prevent credential leakage.
/// </summary>
internal sealed class HttpSessionRecorder
{
    private readonly string _recDir;
    private readonly ILogger _log;
    private readonly HashChainStore? _hashChain;

    private readonly List<HttpRecordEntry> _entries = [];
    private DateTime _startUtc;
    private string? _recId;
    private bool _started;
    private bool _stopped;

    internal HttpSessionRecorder(string recDir, ILogger log, HashChainStore? hashChain = null)
    {
        _recDir    = recDir;
        _log       = log;
        _hashChain = hashChain;
    }

    internal void Start(string sessionId)
    {
        _startUtc = DateTime.UtcNow;
        var ts = new DateTimeOffset(_startUtc).ToUnixTimeSeconds();
        _recId = $"{ts}_{sessionId[..Math.Min(12, sessionId.Length)]}";
        _started = true;
    }

    /// <summary>
    /// Records an HTTP request/response pair. Body content is hashed (SHA-256), not stored.
    /// </summary>
    internal void RecordExchange(HttpMethod method, string url, int statusCode,
        Dictionary<string, string> requestHeaders, Dictionary<string, string> responseHeaders,
        long requestBodyLength, byte[]? requestBodyHash,
        long responseBodyLength, byte[]? responseBodyHash)
    {
        if (!_started || _stopped) return;

        var elapsed = (DateTime.UtcNow - _startUtc).TotalSeconds;
        _entries.Add(new HttpRecordEntry
        {
            ElapsedSeconds = elapsed,
            TimestampUtc = DateTime.UtcNow.ToString("O"),
            Method = method.Method,
            Url = url,
            StatusCode = statusCode,
            RequestHeaders = requestHeaders,
            ResponseHeaders = responseHeaders,
            RequestBodyLength = requestBodyLength,
            RequestBodyHash = requestBodyHash != null ? Convert.ToHexString(requestBodyHash).ToLowerInvariant() : null,
            ResponseBodyLength = responseBodyLength,
            ResponseBodyHash = responseBodyHash != null ? Convert.ToHexString(responseBodyHash).ToLowerInvariant() : null,
        });
    }

    internal void Stop() => _stopped = true;

    internal async Task FlushAsync()
    {
        if (!_started || _recId == null || _entries.Count == 0) return;

        try
        {
            Directory.CreateDirectory(_recDir);

            var jsonOpts = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                WriteIndented = false
            };

            // Build JSONL recording: header line + one line per exchange
            var sb = new StringBuilder();
            var header = new
            {
                version = 1,
                type = "http-session",
                sessionId = _recId,
                startUtc = _startUtc.ToString("O"),
                totalExchanges = _entries.Count,
            };
            sb.AppendLine(JsonSerializer.Serialize(header, jsonOpts));

            foreach (var entry in _entries)
                sb.AppendLine(JsonSerializer.Serialize(entry, jsonOpts));

            var plaintext = Encoding.UTF8.GetBytes(sb.ToString());

            // Encrypt with AES-256-GCM using a random per-session DEK
            var dek = new byte[32];
            RandomNumberGenerator.Fill(dek);
            var nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];

            using (var gcm = new AesGcm(dek, 16))
                gcm.Encrypt(nonce, plaintext, ciphertext, tag);

            var recPath = Path.Combine(_recDir, $"{_recId}.httprec");
            await using (var f = File.Create(recPath))
            {
                await f.WriteAsync(nonce);
                await f.WriteAsync(ciphertext);
                await f.WriteAsync(tag);
            }

            // Protect the DEK
            var dekPath = Path.Combine(_recDir, $"{_recId}.dek");
            byte[] dekToStore;
            if (OperatingSystem.IsWindows())
            {
                dekToStore = ProtectDekWindows(dek);
            }
            else
            {
                dekToStore = (byte[])dek.Clone();
            }

            await File.WriteAllBytesAsync(dekPath, dekToStore);

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(dekPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            // Zero sensitive material
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(dekToStore);

            _log.LogInformation("HTTP recording saved: {Path} ({Entries} exchanges, {Bytes}B plaintext)",
                recPath, _entries.Count, plaintext.Length);

            if (_hashChain != null)
                await _hashChain.AppendAsync(_recId, recPath);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to save HTTP recording for session {Id}", _recId);
        }
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ProtectDekWindows(byte[] dek) =>
        System.Security.Cryptography.ProtectedData.Protect(
            dek, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);

    /// <summary>Computes SHA-256 hash of a byte array for body hashing.</summary>
    internal static byte[] ComputeBodyHash(byte[] body) => SHA256.HashData(body);
}

internal sealed class HttpRecordEntry
{
    public double ElapsedSeconds { get; init; }
    public required string TimestampUtc { get; init; }
    public required string Method { get; init; }
    public required string Url { get; init; }
    public int StatusCode { get; init; }
    public Dictionary<string, string>? RequestHeaders { get; init; }
    public Dictionary<string, string>? ResponseHeaders { get; init; }
    public long RequestBodyLength { get; init; }
    public string? RequestBodyHash { get; init; }
    public long ResponseBodyLength { get; init; }
    public string? ResponseBodyHash { get; init; }
}
