using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OrkunPAM.Cryptography;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Service for decrypting and parsing session recordings.
/// Supports SSH (asciinema v2 encrypted), RDP (binary v2 encrypted), HTTP (JSONL encrypted).
/// </summary>
public interface IRecordingPlaybackService
{
    /// <summary>Get recording metadata without streaming full content.</summary>
    Task<RecordingMetadata?> GetMetadataAsync(string recordingPath, string sessionType);

    /// <summary>Stream decrypted recording content as bytes.</summary>
    Task<byte[]?> GetDecryptedContentAsync(string recordingPath);

    /// <summary>Parse SSH recording (asciinema v2 format) into timed events.</summary>
    Task<AsciinemaRecording?> ParseSshRecordingAsync(string recordingPath);

    /// <summary>Parse HTTP recording (JSONL format) into request/response pairs.</summary>
    Task<List<HttpRecordingEntry>?> ParseHttpRecordingAsync(string recordingPath);

    /// <summary>Search within SSH recording content for a keyword.</summary>
    Task<List<RecordingSearchResult>> SearchSshRecordingAsync(string recordingPath, string keyword);

    /// <summary>Verify hash chain integrity of a recording file.</summary>
    Task<RecordingIntegrityResult> VerifyIntegrityAsync(string recordingPath);
}

public class RecordingPlaybackService : IRecordingPlaybackService
{
    private readonly IVaultEncryptionService _vault;
    private readonly IKeyStore _keyStore;
    private readonly ILogger<RecordingPlaybackService> _logger;

    // HKDF info label for recording integrity key derivation
    private static readonly byte[] RecordingIntegrityLabel = "OrkunPAM-Recording-Integrity-v1"u8.ToArray();

    // Recording file magic bytes for format detection
    private static readonly byte[] SshMagic = "OPAM-SSH-REC"u8.ToArray();
    private static readonly byte[] RdpMagic = "OPAM-RDP-REC"u8.ToArray();
    private static readonly byte[] HttpMagic = "OPAM-HTTP-REC"u8.ToArray();

    public RecordingPlaybackService(IVaultEncryptionService vault, IKeyStore keyStore, ILogger<RecordingPlaybackService> logger)
    {
        _vault = vault;
        _keyStore = keyStore;
        _logger = logger;
    }

    public async Task<RecordingMetadata?> GetMetadataAsync(string recordingPath, string sessionType)
    {
        if (string.IsNullOrEmpty(recordingPath) || !File.Exists(recordingPath))
        {
            _logger.LogWarning("Recording file not found: {Path}", recordingPath);
            return null;
        }

        try
        {
            var fileInfo = new FileInfo(recordingPath);
            var format = DetectFormat(recordingPath, sessionType);

            var metadata = new RecordingMetadata
            {
                FileSizeBytes = fileInfo.Length,
                Format = format,
                CreatedAtUtc = fileInfo.CreationTimeUtc
            };

            // For SSH recordings, try to parse the header for duration and watermark
            if (format == RecordingFormat.AsciinemaV2)
            {
                var recording = await ParseSshRecordingAsync(recordingPath);
                if (recording != null)
                {
                    metadata.DurationSeconds = recording.Header.Duration;
                    metadata.TerminalWidth = recording.Header.Width;
                    metadata.TerminalHeight = recording.Header.Height;
                    metadata.WatermarkTitle = recording.Header.Title;
                }
            }

            return metadata;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read recording metadata: {Path}", recordingPath);
            return null;
        }
    }

    public async Task<byte[]?> GetDecryptedContentAsync(string recordingPath)
    {
        if (string.IsNullOrEmpty(recordingPath) || !File.Exists(recordingPath))
            return null;

        try
        {
            var encryptedBytes = await File.ReadAllBytesAsync(recordingPath);
            return DecryptRecording(encryptedBytes);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decrypt recording: {Path}", recordingPath);
            return null;
        }
    }

    public async Task<AsciinemaRecording?> ParseSshRecordingAsync(string recordingPath)
    {
        var content = await GetDecryptedContentAsync(recordingPath);
        if (content == null) return null;

        try
        {
            var text = Encoding.UTF8.GetString(content);
            return ParseAsciinemaV2(text);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse SSH recording: {Path}", recordingPath);
            return null;
        }
    }

    public async Task<List<HttpRecordingEntry>?> ParseHttpRecordingAsync(string recordingPath)
    {
        var content = await GetDecryptedContentAsync(recordingPath);
        if (content == null) return null;

        try
        {
            var text = Encoding.UTF8.GetString(content);
            var entries = new List<HttpRecordingEntry>();

            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var entry = JsonSerializer.Deserialize<HttpRecordingEntry>(line, JsonOpts);
                if (entry != null)
                    entries.Add(entry);
            }

            return entries;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse HTTP recording: {Path}", recordingPath);
            return null;
        }
    }

    public async Task<List<RecordingSearchResult>> SearchSshRecordingAsync(string recordingPath, string keyword)
    {
        var results = new List<RecordingSearchResult>();
        if (string.IsNullOrEmpty(keyword)) return results;

        var recording = await ParseSshRecordingAsync(recordingPath);
        if (recording == null) return results;

        var keywordLower = keyword.ToLowerInvariant();

        foreach (var evt in recording.Events)
        {
            // Only search output events (type "o")
            if (evt.EventType != "o") continue;

            if (evt.Data.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                results.Add(new RecordingSearchResult
                {
                    TimestampSeconds = evt.TimestampSeconds,
                    MatchedText = ExtractContext(evt.Data, keyword, contextChars: 80),
                    EventIndex = recording.Events.IndexOf(evt)
                });
            }
        }

        return results;
    }

    public async Task<RecordingIntegrityResult> VerifyIntegrityAsync(string recordingPath)
    {
        if (string.IsNullOrEmpty(recordingPath) || !File.Exists(recordingPath))
        {
            return new RecordingIntegrityResult
            {
                IsValid = false,
                Message = "Recording file not found"
            };
        }

        try
        {
            var fileBytes = await File.ReadAllBytesAsync(recordingPath);

            if (fileBytes.Length < 96)
            {
                return new RecordingIntegrityResult
                {
                    IsValid = false,
                    Message = "File too small for integrity verification"
                };
            }

            // Read the stored MAC from the last 32 bytes
            var storedMac = new byte[32];
            Array.Copy(fileBytes, fileBytes.Length - 32, storedMac, 0, 32);

            var contentBytes = new byte[fileBytes.Length - 32];
            Array.Copy(fileBytes, 0, contentBytes, 0, contentBytes.Length);

            // Require vault key store to be initialized for HMAC-SHA256 verification
            var dekResult = _keyStore.GetActiveDataEncryptionKey("SessionRecordings");
            if (!dekResult.IsSuccess)
            {
                return new RecordingIntegrityResult
                {
                    IsValid = false,
                    Message = "Vault not initialized — cannot verify recording integrity"
                };
            }

            // Derive a purpose-specific 256-bit HMAC key via HKDF so the DEK itself is not used directly
            var dekBytes = dekResult.Value.Key;
            var hmacKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, dekBytes, 32, null, RecordingIntegrityLabel);
            try
            {
                using var hmac = new HMACSHA256(hmacKey);
                var expectedMac = hmac.ComputeHash(contentBytes);
                var isValid = CryptographicOperations.FixedTimeEquals(storedMac, expectedMac);

                return new RecordingIntegrityResult
                {
                    IsValid = isValid,
                    Message = isValid ? "HMAC-SHA256 integrity verified" : "Integrity check failed — recording may be tampered",
                    FileHash = Convert.ToHexString(expectedMac).ToLowerInvariant()
                };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hmacKey);
                CryptographicOperations.ZeroMemory(dekBytes);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Integrity verification failed: {Path}", recordingPath);
            return new RecordingIntegrityResult
            {
                IsValid = false,
                Message = $"Verification error: {ex.Message}"
            };
        }
    }

    // ── Private helpers ──────────────────────────────────

    private byte[]? DecryptRecording(byte[] encryptedBytes)
    {
        // Skip magic header (up to 16 bytes) to find encrypted payload
        int offset = 0;
        if (encryptedBytes.Length > 16)
        {
            // Check for known magic headers
            if (StartsWithMagic(encryptedBytes, SshMagic))
                offset = SshMagic.Length;
            else if (StartsWithMagic(encryptedBytes, RdpMagic))
                offset = RdpMagic.Length;
            else if (StartsWithMagic(encryptedBytes, HttpMagic))
                offset = HttpMagic.Length;
        }

        // Strip trailing hash if present (last 32 bytes)
        int payloadLength = encryptedBytes.Length - offset;
        if (payloadLength > 32)
        {
            // Heuristic: if there's a hash chain footer, remove it before decryption
            // The encrypted payload has its own authenticated encryption (AES-GCM tag)
        }

        var payload = new byte[payloadLength];
        Array.Copy(encryptedBytes, offset, payload, 0, payloadLength);

        var result = _vault.Decrypt(payload);
        if (result.IsFailure)
        {
            _logger.LogError("Recording decryption failed: {Error}", result.Error.Message);
            return null;
        }

        return result.Value;
    }

    private static bool StartsWithMagic(byte[] data, byte[] magic)
    {
        if (data.Length < magic.Length) return false;
        for (int i = 0; i < magic.Length; i++)
        {
            if (data[i] != magic[i]) return false;
        }
        return true;
    }

    private static RecordingFormat DetectFormat(string path, string sessionType)
    {
        return sessionType.ToLowerInvariant() switch
        {
            "ssh" => RecordingFormat.AsciinemaV2,
            "rdp" => RecordingFormat.RdpBinaryV2,
            "http" or "https" => RecordingFormat.HttpJsonl,
            "vnc" => RecordingFormat.RdpBinaryV2, // VNC uses same binary format
            "sql" => RecordingFormat.HttpJsonl,    // SQL proxy logs as JSONL
            _ => RecordingFormat.Unknown
        };
    }

    /// <summary>Parse asciinema v2 format: first line is JSON header, remaining lines are [timestamp, type, data].</summary>
    private static AsciinemaRecording? ParseAsciinemaV2(string text)
    {
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0) return null;

        // First line is the header JSON
        var header = JsonSerializer.Deserialize<AsciinemaHeader>(lines[0], JsonOpts);
        if (header == null) return null;

        var events = new List<AsciinemaEvent>();
        double maxTimestamp = 0;

        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrEmpty(line)) continue;

            try
            {
                // Each event line is a JSON array: [timestamp, event_type, data]
                using var doc = JsonDocument.Parse(line);
                var arr = doc.RootElement;
                if (arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() < 3)
                    continue;

                var timestamp = arr[0].GetDouble();
                var eventType = arr[1].GetString() ?? "o";
                var data = arr[2].GetString() ?? "";

                events.Add(new AsciinemaEvent
                {
                    TimestampSeconds = timestamp,
                    EventType = eventType,
                    Data = data
                });

                if (timestamp > maxTimestamp) maxTimestamp = timestamp;
            }
            catch
            {
                // Skip malformed event lines
            }
        }

        // If header doesn't have duration, compute from last event
        if (header.Duration <= 0)
            header = header with { Duration = maxTimestamp };

        return new AsciinemaRecording
        {
            Header = header,
            Events = events
        };
    }

    private static string ExtractContext(string text, string keyword, int contextChars)
    {
        var idx = text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return text.Length > contextChars * 2 ? text[..(contextChars * 2)] : text;

        var start = Math.Max(0, idx - contextChars);
        var end = Math.Min(text.Length, idx + keyword.Length + contextChars);
        var snippet = text[start..end];

        if (start > 0) snippet = "..." + snippet;
        if (end < text.Length) snippet += "...";

        return snippet;
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };
}

// ── DTOs ────────────────────────────────────────────────────\n
public class RecordingMetadata
{
    public long FileSizeBytes { get; set; }
    public RecordingFormat Format { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public double DurationSeconds { get; set; }
    public int? TerminalWidth { get; set; }
    public int? TerminalHeight { get; set; }
    public string? WatermarkTitle { get; set; }
}

public enum RecordingFormat
{
    Unknown,
    AsciinemaV2,
    RdpBinaryV2,
    HttpJsonl
}

public record AsciinemaHeader(
    int Version,
    int Width,
    int Height,
    double Duration,
    string? Title,
    string? Command,
    Dictionary<string, string>? Env);

public class AsciinemaRecording
{
    public AsciinemaHeader Header { get; set; } = null!;
    public List<AsciinemaEvent> Events { get; set; } = new();
}

public class AsciinemaEvent
{
    public double TimestampSeconds { get; set; }
    public string EventType { get; set; } = "o"; // "o" = output, "i" = input
    public string Data { get; set; } = "";
}

public class HttpRecordingEntry
{
    public double TimestampSeconds { get; set; }
    public string Method { get; set; } = "";
    public string Url { get; set; } = "";
    public int StatusCode { get; set; }
    public Dictionary<string, string>? RequestHeaders { get; set; }
    public string? RequestBody { get; set; }
    public Dictionary<string, string>? ResponseHeaders { get; set; }
    public string? ResponseBody { get; set; }
    public double DurationMs { get; set; }
}

public class RecordingSearchResult
{
    public double TimestampSeconds { get; set; }
    public string MatchedText { get; set; } = "";
    public int EventIndex { get; set; }
}

public class RecordingIntegrityResult
{
    public bool IsValid { get; set; }
    public string Message { get; set; } = "";
    public string? FileHash { get; set; }
}
