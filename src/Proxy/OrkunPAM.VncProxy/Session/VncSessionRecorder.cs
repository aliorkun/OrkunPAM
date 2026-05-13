namespace OrkunPAM.VncProxy.Session;

/// <summary>
/// Records raw RFB traffic (target→client direction, i.e., framebuffer updates) to a binary
/// .rfb file for audit and playback purposes.
///
/// File format:
///   Bytes 0-7:  Magic "ORKNVNC\0" (8 bytes)
///   Bytes 8-15: Unix epoch (int64 LE, UTC session start time)
///   Bytes 16+:  Raw RFB messages forwarded from target to client
/// </summary>
internal sealed class VncSessionRecorder : IAsyncDisposable
{
    private readonly FileStream? _file;
    private readonly object _lock = new();

    public string? FilePath { get; }

    private VncSessionRecorder(FileStream? file, string? filePath)
    {
        _file = file;
        FilePath = filePath;
    }

    public static VncSessionRecorder Create(
        string directory, string sessionId, string pamUser, string targetHost)
    {
        try
        {
            Directory.CreateDirectory(directory);

            // Sanitise filename components
            var safeUser   = SanitiseName(pamUser);
            var safeTarget = SanitiseName(targetHost);
            var ts         = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var fileName   = $"{sessionId}_{safeUser}_{safeTarget}_{ts}.rfb";
            var filePath   = Path.Combine(directory, fileName);

            var file = new FileStream(filePath, FileMode.Create, FileAccess.Write,
                FileShare.None, bufferSize: 65536, useAsync: true);

            // Write 8-byte magic header
            file.Write("ORKNVNC\0"u8);

            // Write 8-byte Unix epoch (little-endian)
            Span<byte> tsBuf = stackalloc byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(
                tsBuf, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            file.Write(tsBuf);

            return new VncSessionRecorder(file, filePath);
        }
        catch
        {
            return new VncSessionRecorder(null, null);
        }
    }

    public void Write(ReadOnlySpan<byte> data)
    {
        if (_file == null || data.IsEmpty) return;
        lock (_lock)
        {
            try { _file.Write(data); }
            catch { /* best-effort — don’t crash session if recording fails */ }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_file != null)
        {
            try { await _file.FlushAsync(); }
            catch { /* best-effort */ }
            finally { await _file.DisposeAsync(); }
        }
    }

    private static string SanitiseName(string name)
    {
        var chars = Path.GetInvalidFileNameChars();
        var sb = new System.Text.StringBuilder(name.Length);
        foreach (var c in name.AsSpan())
            sb.Append(Array.IndexOf(chars, c) >= 0 ? '_' : c);
        return sb.Length > 32 ? sb.ToString(0, 32) : sb.ToString();
    }
}
