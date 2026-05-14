using System.Text;

namespace OrkunPAM.HttpProxy.Session;

/// <summary>
/// Writes tab-separated audit log entries for each proxied HTTP request.
///
/// Log line format (one per request):
///   timestamp \t sessionId \t pamUser \t clientIp \t method \t url \t statusCode \t durationMs \t vaultInjected
///
/// Credentials are never logged. The vault injection flag only indicates
/// that a credential was injected, not which credential.
/// </summary>
internal sealed class HttpSessionLogger
{
    private readonly string _directory;

    private HttpSessionLogger(string directory) => _directory = directory;

    public static HttpSessionLogger Create(
        string directory, string sessionId, string pamUser, string clientIp)
    {
        try { Directory.CreateDirectory(directory); }
        catch { /* best-effort */ }
        return new HttpSessionLogger(directory);
    }

    public void Write(
        string sessionId, string pamUser, string clientIp,
        string method, string url, int statusCode, long durationMs, bool vaultInjected)
    {
        try
        {
            // One file per day, rotated automatically
            var fileName = $"http-{DateTime.UtcNow:yyyyMMdd}.log";
            var filePath = Path.Combine(_directory, fileName);

            // Sanitise URL: strip credentials embedded in URL if any (e.g. http://user:pass@host/)
            var safeUrl = StripCredentialsFromUrl(url);

            var line = new StringBuilder(256);
            line.Append(DateTimeOffset.UtcNow.ToString("o")).Append('\t');
            line.Append(sessionId).Append('\t');
            line.Append(pamUser).Append('\t');
            line.Append(clientIp).Append('\t');
            line.Append(method).Append('\t');
            line.Append(safeUrl).Append('\t');
            line.Append(statusCode).Append('\t');
            line.Append(durationMs).Append('\t');
            line.AppendLine(vaultInjected ? "true" : "false");

            // Append to shared daily file (thread-safe via lock)
            lock (FileLock(filePath))
            {
                File.AppendAllText(filePath, line.ToString(), Encoding.UTF8);
            }
        }
        catch { /* best-effort — never crash a session due to logging failure */ }
    }

    private static string StripCredentialsFromUrl(string url)
    {
        try
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
                !string.IsNullOrEmpty(uri.UserInfo))
            {
                return $"{uri.Scheme}://{uri.Host}{(uri.IsDefaultPort ? "" : ":" + uri.Port)}{uri.PathAndQuery}";
            }
        }
        catch { /* fall through */ }
        return url;
    }

    // Simple per-file lock objects to prevent interleaving in multi-session scenarios
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, object> _locks = new();
    private static object FileLock(string path) => _locks.GetOrAdd(path, _ => new object());
}
