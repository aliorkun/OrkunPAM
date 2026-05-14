using System.Net.Sockets;
using System.Text;

namespace OrkunPAM.HttpProxy.Protocol;

/// <summary>
/// Reads and parses an HTTP/1.x request from a network stream.
/// Stops reading after the blank line that terminates the headers (\r\n\r\n).
/// The caller is responsible for reading any request body separately.
/// </summary>
internal sealed record ParsedRequest(
    string Method,
    string RequestUri,
    string Version,
    List<(string Name, string Value)> Headers,
    string? ProxyAuthorization,
    string TargetHost,
    int TargetPort,
    bool IsConnect);

internal static class HttpRequestParser
{
    private const int MaxHeaderBytes = 64 * 1024;

    public static async Task<ParsedRequest?> ReadAsync(NetworkStream stream, CancellationToken ct)
    {
        var raw = await ReadUntilDoubleCrlfAsync(stream, ct);
        if (raw == null) return null;

        var text  = Encoding.ASCII.GetString(raw);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0) return null;

        // Request line: METHOD URI HTTP/version
        var parts = lines[0].Split(' ', 3);
        if (parts.Length != 3) return null;

        var method     = parts[0].ToUpperInvariant();
        var requestUri = parts[1];
        var version    = parts[2];

        // Parse headers
        var headers  = new List<(string Name, string Value)>(16);
        string? proxyAuth = null;

        for (int i = 1; i < lines.Length; i++)
        {
            if (string.IsNullOrEmpty(lines[i])) break;
            var colon = lines[i].IndexOf(':');
            if (colon <= 0) continue;
            var name  = lines[i][..colon].Trim();
            var value = lines[i][(colon + 1)..].Trim();
            headers.Add((name, value));
            if (name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase))
                proxyAuth = value;
        }

        // Determine target host and port
        string targetHost;
        int    targetPort;
        bool   isConnect = method == "CONNECT";

        if (isConnect)
        {
            // CONNECT host:port HTTP/1.1
            var lastColon = requestUri.LastIndexOf(':');
            if (lastColon > 0 && int.TryParse(requestUri[(lastColon + 1)..], out var p))
            {
                targetHost = requestUri[..lastColon];
                targetPort = p;
            }
            else
            {
                targetHost = requestUri;
                targetPort = 443;
            }
        }
        else if (Uri.TryCreate(requestUri, UriKind.Absolute, out var absUri))
        {
            targetHost = absUri.Host;
            targetPort = absUri.IsDefaultPort ? (absUri.Scheme == "https" ? 443 : 80) : absUri.Port;
        }
        else
        {
            // Relative URI — use Host header
            var hostValue = headers.FirstOrDefault(h =>
                h.Name.Equals("Host", StringComparison.OrdinalIgnoreCase)).Value ?? "";
            var hColon = hostValue.LastIndexOf(':');
            if (hColon > 0 && int.TryParse(hostValue[(hColon + 1)..], out var hp))
            {
                targetHost = hostValue[..hColon];
                targetPort = hp;
            }
            else
            {
                targetHost = hostValue;
                targetPort = 80;
            }
        }

        if (string.IsNullOrEmpty(targetHost)) return null;

        return new ParsedRequest(method, requestUri, version, headers,
            proxyAuth, targetHost, targetPort, isConnect);
    }

    /// <summary>Decodes a Proxy-Authorization: Basic header into (username, password).</summary>
    public static (string? Username, string? Password) ParseBasicAuth(string? authHeader)
    {
        if (authHeader == null) return (null, null);
        var sp = authHeader.Split(' ', 2);
        if (sp.Length != 2 || !sp[0].Equals("Basic", StringComparison.OrdinalIgnoreCase))
            return (null, null);
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(sp[1].Trim()));
            var colon   = decoded.IndexOf(':');
            return colon < 0
                ? (decoded, null)
                : (decoded[..colon], decoded[(colon + 1)..]);
        }
        catch { return (null, null); }
    }

    // Reads byte-by-byte until \r\n\r\n, returns header bytes (excluding terminal \r\n\r\n).
    private static async Task<byte[]?> ReadUntilDoubleCrlfAsync(NetworkStream stream, CancellationToken ct)
    {
        var buf     = new byte[MaxHeaderBytes];
        int total   = 0;
        var oneByte = new byte[1];

        while (total < MaxHeaderBytes)
        {
            int read;
            try { read = await stream.ReadAsync(oneByte, ct); }
            catch { return null; }
            if (read == 0) return null;

            buf[total++] = oneByte[0];

            if (total >= 4 &&
                buf[total - 4] == '\r' && buf[total - 3] == '\n' &&
                buf[total - 2] == '\r' && buf[total - 1] == '\n')
            {
                return buf[..(total - 4)];
            }
        }
        return null;
    }
}
