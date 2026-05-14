using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace OrkunPAM.E2ETests.Helpers;

internal static class NetHelpers
{
    /// <summary>Finds an available TCP port on loopback.</summary>
    public static int GetFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    /// <summary>Polls until the given port accepts a TCP connection or the timeout expires.</summary>
    public static async Task WaitForPortAsync(int port, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var tc = new TcpClient();
                await tc.ConnectAsync(IPAddress.Loopback, port);
                return;
            }
            catch
            {
                await Task.Delay(50);
            }
        }
        throw new TimeoutException($"Port {port} not ready after {timeout.TotalSeconds:F0}s");
    }

    /// <summary>Reads one HTTP response line (up to \r\n) from a NetworkStream.</summary>
    public static async Task<string> ReadResponseLineAsync(NetworkStream stream, CancellationToken ct = default)
    {
        var sb = new StringBuilder(128);
        var buf = new byte[1];
        while (true)
        {
            int n = await stream.ReadAsync(buf, ct);
            if (n == 0) break;

            char ch = (char)buf[0];
            if (ch == '\n' && sb.Length > 0 && sb[^1] == '\r')
            {
                sb.Remove(sb.Length - 1, 1);
                break;
            }
            sb.Append(ch);
            if (sb.Length > 8192) break;
        }
        return sb.ToString();
    }
}

/// <summary>
/// Lightweight HTTP server using HttpListener that simulates PAM API responses.
/// Accepts any login for the configured ValidUsername + ValidPassword.
/// Also accepts proxy-service login with E2EConstants.TestProxySecret.
/// </summary>
internal sealed class MockPamApiServer : IDisposable
{
    private readonly HttpListener _listener;
    private readonly CancellationTokenSource _cts = new();

    public string BaseUrl { get; }
    public string ValidUsername { get; set; } = "admin";
    public string ValidPassword { get; set; } = "P@ssword-e2e!";

    public MockPamApiServer()
    {
        int port = NetHelpers.GetFreePort();
        BaseUrl = $"http://localhost:{port}";
        _listener = new HttpListener();
        _listener.Prefixes.Add($"{BaseUrl}/");
        _listener.Start();
        _ = Task.Run(RunAsync);
    }

    private async Task RunAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); }
            catch { return; }
            _ = Task.Run(() => HandleAsync(ctx));
        }
    }

    private async Task HandleAsync(HttpListenerContext ctx)
    {
        try
        {
            var path = ctx.Request.Url!.AbsolutePath.ToLowerInvariant();

            if (ctx.Request.HttpMethod == "POST" && path == "/api/v1/auth/login")
                await HandleLoginAsync(ctx);
            else if (ctx.Request.HttpMethod == "GET" && path.StartsWith("/api/v1/policy/session"))
                WriteJson(ctx, 200, """{"success":true,"data":{"idleTimeoutMinutes":60,"maxConcurrentSessions":50}}""");
            else if (ctx.Request.HttpMethod == "POST" && path.EndsWith("/end"))
                WriteJson(ctx, 200, """{"success":true}""");
            else
            {
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            }
        }
        catch { /* best-effort mock */ }
    }

    private async Task HandleLoginAsync(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        try
        {
            using var doc = JsonDocument.Parse(body);
            var username = doc.RootElement.GetProperty("username").GetString() ?? "";
            var password  = doc.RootElement.GetProperty("password").GetString() ?? "";

            bool valid = (username == ValidUsername && password == ValidPassword)
                      || (username == "proxy-service" && password == E2EConstants.TestProxySecret);

            if (valid)
                WriteJson(ctx, 200, """{"success":true,"data":{"accessToken":"e2e-jwt","userId":"00000000-0000-0000-0000-000000000001","username":"admin","displayName":"Admin","mfaRequired":false,"mustChangePassword":false,"passwordExpired":false}}""");
            else
                WriteJson(ctx, 401, """{"success":false,"errors":["Invalid credentials"]}""");
        }
        catch
        {
            WriteJson(ctx, 400, """{"success":false}""");
        }
    }

    private static void WriteJson(HttpListenerContext ctx, int statusCode, string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        ctx.Response.StatusCode = statusCode;
        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength64 = bytes.Length;
        ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
        ctx.Response.OutputStream.Close();
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
    }
}

internal static class E2EConstants
{
    public const string TestProxySecret = "e2e-test-proxy-secret-at-least-32chars-ok!";
}
