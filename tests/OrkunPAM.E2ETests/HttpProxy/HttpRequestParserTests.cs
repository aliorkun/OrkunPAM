using System.Net;
using System.Net.Sockets;
using System.Text;
using OrkunPAM.HttpProxy.Protocol;

namespace OrkunPAM.E2ETests.HttpProxy;

/// <summary>
/// Tests for the HTTP proxy request parser.
/// HttpRequestParser.ReadAsync requires a NetworkStream, so each test creates a
/// real loopback TCP socket pair: bytes are written on one end and parsed on the other.
/// </summary>
public sealed class HttpRequestParserTests
{
    // ── Socket pair helper ────────────────────────────────────────────

    private static async Task<(TcpClient client, TcpClient server, TcpListener listener)>
        MakePairAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var clientTcp = new TcpClient();
        var acceptTask = listener.AcceptTcpClientAsync();
        await clientTcp.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        var serverTcp = await acceptTask;

        return (clientTcp, serverTcp, listener);
    }

    private static async Task<ParsedRequest?> ParseAsync(string rawRequest)
    {
        var (client, server, listener) = await MakePairAsync();
        try
        {
            await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes(rawRequest));
            return await HttpRequestParser.ReadAsync(server.GetStream(), CancellationToken.None);
        }
        finally
        {
            client.Dispose();
            server.Dispose();
            listener.Stop();
        }
    }

    // ── Parsing tests ───────────────────────────────────────────────

    [Fact]
    [Trait("Category", "E2E")]
    public async Task Parse_GetAbsoluteUri_ExtractsHostPort80()
    {
        var req = await ParseAsync("GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");

        Assert.NotNull(req);
        Assert.Equal("GET", req!.Method);
        Assert.Equal("http://example.com/path?q=1", req.RequestUri);
        Assert.Equal("example.com", req.TargetHost);
        Assert.Equal(80, req.TargetPort);
        Assert.False(req.IsConnect);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task Parse_Connect_ExtractsHostPort443()
    {
        var req = await ParseAsync("CONNECT secure.example.com:443 HTTP/1.1\r\nHost: secure.example.com:443\r\n\r\n");

        Assert.NotNull(req);
        Assert.Equal("CONNECT", req!.Method);
        Assert.Equal("secure.example.com", req.TargetHost);
        Assert.Equal(443, req.TargetPort);
        Assert.True(req.IsConnect);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task Parse_Connect_NonStandardPort()
    {
        var req = await ParseAsync("CONNECT internal.corp:8443 HTTP/1.1\r\n\r\n");

        Assert.NotNull(req);
        Assert.Equal("internal.corp", req!.TargetHost);
        Assert.Equal(8443, req.TargetPort);
        Assert.True(req.IsConnect);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task Parse_RelativeUri_UsesHostHeader()
    {
        var req = await ParseAsync(
            "GET /api/resource HTTP/1.1\r\nHost: api.example.com:9090\r\n\r\n");

        Assert.NotNull(req);
        Assert.Equal("api.example.com", req!.TargetHost);
        Assert.Equal(9090, req.TargetPort);
        Assert.False(req.IsConnect);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task Parse_HttpsAbsoluteUri_DefaultPort443()
    {
        var req = await ParseAsync(
            "GET https://secure.example.com/page HTTP/1.1\r\nHost: secure.example.com\r\n\r\n");

        Assert.NotNull(req);
        Assert.Equal("secure.example.com", req!.TargetHost);
        Assert.Equal(443, req.TargetPort);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task Parse_ExtractsProxyAuthorizationHeader()
    {
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:secret"));
        var req = await ParseAsync(
            $"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {b64}\r\n\r\n");

        Assert.NotNull(req);
        Assert.NotNull(req!.ProxyAuthorization);
        Assert.StartsWith("Basic ", req.ProxyAuthorization, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task Parse_MultipleHeaders_AllPresent()
    {
        var req = await ParseAsync(
            "GET http://example.com/ HTTP/1.1\r\n" +
            "Host: example.com\r\n" +
            "User-Agent: TestProxy/2.0\r\n" +
            "Accept: */*\r\n" +
            "\r\n");

        Assert.NotNull(req);
        Assert.Contains(req!.Headers, h =>
            h.Name.Equals("User-Agent", StringComparison.OrdinalIgnoreCase) &&
            h.Value == "TestProxy/2.0");
    }

    // ── ParseBasicAuth — pure tests (no socket needed) ───────────────────

    [Theory]
    [Trait("Category", "E2E")]
    [InlineData("admin",           "P@ssword!")]
    [InlineData("user@domain.com", "pass:with:colons")]
    [InlineData("u",               "")]
    public void ParseBasicAuth_Valid_DecodesCorrectly(string username, string password)
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
        var (u, p) = HttpRequestParser.ParseBasicAuth($"Basic {encoded}");

        Assert.Equal(username, u);
        Assert.Equal(password, p);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void ParseBasicAuth_NullHeader_ReturnsNulls()
    {
        var (u, p) = HttpRequestParser.ParseBasicAuth(null);
        Assert.Null(u);
        Assert.Null(p);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void ParseBasicAuth_BearerScheme_ReturnsNulls()
    {
        var (u, p) = HttpRequestParser.ParseBasicAuth("Bearer some.jwt.token");
        Assert.Null(u);
        Assert.Null(p);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void ParseBasicAuth_InvalidBase64_ReturnsNulls()
    {
        var (u, p) = HttpRequestParser.ParseBasicAuth("Basic !!!not-base64!!!");
        Assert.Null(u);
        Assert.Null(p);
    }
}
