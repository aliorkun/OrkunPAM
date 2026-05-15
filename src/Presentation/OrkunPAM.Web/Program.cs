using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using OrkunPAM.Web.Components;
using OrkunPAM.Web.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// PAM API HTTP client (TLS dev bypass in Development only)
builder.Services.AddHttpClient("PamApi", client =>
{
    client.BaseAddress = new Uri(
        builder.Configuration["PamApi:BaseUrl"] ?? "https://localhost:5001");
    client.Timeout = TimeSpan.FromSeconds(30);
}).ConfigurePrimaryHttpMessageHandler(() =>
{
    var handler = new HttpClientHandler();
    if (builder.Environment.IsDevelopment())
        handler.ServerCertificateCustomValidationCallback =
            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    return handler;
});

// Scoped per Blazor circuit
builder.Services.AddScoped<AuthStateService>();
builder.Services.AddScoped<PamApiService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(30) });
app.UseAntiforgery();

// SSH Terminal WebSocket bridge: browser <-> Blazor Web <-> PAM API (which talks to SSH Proxy)
app.Map("/ws/ssh", async (HttpContext context) =>
{
    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = 400;
        return;
    }

    var deviceId = context.Request.Query["deviceId"].ToString();
    var credentialId = context.Request.Query["credentialId"].ToString();
    var token = context.Request.Query["token"].ToString();
    var cols = int.TryParse(context.Request.Query["cols"], out var c) ? c : 80;
    var rows = int.TryParse(context.Request.Query["rows"], out var r) ? r : 24;

    if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(token))
    {
        context.Response.StatusCode = 400;
        return;
    }

    var browserWs = await context.WebSockets.AcceptWebSocketAsync();
    var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("SshBridge");

    try
    {
        // 1. Call PAM API to create SSH session and get target info
        var pamApiBase = builder.Configuration["PamApi:BaseUrl"] ?? "http://localhost:5000";
        using var httpClient = new HttpClient { BaseAddress = new Uri(pamApiBase) };
        httpClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var sessionReq = new { deviceId, credentialId, sessionType = 0, reason = "Web SSH Terminal" };
        var sessionResp = await httpClient.PostAsJsonAsync("/api/v1/sessions/ssh/connect", sessionReq);

        string? sessionId = null;
        if (sessionResp.IsSuccessStatusCode)
        {
            var sessJson = await sessionResp.Content.ReadFromJsonAsync<JsonElement>();
            if (sessJson.TryGetProperty("data", out var sd) && sd.TryGetProperty("sessionId", out var si))
                sessionId = si.GetString();
        }
        else
        {
            var err = await sessionResp.Content.ReadAsStringAsync();
            logger.LogWarning("SSH session creation failed: {Status} {Error}", sessionResp.StatusCode, err);
            // Continue anyway — session tracking optional for terminal
        }

        // 2. Get device info + credential from API
        var deviceResp = await httpClient.GetAsync($"/api/v1/devices/{deviceId}");
        string targetHost = "";
        int targetPort = 22;

        if (deviceResp.IsSuccessStatusCode)
        {
            var deviceJson = await deviceResp.Content.ReadFromJsonAsync<JsonElement>();
            if (deviceJson.TryGetProperty("data", out var data))
            {
                targetHost = data.TryGetProperty("ipAddress", out var ip) ? ip.GetString() ?? "" : "";
                if (data.TryGetProperty("connectionPort", out var cp) && cp.ValueKind == JsonValueKind.Number)
                    targetPort = cp.GetInt32();
            }
        }

        if (string.IsNullOrEmpty(targetHost))
        {
            await SendJsonAsync(browserWs, new { t = "error", msg = "Device not found or no IP address" });
            await browserWs.CloseAsync(WebSocketCloseStatus.InternalServerError, "No target", CancellationToken.None);
            return;
        }

        // 3. Checkout credential (returns decrypted password)
        string sshUser = "root", sshPass = "";
        var credResp = await httpClient.PostAsJsonAsync($"/api/v1/vault/credentials/{credentialId}/checkout",
            new { reason = "Web SSH Terminal", maxMinutes = 60 });

        if (credResp.IsSuccessStatusCode)
        {
            var credJson = await credResp.Content.ReadFromJsonAsync<JsonElement>();
            if (credJson.TryGetProperty("data", out var cd))
            {
                sshUser = cd.TryGetProperty("username", out var u) ? u.GetString() ?? "root" : "root";
                sshPass = cd.TryGetProperty("password", out var p) ? p.GetString() ?? "" : "";
            }
        }
        else
        {
            // Credential might already be checked out or approval required
            var errBody = await credResp.Content.ReadAsStringAsync();
            logger.LogWarning("Credential checkout failed: {Status} {Body}", credResp.StatusCode, errBody);
            // Try to get username from credential info at least
            var credInfoResp = await httpClient.GetAsync($"/api/v1/vault/credentials?pageSize=50&deviceId={deviceId}");
            if (credInfoResp.IsSuccessStatusCode)
            {
                var infoJson = await credInfoResp.Content.ReadFromJsonAsync<JsonElement>();
                if (infoJson.TryGetProperty("data", out var arr) && arr.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in arr.EnumerateArray())
                    {
                        var itemId = item.TryGetProperty("id", out var iid) ? iid.GetString() : "";
                        if (itemId == credentialId)
                        {
                            sshUser = item.TryGetProperty("username", out var iu) ? iu.GetString() ?? "root" : "root";
                            break;
                        }
                    }
                }
            }
        }

        if (string.IsNullOrEmpty(sshPass))
        {
            await SendJsonAsync(browserWs, new { t = "error", msg = "Could not retrieve credential password. Check vault." });
            await browserWs.CloseAsync(WebSocketCloseStatus.InternalServerError, "No credential", CancellationToken.None);
            return;
        }

        logger.LogInformation("SSH bridge: connecting to {Host}:{Port} as {User} for device {DeviceId}",
            targetHost, targetPort, sshUser, deviceId);

        // 4. Launch plink.exe to connect to target
        var plinkPath = @"C:\OrkunPAM\Tools\plink.exe";
        var psi = new System.Diagnostics.ProcessStartInfo(plinkPath,
            $"-ssh -P {targetPort} -l {sshUser} -pw {sshPass} {targetHost} -no-antispoof")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var proc = System.Diagnostics.Process.Start(psi);
        if (proc == null)
        {
            await SendJsonAsync(browserWs, new { t = "error", msg = "Failed to start SSH" });
            await browserWs.CloseAsync(WebSocketCloseStatus.InternalServerError, "Process failed", CancellationToken.None);
            return;
        }

        await SendJsonAsync(browserWs, new { t = "connected" });
        logger.LogInformation("SSH started (PID {Pid}) for {User}@{Host}:{Port}", proc.Id, sshUser, targetHost, targetPort);

        using var cts = new CancellationTokenSource();

        // SSH stdout -> Browser
        var stdoutToBrowser = Task.Run(async () =>
        {
            var buf = new byte[4096];
            try
            {
                while (!cts.Token.IsCancellationRequested && !proc.HasExited)
                {
                    var n = await proc.StandardOutput.BaseStream.ReadAsync(buf, 0, buf.Length, cts.Token);
                    if (n == 0) break;
                    if (browserWs.State == WebSocketState.Open)
                        await browserWs.SendAsync(new ArraySegment<byte>(buf, 0, n),
                            WebSocketMessageType.Binary, true, cts.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { logger.LogDebug("StdoutToBrowser ended: {Msg}", ex.Message); }
        }, cts.Token);

        // SSH stderr -> Browser
        var stderrToBrowser = Task.Run(async () =>
        {
            var buf = new byte[4096];
            try
            {
                while (!cts.Token.IsCancellationRequested && !proc.HasExited)
                {
                    var n = await proc.StandardError.BaseStream.ReadAsync(buf, 0, buf.Length, cts.Token);
                    if (n == 0) break;
                    if (browserWs.State == WebSocketState.Open)
                        await browserWs.SendAsync(new ArraySegment<byte>(buf, 0, n),
                            WebSocketMessageType.Binary, true, cts.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch { }
        }, cts.Token);

        // Browser -> SSH stdin
        var browserToStdin = Task.Run(async () =>
        {
            var buf = new byte[4096];
            try
            {
                while (!cts.Token.IsCancellationRequested && browserWs.State == WebSocketState.Open)
                {
                    var result = await browserWs.ReceiveAsync(new ArraySegment<byte>(buf), cts.Token);
                    if (result.MessageType == WebSocketMessageType.Close) break;

                    if (result.MessageType == WebSocketMessageType.Text)
                    {
                        var json = Encoding.UTF8.GetString(buf, 0, result.Count);
                        try
                        {
                            var msg = JsonSerializer.Deserialize<JsonElement>(json);
                            var type = msg.GetProperty("t").GetString();
                            if (type == "i" && msg.TryGetProperty("d", out var d))
                            {
                                var inputBytes = Convert.FromBase64String(d.GetString()!);
                                await proc.StandardInput.BaseStream.WriteAsync(inputBytes, 0, inputBytes.Length, cts.Token);
                                await proc.StandardInput.BaseStream.FlushAsync(cts.Token);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { logger.LogDebug("BrowserToStdin ended: {Msg}", ex.Message); }
        }, cts.Token);

        await Task.WhenAny(stdoutToBrowser, browserToStdin);
        cts.Cancel();

        if (!proc.HasExited)
        {
            try { proc.Kill(); } catch { }
        }

        // End session in API
        if (!string.IsNullOrEmpty(sessionId))
        {
            try
            {
                var proxySecret = builder.Configuration["PamApi:ProxySecret"]
                    ?? builder.Configuration["ProxyService:Secret"] ?? "";
                using var endClient = new HttpClient { BaseAddress = new Uri(pamApiBase) };
                endClient.DefaultRequestHeaders.Add("X-Proxy-Secret", proxySecret);
                await endClient.PostAsJsonAsync($"/api/v1/sessions/{sessionId}/end",
                    new { durationSeconds = 0, recordingPath = (string?)null });
                logger.LogInformation("Session {SessionId} marked as completed", sessionId);
            }
            catch (Exception ex2) { logger.LogWarning("Failed to end session: {Msg}", ex2.Message); }
        }

        // Check in credential
        try
        {
            await httpClient.PostAsync($"/api/v1/vault/credentials/{credentialId}/checkin", null);
        }
        catch { }

        logger.LogInformation("SSH bridge closed for device {DeviceId}", deviceId);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "SSH bridge error for device {DeviceId}", deviceId);
        if (browserWs.State == WebSocketState.Open)
        {
            await SendJsonAsync(browserWs, new { t = "error", msg = ex.Message });
            await browserWs.CloseAsync(WebSocketCloseStatus.InternalServerError, ex.Message, CancellationToken.None);
        }
    }
});

static async Task SendJsonAsync(WebSocket ws, object data)
{
    var json = JsonSerializer.Serialize(data);
    var bytes = Encoding.UTF8.GetBytes(json);
    await ws.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
}

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
