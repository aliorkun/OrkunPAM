using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OrkunPAM.Persistence.Services;

public interface IItsmService
{
    Task<ItsmTestResult> TestConnectionAsync(string provider, string baseUrl, string? username, string? password, string? apiKey);
    Task<ItsmTicketValidationResult> ValidateTicketAsync(string provider, string baseUrl, string ticketNumber,
        string? username, string? password, string? apiKey);
}

public record ItsmTestResult(bool Success, string Message, int ResponseTimeMs, string? ServerVersion = null);
public record ItsmTicketValidationResult(bool Valid, string? TicketStatus, string? Summary, string? Assignee, string Message);

public sealed class ItsmService : IItsmService, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ItsmService> _logger;

    public ItsmService(ILogger<ItsmService> logger)
    {
        _logger = logger;
        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public async Task<ItsmTestResult> TestConnectionAsync(string provider, string baseUrl, string? username, string? password, string? apiKey)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using var request = provider.ToLowerInvariant() switch
            {
                "servicenow" => BuildServiceNowTestRequest(baseUrl, username, password),
                "jira" => BuildJiraTestRequest(baseUrl, username, apiKey),
                _ => throw new ArgumentException($"Unsupported ITSM provider: {provider}")
            };

            _httpClient.Timeout = TimeSpan.FromSeconds(15);
            var response = await _httpClient.SendAsync(request);
            sw.Stop();

            if (response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                var version = ExtractServerVersion(provider, body);

                _logger.LogInformation("ITSM connection test successful to {Provider} at {BaseUrl} in {Ms}ms",
                    provider, baseUrl, sw.ElapsedMilliseconds);

                return new ItsmTestResult(true, $"Connected to {provider} successfully", (int)sw.ElapsedMilliseconds, version);
            }

            sw.Stop();
            return new ItsmTestResult(false, $"{provider} returned HTTP {(int)response.StatusCode}: {response.ReasonPhrase}",
                (int)sw.ElapsedMilliseconds);
        }
        catch (HttpRequestException ex)
        {
            sw.Stop();
            _logger.LogWarning(ex, "ITSM connection test failed for {Provider} at {BaseUrl}", provider, baseUrl);
            return new ItsmTestResult(false, $"Connection failed: {ex.Message}", (int)sw.ElapsedMilliseconds);
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            return new ItsmTestResult(false, "Connection timed out after 15s", (int)sw.ElapsedMilliseconds);
        }
    }

    public async Task<ItsmTicketValidationResult> ValidateTicketAsync(string provider, string baseUrl, string ticketNumber,
        string? username, string? password, string? apiKey)
    {
        try
        {
            using var request = provider.ToLowerInvariant() switch
            {
                "servicenow" => BuildServiceNowTicketRequest(baseUrl, ticketNumber, username, password),
                "jira" => BuildJiraTicketRequest(baseUrl, ticketNumber, username, apiKey),
                _ => throw new ArgumentException($"Unsupported ITSM provider: {provider}")
            };

            _httpClient.Timeout = TimeSpan.FromSeconds(15);
            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    return new ItsmTicketValidationResult(false, null, null, null, $"Ticket '{ticketNumber}' not found");

                return new ItsmTicketValidationResult(false, null, null, null,
                    $"{provider} returned HTTP {(int)response.StatusCode}");
            }

            var body = await response.Content.ReadAsStringAsync();
            var (status, summary, assignee) = ParseTicketResponse(provider, body);

            _logger.LogInformation("ITSM ticket {TicketNumber} validated via {Provider}: status={Status}",
                ticketNumber, provider, status);

            var isValid = !string.IsNullOrEmpty(status) &&
                          !status.Equals("Closed", StringComparison.OrdinalIgnoreCase) &&
                          !status.Equals("Cancelled", StringComparison.OrdinalIgnoreCase) &&
                          !status.Equals("Done", StringComparison.OrdinalIgnoreCase);

            return new ItsmTicketValidationResult(isValid, status, summary, assignee,
                isValid ? "Ticket is valid and active" : $"Ticket status is '{status}' - not active");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ITSM ticket validation failed for {TicketNumber} via {Provider}", ticketNumber, provider);
            return new ItsmTicketValidationResult(false, null, null, null, $"Validation failed: {ex.Message}");
        }
    }

    // --- ServiceNow ---
    private static HttpRequestMessage BuildServiceNowTestRequest(string baseUrl, string? username, string? password)
    {
        var url = $"{baseUrl.TrimEnd('/')}/api/now/table/sys_properties?sysparm_limit=1";
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        AddBasicAuth(request, username, password);
        return request;
    }

    private static HttpRequestMessage BuildServiceNowTicketRequest(string baseUrl, string ticketNumber, string? username, string? password)
    {
        // ServiceNow incident table - also check change_request and sc_req_item
        var table = ticketNumber.StartsWith("CHG", StringComparison.OrdinalIgnoreCase) ? "change_request" :
                    ticketNumber.StartsWith("RITM", StringComparison.OrdinalIgnoreCase) ? "sc_req_item" : "incident";

        var url = $"{baseUrl.TrimEnd('/')}/api/now/table/{table}?sysparm_query=number={ticketNumber}&sysparm_fields=number,state,short_description,assigned_to&sysparm_limit=1";
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        AddBasicAuth(request, username, password);
        return request;
    }

    // --- Jira ---
    private static HttpRequestMessage BuildJiraTestRequest(string baseUrl, string? username, string? apiKey)
    {
        var url = $"{baseUrl.TrimEnd('/')}/rest/api/2/myself";
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        AddBasicAuth(request, username, apiKey);
        return request;
    }

    private static HttpRequestMessage BuildJiraTicketRequest(string baseUrl, string ticketNumber, string? username, string? apiKey)
    {
        var url = $"{baseUrl.TrimEnd('/')}/rest/api/2/issue/{ticketNumber}?fields=status,summary,assignee";
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        AddBasicAuth(request, username, apiKey);
        return request;
    }

    private static void AddBasicAuth(HttpRequestMessage request, string? username, string? password)
    {
        if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
        {
            var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        }
    }

    private static string? ExtractServerVersion(string provider, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return provider.ToLowerInvariant() switch
            {
                "jira" => doc.RootElement.TryGetProperty("displayName", out var dn) ? dn.GetString() : null,
                _ => null
            };
        }
        catch { return null; }
    }

    private static (string? Status, string? Summary, string? Assignee) ParseTicketResponse(string provider, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return provider.ToLowerInvariant() switch
            {
                "servicenow" => ParseServiceNowTicket(doc),
                "jira" => ParseJiraTicket(doc),
                _ => (null, null, null)
            };
        }
        catch { return (null, null, null); }
    }

    private static (string?, string?, string?) ParseServiceNowTicket(JsonDocument doc)
    {
        if (!doc.RootElement.TryGetProperty("result", out var result)) return (null, null, null);
        JsonElement first;
        if (result.ValueKind == JsonValueKind.Array)
        {
            if (result.GetArrayLength() == 0) return (null, null, null);
            first = result[0];
        }
        else
        {
            first = result;
        }

        var state = first.TryGetProperty("state", out var s) ? s.GetString() : null;
        var summary = first.TryGetProperty("short_description", out var sd) ? sd.GetString() : null;
        var assignee = first.TryGetProperty("assigned_to", out var at) ?
            (at.ValueKind == JsonValueKind.Object && at.TryGetProperty("display_value", out var dv) ? dv.GetString() : at.GetString()) : null;

        // Map ServiceNow state numbers to names
        var stateMap = new Dictionary<string, string>
        {
            ["1"] = "New", ["2"] = "In Progress", ["3"] = "On Hold",
            ["6"] = "Resolved", ["7"] = "Closed", ["8"] = "Cancelled"
        };
        if (state != null && stateMap.TryGetValue(state, out var mapped))
            state = mapped;

        return (state, summary, assignee);
    }

    private static (string?, string?, string?) ParseJiraTicket(JsonDocument doc)
    {
        if (!doc.RootElement.TryGetProperty("fields", out var fields)) return (null, null, null);
        var status = fields.TryGetProperty("status", out var st) && st.TryGetProperty("name", out var sn) ? sn.GetString() : null;
        var summary = fields.TryGetProperty("summary", out var sm) ? sm.GetString() : null;
        var assignee = fields.TryGetProperty("assignee", out var asg) && asg.ValueKind == JsonValueKind.Object
            && asg.TryGetProperty("displayName", out var adn) ? adn.GetString() : null;
        return (status, summary, assignee);
    }

    public void Dispose() => _httpClient.Dispose();
}
