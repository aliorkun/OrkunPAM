using System.Globalization;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Evaluates time windows and IP range restrictions from access policies
/// assigned to users or their groups.
///
/// Policy JSON format (stored in Policy.PolicyJson where PolicyType == "AccessPolicy"):
/// {
///   "AllowedTimeWindows": ["Mon-Fri 09:00-18:00", "Sat 10:00-14:00"],
///   "AllowedIpRanges": ["10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12"],
///   "DenyIpRanges": ["10.0.0.99/32"]
/// }
/// </summary>
public sealed class AccessPolicyEngine : IAccessPolicyEngine
{
    private readonly OrkunPamDbContext _db;
    private readonly ILogger<AccessPolicyEngine> _logger;

    public AccessPolicyEngine(OrkunPamDbContext db, ILogger<AccessPolicyEngine> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task<AccessDecision> EvaluateAsync(
        Guid userId, Guid? credentialId, string clientIp, DateTime requestTime, CancellationToken ct = default)
    {
        // Collect all applicable access policies, ordered by priority (higher = more specific)
        var policies = await GetApplicablePoliciesAsync(userId, ct);

        if (policies.Count == 0)
        {
            _logger.LogDebug("No access policies found for user {UserId} — allowing by default", userId);
            return new AccessDecision(AccessVerdict.Allow, "No access policies configured");
        }

        // Evaluate each policy in priority order (highest priority first)
        foreach (var policy in policies.OrderByDescending(p => p.Priority))
        {
            if (!policy.IsEnabled)
                continue;

            var parsed = ParsePolicyJson(policy.PolicyJson);
            if (parsed == null)
                continue;

            // Check deny IP ranges first (explicit deny always wins)
            if (parsed.DenyIpRanges?.Length > 0)
            {
                if (IsIpInRanges(clientIp, parsed.DenyIpRanges))
                {
                    _logger.LogWarning("Access denied for user {UserId} from IP {Ip} — IP in deny list (policy: {Policy})",
                        userId, clientIp, policy.Name);
                    return new AccessDecision(AccessVerdict.Deny,
                        $"Client IP {clientIp} is in the deny list",
                        policy.Name, policy.Id);
                }
            }

            // Check allowed IP ranges
            if (parsed.AllowedIpRanges?.Length > 0)
            {
                if (!IsIpInRanges(clientIp, parsed.AllowedIpRanges))
                {
                    _logger.LogWarning("Access denied for user {UserId} from IP {Ip} — IP not in allowed ranges (policy: {Policy})",
                        userId, clientIp, policy.Name);
                    return new AccessDecision(AccessVerdict.Deny,
                        $"Client IP {clientIp} is not in the allowed IP ranges",
                        policy.Name, policy.Id);
                }
            }

            // Check time windows
            if (parsed.AllowedTimeWindows?.Length > 0)
            {
                if (!IsWithinTimeWindows(requestTime, parsed.AllowedTimeWindows))
                {
                    _logger.LogWarning("Access denied for user {UserId} at {Time} — outside allowed time windows (policy: {Policy})",
                        userId, requestTime, policy.Name);
                    return new AccessDecision(AccessVerdict.Deny,
                        $"Access not permitted at this time. Allowed windows: {string.Join(", ", parsed.AllowedTimeWindows)}",
                        policy.Name, policy.Id);
                }
            }
        }

        return new AccessDecision(AccessVerdict.Allow, "All access policies passed");
    }

    private async Task<List<Domain.Entities.Identity.Policy>> GetApplicablePoliciesAsync(Guid userId, CancellationToken ct)
    {
        // Get user's group IDs
        var groupIds = await _db.UserGroups
            .Where(ug => ug.UserId == userId)
            .Select(ug => ug.GroupId)
            .ToListAsync(ct);

        // Find all AccessPolicy type policies that apply to this user
        var policies = await _db.Policies
            .Where(p => p.PolicyType == "AccessPolicy" && p.IsEnabled)
            .Where(p =>
                p.Scope == PolicyScope.Global ||
                (p.Scope == PolicyScope.User && p.ScopeId == userId) ||
                (p.Scope == PolicyScope.Group && p.ScopeId != null && groupIds.Contains(p.ScopeId.Value)))
            .OrderByDescending(p => p.Priority)
            .ToListAsync(ct);

        return policies;
    }

    private AccessPolicyData? ParsePolicyJson(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<AccessPolicyData>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse access policy JSON: {Json}", json);
            return null;
        }
    }

    /// <summary>
    /// Check if a given time falls within any of the specified time windows.
    /// Format: "DayRange HH:mm-HH:mm" where DayRange is like "Mon-Fri", "Sat", "Mon,Wed,Fri"
    /// </summary>
    internal static bool IsWithinTimeWindows(DateTime time, string[] windows)
    {
        foreach (var window in windows)
        {
            if (string.IsNullOrWhiteSpace(window))
                continue;

            var parts = window.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
                continue;

            var dayPart = parts[0];
            var timePart = parts[1];

            if (!IsMatchingDay(time.DayOfWeek, dayPart))
                continue;

            var timeRange = timePart.Split('-', 2);
            if (timeRange.Length != 2)
                continue;

            if (!TimeOnly.TryParse(timeRange[0], CultureInfo.InvariantCulture, out var start) ||
                !TimeOnly.TryParse(timeRange[1], CultureInfo.InvariantCulture, out var end))
                continue;

            var currentTime = TimeOnly.FromDateTime(time);

            // Handle overnight ranges (e.g., 22:00-06:00)
            if (end < start)
            {
                if (currentTime >= start || currentTime <= end)
                    return true;
            }
            else
            {
                if (currentTime >= start && currentTime <= end)
                    return true;
            }
        }

        return false;
    }

    private static bool IsMatchingDay(DayOfWeek day, string daySpec)
    {
        // Handle range: "Mon-Fri"
        if (daySpec.Contains('-'))
        {
            var rangeParts = daySpec.Split('-', 2);
            if (TryParseDayOfWeek(rangeParts[0], out var rangeStart) &&
                TryParseDayOfWeek(rangeParts[1], out var rangeEnd))
            {
                if (rangeStart <= rangeEnd)
                    return day >= rangeStart && day <= rangeEnd;
                else
                    // Wrap around: e.g., "Fri-Mon" means Fri,Sat,Sun,Mon
                    return day >= rangeStart || day <= rangeEnd;
            }
        }

        // Handle comma-separated: "Mon,Wed,Fri"
        if (daySpec.Contains(','))
        {
            return daySpec.Split(',')
                .Any(d => TryParseDayOfWeek(d.Trim(), out var parsed) && parsed == day);
        }

        // Single day
        return TryParseDayOfWeek(daySpec, out var singleDay) && singleDay == day;
    }

    private static bool TryParseDayOfWeek(string name, out DayOfWeek day)
    {
        day = default;
        var lower = name.Trim().ToLowerInvariant();
        switch (lower)
        {
            case "mon" or "monday": day = DayOfWeek.Monday; return true;
            case "tue" or "tuesday": day = DayOfWeek.Tuesday; return true;
            case "wed" or "wednesday": day = DayOfWeek.Wednesday; return true;
            case "thu" or "thursday": day = DayOfWeek.Thursday; return true;
            case "fri" or "friday": day = DayOfWeek.Friday; return true;
            case "sat" or "saturday": day = DayOfWeek.Saturday; return true;
            case "sun" or "sunday": day = DayOfWeek.Sunday; return true;
            default: return false;
        }
    }

    /// <summary>
    /// Check if an IP address falls within any of the specified CIDR ranges.
    /// </summary>
    internal static bool IsIpInRanges(string ipString, string[] cidrRanges)
    {
        if (!IPAddress.TryParse(ipString, out var clientIp))
            return false;

        foreach (var cidr in cidrRanges)
        {
            if (string.IsNullOrWhiteSpace(cidr))
                continue;

            try
            {
                if (IsIpInCidr(clientIp, cidr.Trim()))
                    return true;
            }
            catch
            {
                // Skip malformed CIDR entries
            }
        }

        return false;
    }

    private static bool IsIpInCidr(IPAddress address, string cidr)
    {
        var parts = cidr.Split('/', 2);
        if (!IPAddress.TryParse(parts[0], out var networkAddress))
            return false;

        // Handle single IP (no prefix)
        if (parts.Length == 1)
            return address.Equals(networkAddress);

        if (!int.TryParse(parts[1], out var prefixLength))
            return false;

        // Ensure both addresses are the same family
        if (address.AddressFamily != networkAddress.AddressFamily)
            return false;

        var addressBytes = address.GetAddressBytes();
        var networkBytes = networkAddress.GetAddressBytes();

        // Compare prefix bits
        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes && i < addressBytes.Length; i++)
        {
            if (addressBytes[i] != networkBytes[i])
                return false;
        }

        if (remainingBits > 0 && fullBytes < addressBytes.Length)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            if ((addressBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Internal DTO for deserializing the access policy JSON.
    /// </summary>
    private sealed class AccessPolicyData
    {
        public string[]? AllowedTimeWindows { get; set; }
        public string[]? AllowedIpRanges { get; set; }
        public string[]? DenyIpRanges { get; set; }
    }
}
