using System.Text.Json;
using System.Text.RegularExpressions;

namespace OrkunPAM.SshProxy;

/// <summary>
/// Result of command filter evaluation.
/// </summary>
internal enum FilterAction : byte
{
    Allow = 0,
    Block = 1,
    Warn = 2,
    DoubleConfirm = 3
}

/// <summary>
/// Command filter mode matching the domain enum.
/// </summary>
internal enum CommandFilterModeProxy : byte
{
    None = 0,
    Whitelist = 1,
    Blacklist = 2
}

/// <summary>
/// Result of evaluating a command against the session policy filter rules.
/// </summary>
internal sealed record FilterResult(
    FilterAction Action,
    string? Reason = null,
    decimal RiskScore = 0m,
    string? MatchedPattern = null);

/// <summary>
/// A single filter rule parsed from CommandFilterRulesJson.
/// </summary>
internal sealed class CommandFilterRule
{
    public string Pattern { get; set; } = string.Empty;
    public bool IsRegex { get; set; }
    public decimal RiskScore { get; set; } = 5.0m;
    public string? Description { get; set; }
    /// <summary>Per-rule action: "Deny" (block), "Alert" (warn+allow), "Allow" (explicit pass). Null = mode-driven.</summary>
    public string? Action { get; set; }
}

/// <summary>
/// Interface for command filtering in SSH sessions.
/// Evaluates commands against session policy rules before forwarding to target.
/// </summary>
internal interface ICommandFilter
{
    FilterResult Evaluate(string command, CommandFilterModeProxy mode, string? commandFilterRulesJson);
}

/// <summary>
/// Evaluates SSH commands against whitelist/blacklist rules defined in session policy.
/// Supports both glob patterns and regex patterns.
/// Thread-safe: can be shared across sessions.
/// </summary>
internal sealed class CommandFilter : ICommandFilter
{
    private readonly ILogger _log;

    // Cache compiled rules per policy JSON to avoid re-parsing — capped at MaxCacheEntries
    // to prevent OOM in long-running Windows Service (CWE-770)
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, CommandFilterRule[]>
        _ruleCache = new();
    private const int MaxCacheEntries = 50;

    // High-risk commands that always get elevated risk score regardless of rules
    private static readonly string[] HighRiskPatterns =
    [
        @"\brm\s+.*-rf\b",
        @"\bdd\s+",
        @"\bmkfs\b",
        @"\bshutdown\b",
        @"\breboot\b",
        @"\bchmod\s+777\b",
        @"\bpasswd\b",
        @"\buseradd\b",
        @"\buserdel\b",
        @"\biptables\s+.*-F\b",
        @"\bsystemctl\s+(stop|disable)\b",
        @"\bkill\s+-9\b",
        @"\b(wget|curl)\s+.*\|\s*(sh|bash)\b"
    ];

    private static readonly Regex[] HighRiskRegexes = HighRiskPatterns
        .Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
        .ToArray();

    internal CommandFilter(ILogger log)
    {
        _log = log;
    }

    public FilterResult Evaluate(string command, CommandFilterModeProxy mode, string? commandFilterRulesJson)
    {
        if (string.IsNullOrWhiteSpace(command))
            return new FilterResult(FilterAction.Allow);

        if (mode == CommandFilterModeProxy.None)
        {
            // Even with no filter mode, calculate risk score for logging
            var riskScore = CalculateRiskScore(command);
            return new FilterResult(FilterAction.Allow, RiskScore: riskScore);
        }

        var rules = ParseRules(commandFilterRulesJson);
        if (rules.Length == 0)
        {
            // No rules configured: whitelist mode blocks everything, blacklist allows everything
            return mode == CommandFilterModeProxy.Whitelist
                ? new FilterResult(FilterAction.Block, "No whitelist rules configured — all commands blocked")
                : new FilterResult(FilterAction.Allow);
        }

        var (matched, matchedRule) = MatchesAnyRule(command, rules);

        return mode switch
        {
            CommandFilterModeProxy.Whitelist => matched
                ? new FilterResult(FilterAction.Allow, MatchedPattern: matchedRule?.Pattern)
                : new FilterResult(FilterAction.Block,
                    $"Command not in whitelist: {TruncateCommand(command)}",
                    CalculateRiskScore(command)),

            CommandFilterModeProxy.Blacklist => matched
                ? matchedRule?.Action == "Alert"
                    ? new FilterResult(FilterAction.Warn,
                        $"Command alerted by policy: {matchedRule?.Description ?? matchedRule?.Pattern}",
                        matchedRule?.RiskScore ?? CalculateRiskScore(command),
                        matchedRule?.Pattern)
                    : new FilterResult(FilterAction.Block,
                        $"Command matches blacklist rule: {matchedRule?.Description ?? matchedRule?.Pattern}",
                        matchedRule?.RiskScore ?? CalculateRiskScore(command),
                        matchedRule?.Pattern)
                : new FilterResult(FilterAction.Allow, RiskScore: CalculateRiskScore(command)),

            _ => new FilterResult(FilterAction.Allow)
        };
    }

    private static CommandFilterRule[] ParseRules(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];

        if (_ruleCache.TryGetValue(json, out var cached))
            return cached;

        var parsed = ParseRulesCore(json);

        // Evict oldest entries if at capacity before inserting
        while (_ruleCache.Count >= MaxCacheEntries)
        {
            var evict = _ruleCache.Keys.FirstOrDefault();
            if (evict is null) break;
            _ruleCache.TryRemove(evict, out _);
        }

        _ruleCache.TryAdd(json, parsed);
        return parsed;
    }

    private static CommandFilterRule[] ParseRulesCore(string j)
    {
        try
        {
            var rules = JsonSerializer.Deserialize<CommandFilterRule[]>(j,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (rules != null)
                return rules;
        }
        catch
        {
            try
            {
                var patterns = JsonSerializer.Deserialize<string[]>(j);
                if (patterns != null)
                    return patterns.Select(p => new CommandFilterRule
                    {
                        Pattern = p,
                        IsRegex = p.Contains('(') || p.Contains('[') || p.Contains('+') || p.Contains('\\'),
                        RiskScore = 5.0m
                    }).ToArray();
            }
            catch { /* fall through */ }
        }

        return [];
    }

    private static (bool matched, CommandFilterRule? rule) MatchesAnyRule(string command, CommandFilterRule[] rules)
    {
        var trimmed = command.Trim();

        foreach (var rule in rules)
        {
            try
            {
                if (rule.IsRegex)
                {
                    // Regex match with timeout protection
                    var regex = new Regex(rule.Pattern,
                        RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));
                    if (regex.IsMatch(trimmed))
                        return (true, rule);
                }
                else
                {
                    // Glob-style match: * matches anything, ? matches single char
                    if (GlobMatch(trimmed, rule.Pattern))
                        return (true, rule);
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Treat timeout as no match to avoid DoS via crafted patterns
                continue;
            }
        }

        return (false, null);
    }

    /// <summary>
    /// Simple glob matcher: * matches any sequence, ? matches any single character.
    /// Case-insensitive.
    /// </summary>
    private static bool GlobMatch(string input, string pattern)
    {
        // Convert glob to regex: escape everything except * and ?
        var regexPattern = "^" +
            Regex.Escape(pattern)
                .Replace("\\*", ".*")
                .Replace("\\?", ".") +
            "$";

        try
        {
            return Regex.IsMatch(input, regexPattern,
                RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    internal static decimal CalculateRiskScore(string command)
    {
        decimal score = 0m;
        var trimmed = command.Trim();

        foreach (var regex in HighRiskRegexes)
        {
            try
            {
                if (regex.IsMatch(trimmed))
                    score = Math.Max(score, 8.0m);
            }
            catch (RegexMatchTimeoutException)
            {
                // Skip on timeout
            }
        }

        // Pipe to shell = high risk
        if (trimmed.Contains("| sh") || trimmed.Contains("| bash") || trimmed.Contains("| /bin/"))
            score = Math.Max(score, 9.0m);

        // Sudo elevation
        if (trimmed.StartsWith("sudo ", StringComparison.OrdinalIgnoreCase))
            score = Math.Max(score, 3.0m);

        // Long commands are suspicious
        if (trimmed.Length > 500)
            score = Math.Max(score, 2.0m);

        return Math.Min(score, 10.0m);
    }

    internal bool IsInDoubleConfirmList(string command, string? patternsJson)
    {
        if (string.IsNullOrWhiteSpace(patternsJson)) return false;
        var rules = ParseRules(patternsJson);
        if (rules.Length == 0) return false;
        var (matched, _) = MatchesAnyRule(command, rules);
        return matched;
    }

    private static string TruncateCommand(string command, int maxLen = 100)
    {
        var trimmed = command.Trim();
        return trimmed.Length <= maxLen ? trimmed : trimmed[..maxLen] + "...";
    }
}

/// <summary>
/// Inline command detector for SSH data streams.
/// Accumulates bytes to detect newline-terminated commands from interactive SSH sessions.
/// </summary>
internal sealed class CommandDetector
{
    private readonly System.Text.StringBuilder _buffer = new();
    private const int MaxBufferSize = 4096;

    /// <summary>
    /// Feed data from client→target stream. Returns detected commands (newline-terminated).
    /// </summary>
    internal IEnumerable<string> Feed(byte[] data)
    {
        foreach (var b in data)
        {
            if (b == '\r' || b == '\n')
            {
                if (_buffer.Length > 0)
                {
                    var cmd = _buffer.ToString().Trim();
                    _buffer.Clear();
                    if (!string.IsNullOrEmpty(cmd))
                        yield return cmd;
                }
            }
            else if (b == 0x7f || b == 0x08) // Backspace / DEL
            {
                if (_buffer.Length > 0)
                    _buffer.Length--;
            }
            else if (b >= 0x20 && b < 0x7f) // Printable ASCII
            {
                if (_buffer.Length < MaxBufferSize)
                    _buffer.Append((char)b);
            }
            // Non-printable / control characters are ignored
        }
    }

    internal void Reset() => _buffer.Clear();
}
