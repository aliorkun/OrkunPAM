namespace OrkunPAM.HttpProxy;

/// <summary>
/// Configuration for the HTTP reverse proxy Windows Service.
/// Bound from the "HttpProxy" configuration section.
/// </summary>
public sealed class HttpProxyOptions
{
    /// <summary>HTTPS port the proxy listens on. Default 8443.</summary>
    public int ListenPort { get; set; } = 8443;

    /// <summary>Bind address. Null = 0.0.0.0 (all interfaces).</summary>
    public string? ListenAddress { get; set; }

    /// <summary>Path to PKCS#12 / PFX file used for TLS termination.</summary>
    public string? TlsCertPath { get; set; }

    /// <summary>Password for the TLS certificate PFX file.</summary>
    public string? TlsCertPassword { get; set; }

    /// <summary>PAM WebAPI base URL for session token validation and credential retrieval.</summary>
    public string PamApiBaseUrl { get; set; } = "https://localhost:5001";

    /// <summary>Maximum number of concurrent HTTP proxy sessions.</summary>
    public int MaxConcurrentSessions { get; set; } = 100;

    /// <summary>Session idle timeout in minutes. No activity = session terminated.</summary>
    public int IdleTimeoutMinutes { get; set; } = 30;

    /// <summary>Directory where encrypted session recordings are stored.</summary>
    public string RecordingDirectory { get; set; } = "http-recordings";

    /// <summary>Recordings older than this many days are automatically deleted. RFP §66 requires ≥6 months.</summary>
    public int RetentionDays { get; set; } = 183;

    /// <summary>
    /// URL path patterns to block (regex). Requests matching these patterns are rejected with 403.
    /// Example: ["^/admin/.*", "^/api/debug/.*"]
    /// </summary>
    public List<string> BlockedUrlPatterns { get; set; } = [];

    /// <summary>Maximum request body size in bytes (default 10 MB). Prevents memory exhaustion.</summary>
    public long MaxRequestBodyBytes { get; set; } = 10 * 1024 * 1024;

    /// <summary>Per-session request rate limit: max requests within the rate window.</summary>
    public int RateLimitMaxRequests { get; set; } = 200;

    /// <summary>Rate limit sliding window in seconds.</summary>
    public int RateLimitWindowSeconds { get; set; } = 60;
}
