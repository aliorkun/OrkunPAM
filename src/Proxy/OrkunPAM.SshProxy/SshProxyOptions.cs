namespace OrkunPAM.SshProxy;

public sealed class SshProxyOptions
{
    public int ListenPort { get; set; } = 2222;
    public string? ListenAddress { get; set; }
    public string? KeyDirectory { get; set; }
    public int MaxConcurrentSessions { get; set; } = 100;
    public string RecordingDirectory { get; set; } = "recordings";
    /// <summary>Recordings older than this many days are automatically deleted. RFP §66 requires ≥6 months.</summary>
    public int RetentionDays { get; set; } = 183;
    /// <summary>Fallback idle timeout in minutes. Overridden at runtime by the global Session Policy fetched from the API.</summary>
    public int IdleTimeoutMinutes { get; set; } = 30;
    /// <summary>
    /// When true, SSH sessions to targets with no pre-enrolled host key fingerprint are blocked (CWE-295).
    /// Set to true in production; false allows TOFU (Trust On First Use) with a warning logged.
    /// </summary>
    public bool RequireFingerprintVerification { get; set; } = false;
}
