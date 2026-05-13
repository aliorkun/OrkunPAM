namespace OrkunPAM.RdpProxy;

public sealed class RdpProxyOptions
{
    /// <summary>TCP port the proxy listens on. Default 3389 (standard RDP).</summary>
    public int ListenPort { get; set; } = 3389;

    /// <summary>Bind address. Null = 0.0.0.0 (all interfaces).</summary>
    public string? ListenAddress { get; set; }

    public int MaxConcurrentSessions { get; set; } = 50;

    /// <summary>Directory where session recordings (raw TCP streams) are stored.</summary>
    public string RecordingDirectory { get; set; } = "rdp-recordings";

    /// <summary>Recordings older than this are deleted by the retention service. RFP §66 requires ≥6 months.</summary>
    public int RetentionDays { get; set; } = 183;

    /// <summary>
    /// Optional: hostname of a Windows RDS Gateway to use as the outbound relay for target connections.
    /// When null the proxy connects directly to target TCP:3389.
    /// </summary>
    public string? RdsGatewayHostname { get; set; }
    public int RdsGatewayPort { get; set; } = 443;

    /// <summary>Session token TTL in seconds. Tokens are created by the WebAPI when a user launches an RDP session.</summary>
    public int SessionTokenTtlSeconds { get; set; } = 300;
    /// <summary>Fallback idle timeout in minutes. Overridden at runtime by the global Session Policy fetched from the API.</summary>
    public int IdleTimeoutMinutes { get; set; } = 30;

    /// <summary>
    /// Base64-encoded 32-byte AES-256 master key used to wrap per-session recording content keys.
    /// Generate with: openssl rand -base64 32
    /// If not set, recordings are frame-encrypted but the content key is stored unprotected in the file header.
    /// </summary>
    public string? RecordingEncryptionKeyBase64 { get; set; }
}
