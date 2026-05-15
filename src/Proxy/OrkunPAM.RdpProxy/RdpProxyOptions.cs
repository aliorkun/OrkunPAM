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

    /// <summary>
    /// Path to the PFX/PKCS#12 certificate file used for TLS termination on the client side.
    /// If not set, a self-signed certificate is generated at startup.
    /// </summary>
    public string? TlsCertificatePath { get; set; }

    /// <summary>Password for the TLS certificate PFX file. Null if no password.</summary>
    public string? TlsCertificatePassword { get; set; }

    // ── RDS HA Cluster ────────────────────────────────────────────────────────

    /// <summary>
    /// Optional list of RDSH/RDP proxy hostnames for HA load balancing.
    /// When empty, all connections route to the single proxy node.
    /// The load balancer health-checks each node every 30 s and uses least-connections routing.
    /// </summary>
    public string[] RdsHosts { get; set; } = [];

    /// <summary>Optional RDS Connection Broker hostname for session-aware routing.</summary>
    public string? ConnectionBroker { get; set; }

    // ── Advanced Features ─────────────────────────────────────────────────────

    /// <summary>Allow admins to create shadow (monitor) sessions on active RDP connections.</summary>
    public bool EnableSessionShadowing { get; set; } = true;

    /// <summary>Allow launching published RemoteApps via PAM session tokens.</summary>
    public bool EnableRemoteApp { get; set; } = true;

    /// <summary>RDS RemoteApp collection name on the RDSH server.</summary>
    public string RemoteAppCollection { get; set; } = "PAM-RemoteApps";

    // ── Proxy-to-Target TLS Validation ────────────────────────────────────────

    /// <summary>
    /// When false (default), the proxy validates the target server's TLS certificate against the
    /// system CA store. Set to true only in dev/lab environments where targets use self-signed
    /// certificates that cannot be added to AllowedTargetThumbprints.
    /// Never set to true in production.
    /// </summary>
    public bool SkipTargetCertValidation { get; set; } = false;

    /// <summary>
    /// Explicit SHA-1 thumbprints (hex, case-insensitive) of target server certificates to accept
    /// even when they fail normal chain validation (e.g. internal self-signed certs).
    /// Example: ["A1B2C3D4E5F6...", "..."]
    /// </summary>
    public string[] AllowedTargetThumbprints { get; set; } = [];
}
