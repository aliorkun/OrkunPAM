namespace OrkunPAM.TacacsProxy;

internal sealed class TacacsProxyOptions
{
    /// <summary>TCP port to listen on. TACACS+ standard is 49.</summary>
    public int ListenPort { get; set; } = 49;

    /// <summary>IP address to bind. Empty = 0.0.0.0 (all interfaces).</summary>
    public string ListenAddress { get; set; } = string.Empty;

    /// <summary>Max simultaneous client sessions.</summary>
    public int MaxConcurrentSessions { get; set; } = 200;

    /// <summary>Per-device shared secrets keyed by device IP or CIDR prefix.</summary>
    public Dictionary<string, string> SharedSecrets { get; set; } = new();

    /// <summary>Fallback secret when no device-specific entry matches.</summary>
    public string DefaultSharedSecret { get; set; } = string.Empty;

    /// <summary>Privilege levels (0-15) allowed for enable/exec authorization.</summary>
    public int DefaultPrivilegeLevel { get; set; } = 1;

    /// <summary>Command authorization mode: None, PermitAll, DenyAll, Policy.</summary>
    public string CommandAuthorizationMode { get; set; } = "PermitAll";

    // RADIUS server (RFC 2865/2866)
    public bool RadiusEnabled  { get; set; } = true;
    public int  RadiusAuthPort { get; set; } = 1812;
    public int  RadiusAcctPort { get; set; } = 1813;

    /// <summary>When true, ASCII auth prompts for TOTP code after password.</summary>
    public bool EnableMfaTotp { get; set; } = false;
}
