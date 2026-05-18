namespace OrkunPAM.TelnetProxy;

internal sealed class TelnetProxyOptions
{
    /// <summary>TCP port to listen on. Default 2323 (avoids privileged port 23).</summary>
    public int ListenPort { get; set; } = 2323;

    /// <summary>IP address to bind. Empty = 0.0.0.0 (all interfaces).</summary>
    public string ListenAddress { get; set; } = string.Empty;

    /// <summary>Max simultaneous Telnet proxy sessions.</summary>
    public int MaxConcurrentSessions { get; set; } = 100;

    /// <summary>Idle timeout in seconds before the relay is torn down.</summary>
    public int IdleTimeoutSeconds { get; set; } = 300;

    /// <summary>When true, send a PAM banner before the login prompt.</summary>
    public bool SessionBannerEnabled { get; set; } = true;
}
