namespace OrkunPAM.Installer;

/// <summary>
/// Holds all configuration gathered during the interactive installation process.
/// </summary>
public sealed class InstallerConfig
{
    public string InstallDirectory { get; set; } = @"C:\Program Files\OrkunPAM";
    public string DataDirectory => Path.Combine(InstallDirectory, "data");
    public string LogsDirectory => Path.Combine(InstallDirectory, "logs");
    public string CertsDirectory => Path.Combine(InstallDirectory, "certs");
    public string ConfigDirectory => Path.Combine(InstallDirectory, "config");

    // Component selection
    public bool InstallWebApi { get; set; } = true;
    public bool InstallBlazorUi { get; set; } = true;
    public bool InstallSshProxy { get; set; } = true;
    public bool InstallRdpProxy { get; set; } = true;
    public bool InstallHttpProxy { get; set; } = true;

    // Database
    public string DatabaseConnectionString { get; set; } = string.Empty;

    // Security
    public string MasterPassphrase { get; set; } = string.Empty;
    public string AdminUsername { get; set; } = "admin";
    public string AdminPassword { get; set; } = string.Empty;

    // TLS
    public bool GenerateSelfSignedCert { get; set; } = true;
    public string CertificatePath { get; set; } = string.Empty;
    public string CertificatePassword { get; set; } = string.Empty;
    public string Hostname { get; set; } = Environment.MachineName;

    // Ports
    public int WebApiPort { get; set; } = 5443;
    public int BlazorPort { get; set; } = 5444;
    public int SshProxyPort { get; set; } = 2222;
    public int RdpProxyPort { get; set; } = 3389;
    public int HttpProxyPort { get; set; } = 8443;

    /// <summary>
    /// Returns a list of selected component names.
    /// </summary>
    public IReadOnlyList<string> GetSelectedComponents()
    {
        var components = new List<string>();
        if (InstallWebApi) components.Add("OrkunPAM.WebAPI");
        if (InstallBlazorUi) components.Add("OrkunPAM.Web");
        if (InstallSshProxy) components.Add("OrkunPAM.SshProxy");
        if (InstallRdpProxy) components.Add("OrkunPAM.RdpProxy");
        if (InstallHttpProxy) components.Add("OrkunPAM.HttpProxy");
        return components;
    }

    /// <summary>
    /// Returns service definitions for selected proxy/service components.
    /// </summary>
    public IReadOnlyList<ServiceDefinition> GetServiceDefinitions()
    {
        var services = new List<ServiceDefinition>();

        if (InstallWebApi)
            services.Add(new ServiceDefinition("OrkunPAM.WebAPI", "OrkunPAM Web API",
                "OrkunPAM REST API backend service", WebApiPort));

        if (InstallBlazorUi)
            services.Add(new ServiceDefinition("OrkunPAM.Web", "OrkunPAM Blazor UI",
                "OrkunPAM web management console", BlazorPort));

        if (InstallSshProxy)
            services.Add(new ServiceDefinition("OrkunPAM.SshProxy", "OrkunPAM SSH Proxy",
                "OrkunPAM SSH session proxy service", SshProxyPort));

        if (InstallRdpProxy)
            services.Add(new ServiceDefinition("OrkunPAM.RdpProxy", "OrkunPAM RDP Proxy",
                "OrkunPAM RDP session proxy service", RdpProxyPort));

        if (InstallHttpProxy)
            services.Add(new ServiceDefinition("OrkunPAM.HttpProxy", "OrkunPAM HTTP Proxy",
                "OrkunPAM HTTP/HTTPS session proxy service", HttpProxyPort));

        return services;
    }
}

/// <summary>
/// Defines a Windows Service to be registered.
/// </summary>
public sealed record ServiceDefinition(
    string Name,
    string DisplayName,
    string Description,
    int Port);
