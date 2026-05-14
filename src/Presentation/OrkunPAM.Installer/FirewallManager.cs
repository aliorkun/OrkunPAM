using System.Diagnostics;

namespace OrkunPAM.Installer;

/// <summary>
/// Manages Windows Firewall rules via netsh advfirewall.
/// </summary>
public static class FirewallManager
{
    /// <summary>
    /// Creates an inbound firewall rule for the given service/port.
    /// </summary>
    public static bool CreateInboundRule(string ruleName, int port, string protocol = "TCP")
    {
        // Delete existing rule first (ignore failure if it doesn't exist)
        DeleteRule(ruleName);

        var arguments = $"advfirewall firewall add rule " +
                        $"name=\"{ruleName}\" " +
                        $"dir=in " +
                        $"action=allow " +
                        $"protocol={protocol} " +
                        $"localport={port} " +
                        $"enable=yes " +
                        $"profile=any " +
                        $"description=\"OrkunPAM - {ruleName}\"";

        var result = RunNetsh(arguments);
        if (result)
            ConsoleHelper.WriteSuccess($"Firewall rule created: {ruleName} (port {port}/{protocol})");
        else
            ConsoleHelper.WriteError($"Failed to create firewall rule: {ruleName}");

        return result;
    }

    /// <summary>
    /// Creates all firewall rules for selected components.
    /// </summary>
    public static void CreateRulesForConfig(InstallerConfig config)
    {
        ConsoleHelper.WriteStep("Configuring Windows Firewall rules...");

        if (config.InstallWebApi)
            CreateInboundRule("OrkunPAM WebAPI", config.WebApiPort);

        if (config.InstallBlazorUi)
            CreateInboundRule("OrkunPAM Blazor UI", config.BlazorPort);

        if (config.InstallSshProxy)
            CreateInboundRule("OrkunPAM SSH Proxy", config.SshProxyPort);

        if (config.InstallRdpProxy)
            CreateInboundRule("OrkunPAM RDP Proxy", config.RdpProxyPort);

        if (config.InstallHttpProxy)
            CreateInboundRule("OrkunPAM HTTP Proxy", config.HttpProxyPort);
    }

    /// <summary>
    /// Removes all OrkunPAM firewall rules.
    /// </summary>
    public static void RemoveAllRules()
    {
        string[] ruleNames =
        [
            "OrkunPAM WebAPI",
            "OrkunPAM Blazor UI",
            "OrkunPAM SSH Proxy",
            "OrkunPAM RDP Proxy",
            "OrkunPAM HTTP Proxy"
        ];

        foreach (var rule in ruleNames)
        {
            DeleteRule(rule);
        }
    }

    private static bool DeleteRule(string ruleName)
    {
        var arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"";
        return RunNetsh(arguments);
    }

    private static bool RunNetsh(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return false;

            process.WaitForExit(30_000);
            return process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"netsh error: {ex.Message}");
            return false;
        }
    }
}
