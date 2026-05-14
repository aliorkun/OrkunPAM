using System.Diagnostics;

namespace OrkunPAM.Installer;

/// <summary>
/// Manages Windows Service registration via sc.exe.
/// </summary>
public static class ServiceInstaller
{
    /// <summary>
    /// Registers a Windows Service using sc.exe create.
    /// </summary>
    public static bool CreateService(ServiceDefinition service, string installDirectory)
    {
        var exePath = Path.Combine(installDirectory, service.Name, $"{service.Name}.exe");

        if (!File.Exists(exePath))
        {
            ConsoleHelper.WriteWarning($"Executable not found: {exePath}");
            ConsoleHelper.WriteWarning($"Service '{service.DisplayName}' will be registered but may fail to start until binaries are deployed.");
        }

        // Stop and delete existing service if present
        StopService(service.Name);
        DeleteService(service.Name);

        // Create the service
        var createArgs = $"create \"{service.Name}\" binPath= \"\\\"{exePath}\\\"\" " +
                         $"DisplayName= \"{service.DisplayName}\" " +
                         $"start= auto " +
                         $"obj= \"NT AUTHORITY\\LocalService\"";

        var result = RunScCommand(createArgs);
        if (!result)
        {
            ConsoleHelper.WriteError($"Failed to create service: {service.DisplayName}");
            return false;
        }

        // Set description
        var descArgs = $"description \"{service.Name}\" \"{service.Description}\"";
        RunScCommand(descArgs);

        // Configure failure recovery: restart after 30s, 60s, 120s
        var failureArgs = $"failure \"{service.Name}\" reset= 86400 actions= restart/30000/restart/60000/restart/120000";
        RunScCommand(failureArgs);

        ConsoleHelper.WriteSuccess($"Service registered: {service.DisplayName}");
        return true;
    }

    /// <summary>
    /// Starts a Windows Service.
    /// </summary>
    public static bool StartService(string serviceName)
    {
        var result = RunScCommand($"start \"{serviceName}\"");
        if (result)
            ConsoleHelper.WriteSuccess($"Service started: {serviceName}");
        else
            ConsoleHelper.WriteWarning($"Failed to start service: {serviceName}");
        return result;
    }

    /// <summary>
    /// Stops a Windows Service.
    /// </summary>
    public static bool StopService(string serviceName)
    {
        return RunScCommand($"stop \"{serviceName}\"");
    }

    /// <summary>
    /// Deletes a Windows Service registration.
    /// </summary>
    public static bool DeleteService(string serviceName)
    {
        return RunScCommand($"delete \"{serviceName}\"");
    }

    /// <summary>
    /// Queries the status of a Windows Service.
    /// </summary>
    public static string QueryService(string serviceName)
    {
        var (success, output) = RunScCommandWithOutput($"query \"{serviceName}\"");
        return success ? output : "NOT_FOUND";
    }

    private static bool RunScCommand(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
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
            ConsoleHelper.WriteError($"sc.exe error: {ex.Message}");
            return false;
        }
    }

    private static (bool Success, string Output) RunScCommandWithOutput(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return (false, string.Empty);

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(30_000);
            return (process.ExitCode == 0, output);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
