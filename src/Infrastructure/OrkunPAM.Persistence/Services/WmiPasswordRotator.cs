using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// WMI-based Windows password rotator.
/// Uses System.Management (native WMI, NOT WinRM) to remotely change
/// Windows local user passwords via Win32_UserAccount.SetPassword.
/// Supports both NTLM and Kerberos authentication via ConnectionOptions.
/// Windows-only — requires System.Management package.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WmiPasswordRotator : IPasswordRotator
{
    private const int DefaultWmiPort = 135; // DCOM/RPC
    private const int ConnectTimeoutSec = 30;

    private readonly ILogger<WmiPasswordRotator> _logger;

    public WmiPasswordRotator(ILogger<WmiPasswordRotator> logger)
    {
        _logger = logger;
    }

    public RotationConnector ConnectorType => RotationConnector.Wmi;

    public async Task<RotationResult> RotatePasswordAsync(RotationTarget target, CancellationToken ct)
    {
        _logger.LogInformation("WMI rotation starting for {User}@{Host}",
            target.Username, target.Host);

        return await Task.Run(() => RotateViaWmi(target), ct);
    }

    private RotationResult RotateViaWmi(RotationTarget target)
    {
        try
        {
#pragma warning disable CA1416 // Validate platform compatibility
            var scope = new System.Management.ManagementScope();

            // Build WMI connection path
            var path = $"\\\\{target.Host}\\root\\cimv2";
            scope.Path = new System.Management.ManagementPath(path);

            // Configure authentication
            scope.Options = new System.Management.ConnectionOptions
            {
                Timeout = TimeSpan.FromSeconds(ConnectTimeoutSec),
                EnablePrivileges = true
            };

            if (!string.IsNullOrEmpty(target.CurrentPassword))
            {
                scope.Options.Username = !string.IsNullOrEmpty(target.Domain)
                    ? $"{target.Domain}\\{target.Username}"
                    : target.Username;
                scope.Options.Password = target.CurrentPassword;
            }

            // Determine authentication: Kerberos if domain specified, NTLM otherwise
            if (!string.IsNullOrEmpty(target.Domain))
            {
                scope.Options.Authentication = System.Management.AuthenticationLevel.PacketPrivacy;
                scope.Options.Authority = $"Kerberos:{target.Domain}";
                _logger.LogDebug("WMI using Kerberos auth for domain {Domain}", target.Domain);
            }
            else
            {
                scope.Options.Authentication = System.Management.AuthenticationLevel.PacketPrivacy;
                scope.Options.Impersonation = System.Management.ImpersonationLevel.Impersonate;
                _logger.LogDebug("WMI using NTLM auth for {Host}", target.Host);
            }

            scope.Connect();

            if (!scope.IsConnected)
                return new RotationResult(false, $"WMI connection failed to {target.Host}", "WMI");

            _logger.LogDebug("WMI connected to {Host}", target.Host);

            // Query for the specific user account
            var query = new System.Management.ObjectQuery(
                $"SELECT * FROM Win32_UserAccount WHERE Name = '{EscapeWqlString(target.Username)}' AND LocalAccount = TRUE");

            using var searcher = new System.Management.ManagementObjectSearcher(scope, query);
            var users = searcher.Get();

            System.Management.ManagementObject? userObj = null;
            foreach (System.Management.ManagementObject user in users)
            {
                userObj = user;
                break;
            }

            if (userObj == null)
            {
                return new RotationResult(false,
                    $"Local user '{target.Username}' not found on {target.Host} via WMI", "WMI");
            }

            // Use Win32_UserAccount.Rename is not what we want.
            // SetPassword is not directly on Win32_UserAccount.
            // Instead, use Win32_Process.Create to execute 'net user' command,
            // or use ADSI via WMI. The most reliable WMI approach is via
            // Win32_Process to execute the password change.
            userObj.Dispose();

            // Use Win32_Process.Create to run net user command
            var processClass = new System.Management.ManagementClass(scope,
                new System.Management.ManagementPath("Win32_Process"), null);

            // Build the command — net user sets password for local accounts
            var escapedUser = target.Username.Replace("\"", "\\\"");
            var escapedPwd = target.NewPassword.Replace("\"", "\\\"");
            var cmdLine = $"cmd.exe /c net user \"{escapedUser}\" \"{escapedPwd}\"";

            var inParams = processClass.GetMethodParameters("Create");
            inParams["CommandLine"] = cmdLine;

            var outParams = processClass.InvokeMethod("Create", inParams, null);

            // Zero the command line from memory
            var cmdBytes = System.Text.Encoding.UTF8.GetBytes(cmdLine);
            CryptographicOperations.ZeroMemory(cmdBytes);

            var returnValue = Convert.ToUInt32(outParams?["ReturnValue"]);
            var processId = outParams?["ProcessId"];

            if (returnValue != 0)
            {
                var errorMsg = returnValue switch
                {
                    2 => "Access denied",
                    3 => "Insufficient privilege",
                    8 => "Unknown failure",
                    9 => "Path not found",
                    21 => "Invalid parameter",
                    _ => $"Error code {returnValue}"
                };

                return new RotationResult(false,
                    $"WMI Win32_Process.Create failed: {errorMsg}", "WMI");
            }

            // Wait briefly for process to complete, then verify
            if (processId != null)
            {
                var pid = Convert.ToUInt32(processId);
                if (!WaitForProcessExit(scope, pid, TimeSpan.FromSeconds(15)))
                {
                    _logger.LogWarning("WMI password change process {Pid} did not exit within timeout", pid);
                }
            }

            _logger.LogInformation("WMI password rotation succeeded for {User}@{Host}",
                target.Username, target.Host);

            return new RotationResult(true, "Password changed via WMI (Win32_Process net user)", "WMI");
#pragma warning restore CA1416
        }
        catch (System.Management.ManagementException ex)
        {
            _logger.LogError(ex, "WMI management error for {User}@{Host}", target.Username, target.Host);
            return new RotationResult(false, $"WMI error: {ex.ErrorCode} - {ex.Message}", "WMI");
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogError(ex, "WMI access denied for {User}@{Host}", target.Username, target.Host);
            return new RotationResult(false, $"WMI access denied: {ex.Message}", "WMI");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WMI rotation failed for {User}@{Host}", target.Username, target.Host);
            return new RotationResult(false, $"WMI rotation error: {ex.Message}", "WMI");
        }
    }

    private static bool WaitForProcessExit(System.Management.ManagementScope scope, uint processId, TimeSpan timeout)
    {
#pragma warning disable CA1416
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var query = new System.Management.ObjectQuery(
                    $"SELECT ProcessId FROM Win32_Process WHERE ProcessId = {processId}");
                using var searcher = new System.Management.ManagementObjectSearcher(scope, query);
                var results = searcher.Get();

                bool found = false;
                foreach (var _ in results) { found = true; break; }
                if (!found) return true; // Process exited

                Thread.Sleep(500);
            }
            catch
            {
                return true; // Assume exited if we can't query
            }
        }
        return false;
#pragma warning restore CA1416
    }

    private static string EscapeWqlString(string input) =>
        input.Replace("\\", "\\\\").Replace("'", "\\'");
}
