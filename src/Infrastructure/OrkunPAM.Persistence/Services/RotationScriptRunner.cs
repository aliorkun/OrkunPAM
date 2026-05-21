using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

public record ScriptRunResult(bool Success, int ExitCode, string? Output, string? Error);

public static class RotationScriptRunner
{
    public static async Task<ScriptRunResult> RunAsync(
        RotationScriptType scriptType,
        string scriptContent,
        bool isTest,
        Dictionary<string, string>? env = null,
        CancellationToken ct = default)
    {
        var ext = scriptType switch
        {
            RotationScriptType.PowerShell => ".ps1",
            RotationScriptType.Python     => ".py",
            _                             => ".sh"
        };

        var tmpFile = Path.GetTempFileName() + ext;
        try
        {
            await File.WriteAllTextAsync(tmpFile, scriptContent, ct);

            var psi = scriptType switch
            {
                RotationScriptType.PowerShell => new System.Diagnostics.ProcessStartInfo("pwsh",
                    "-NonInteractive -File \"" + tmpFile + "\""),
                RotationScriptType.Python     => new System.Diagnostics.ProcessStartInfo("python3", tmpFile),
                _                             => new System.Diagnostics.ProcessStartInfo("bash", tmpFile)
            };

            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError  = true;
            psi.UseShellExecute        = false;
            psi.CreateNoWindow         = true;

            if (env != null)
            {
                foreach (var kv in env)
                {
                    psi.Environment[kv.Key] = isTest && kv.Key.Contains("PASSWORD")
                        ? "[TEST_VALUE]"
                        : kv.Value;
                }
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(60));

            using var proc = new System.Diagnostics.Process { StartInfo = psi };
            proc.Start();

            var stdoutTask = proc.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderrTask = proc.StandardError.ReadToEndAsync(timeout.Token);

            await proc.WaitForExitAsync(timeout.Token);

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (stdout.Length > 8192) stdout = stdout[..8192] + "\n[truncated]";
            if (stderr.Length > 2048) stderr = stderr[..2048] + "\n[truncated]";

            return new ScriptRunResult(proc.ExitCode == 0, proc.ExitCode, stdout, stderr);
        }
        catch (OperationCanceledException)
        {
            return new ScriptRunResult(false, -1, null, "Script execution timed out after 60 seconds");
        }
        catch (Exception ex)
        {
            return new ScriptRunResult(false, -1, null, $"Failed to start script: {ex.Message}");
        }
        finally
        {
            try { File.Delete(tmpFile); } catch { /* best effort */ }
        }
    }
}
