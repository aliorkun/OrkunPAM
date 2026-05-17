using Microsoft.Win32;

namespace OrkunPAM.Cryptography;

public static class FipsUtils
{
    private static bool? _cached;

    public static bool IsFipsEnabled()
    {
        if (_cached.HasValue) return _cached.Value;

        bool enabled = false;
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy");
                enabled = key?.GetValue("Enabled") is int v && v == 1;
            }
            catch { }
        }
        else if (OperatingSystem.IsLinux())
        {
            try { enabled = File.ReadAllText("/proc/sys/crypto/fips_enabled").Trim() == "1"; }
            catch { }
        }

        return (_cached = enabled).Value;
    }

    public static string GetComplianceNote() => IsFipsEnabled()
        ? "System FIPS policy is active. AES-256-GCM (CNG-backed) and PBKDF2-SHA256 are FIPS 140-2 approved."
        : "FIPS policy is not enforced. AES-256-GCM and PBKDF2-SHA256 are FIPS 140-2 approved algorithms.";
}
