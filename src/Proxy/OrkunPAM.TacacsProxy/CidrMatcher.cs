using System.Net;

namespace OrkunPAM.TacacsProxy;

/// <summary>
/// Resolves per-device TACACS+/RADIUS shared secrets by exact IP or CIDR prefix.
/// Keys in the SharedSecrets dictionary may be "192.168.1.1" or "10.0.0.0/8".
/// </summary>
internal static class CidrMatcher
{
    public static string? Resolve(string deviceIp, Dictionary<string, string> secrets)
    {
        if (secrets.TryGetValue(deviceIp, out var exact)) return exact;
        if (!IPAddress.TryParse(deviceIp, out var addr)) return null;

        foreach (var (key, value) in secrets)
        {
            int slash = key.IndexOf('/');
            if (slash < 0) continue;
            if (!IPAddress.TryParse(key[..slash], out var network)) continue;
            if (!int.TryParse(key[(slash + 1)..], out var prefix)) continue;
            if (IsInCidr(addr, network, prefix)) return value;
        }
        return null;
    }

    private static bool IsInCidr(IPAddress addr, IPAddress network, int prefix)
    {
        var a = addr.GetAddressBytes();
        var n = network.GetAddressBytes();
        if (a.Length != n.Length) return false;

        int full = prefix / 8, rem = prefix % 8;
        for (int i = 0; i < full && i < a.Length; i++)
            if (a[i] != n[i]) return false;

        if (rem > 0 && full < a.Length)
        {
            byte mask = (byte)(0xFF << (8 - rem));
            if ((a[full] & mask) != (n[full] & mask)) return false;
        }
        return true;
    }
}
