using System.Text;

namespace OrkunPAM.SqlProxy.Protocol;

/// <summary>
/// Handles the TDS Login7 packet (type 0x10).
///
/// Login7 payload fixed header (94 bytes, all little-endian):
///   [0..3]   Length          — total payload length (includes this field)
///   [4..7]   TDSVersion      — e.g. 0x04000074 = TDS 7.4
///   [8..11]  PacketSize
///   [12..15] ClientProgVer
///   [16..19] ClientPID
///   [20..23] ConnectionID
///   [24]     OptionalFlags1
///   [25]     OptionalFlags2
///   [26]     TypeFlags
///   [27]     OptionalFlags3
///   [28..31] ClientTimeZone
///   [32..35] ClientLCID
///   String offset/length pairs (each 2+2 bytes = 4 bytes):
///   [36..39]  ibHostName / cchHostName
///   [40..43]  ibUserName / cchUserName
///   [44..47]  ibPassword / cchPassword   (password bytes are nibble-swapped XOR 0xA5)
///   [48..51]  ibAppName  / cchAppName
///   [52..55]  ibServerName / cchServerName
///   [56..59]  ibExtension / cbExtension
///   [60..63]  ibCltIntName / cchCltIntName
///   [64..67]  ibLanguage / cchLanguage
///   [68..71]  ibDatabase / cchDatabase
///   [72..77]  ClientID (6-byte MAC address)
///   [78..81]  ibSSPI / cbSSPI
///   [82..85]  ibAtchDBFile / cchAtchDBFile
///   [86..89]  ibChangePassword / cchChangePassword
///   [90..93]  cbSSPILong
///   Variable string data follows at offset 94.
///
/// All string data is encoded as UCS-2 LE (UTF-16 LE); offsets are absolute
/// from the start of the Login7 payload.
/// </summary>
internal static class TdsLogin7
{
    private static readonly Encoding Ucs2Le = Encoding.Unicode; // UTF-16 LE

    private const int FixedHeaderSize = 94;

    /// <summary>
    /// Extract the PAM username from the client Login7 payload.
    /// Returns null if payload is too short, SSPI auth is used, or username field is empty.
    /// </summary>
    public static string? ExtractUsername(byte[] payload)
    {
        if (payload.Length < FixedHeaderSize) return null;

        // Check if SSPI (Windows Auth) is being used — cbSSPI at offset 80
        int cbSspi = BitConverter.ToUInt16(payload, 80);
        if (cbSspi > 0) return null; // Windows Auth — not supported by SQL proxy

        return ReadString(payload, 40);
    }

    /// <summary>Extract the PAM password from the Login7 payload (de-obfuscated).</summary>
    public static string? ExtractPassword(byte[] payload)
    {
        if (payload.Length < FixedHeaderSize) return null;
        return ReadObfuscatedPassword(payload, 44);
    }

    /// <summary>Extract the target server name from the Login7 payload.</summary>
    public static string? ExtractServerName(byte[] payload)
    {
        if (payload.Length < FixedHeaderSize) return null;
        return ReadString(payload, 52);
    }

    /// <summary>Extract the target database name from the Login7 payload.</summary>
    public static string? ExtractDatabase(byte[] payload)
    {
        if (payload.Length < FixedHeaderSize) return null;
        return ReadString(payload, 68);
    }

    /// <summary>
    /// Build a new Login7 payload substituting the given SQL Server credentials.
    /// The original TDS version, packet size, app name, client flags, etc. are preserved.
    /// Extension, SSPI, and change-password fields are cleared.
    /// </summary>
    public static byte[] BuildWithCredentials(
        byte[] original,
        string sqlUsername,
        string sqlPassword,
        string? targetServerName = null,
        string? targetDatabase   = null)
    {
        if (original.Length < FixedHeaderSize)
            throw new InvalidDataException("Login7 payload too short");

        // Preserve the fixed header verbatim, then rebuild variable section
        var fixedHeader = new byte[FixedHeaderSize];
        Buffer.BlockCopy(original, 0, fixedHeader, 0, FixedHeaderSize);

        // Fields to include in variable section
        string hostname   = ReadString(original, 36) ?? "";
        string appName    = ReadString(original, 48) ?? "OrkunPAM SQL Proxy";
        string serverName = targetServerName ?? ReadString(original, 52) ?? "";
        string intName    = ReadString(original, 60) ?? "";
        string language   = ReadString(original, 64) ?? "";
        string database   = targetDatabase   ?? ReadString(original, 68) ?? "";

        // Build variable section and fix up offset fields in the header copy
        using var varStream = new MemoryStream();
        int currentOffset = FixedHeaderSize;

        currentOffset = WriteStringField(fixedHeader, 36, hostname,   Ucs2Le, varStream, currentOffset);
        currentOffset = WriteStringField(fixedHeader, 40, sqlUsername, Ucs2Le, varStream, currentOffset);
        currentOffset = WritePasswordField(fixedHeader, 44, sqlPassword, varStream, currentOffset);
        currentOffset = WriteStringField(fixedHeader, 48, appName,    Ucs2Le, varStream, currentOffset);
        currentOffset = WriteStringField(fixedHeader, 52, serverName, Ucs2Le, varStream, currentOffset);
        // Extension: none
        fixedHeader[56] = 0; fixedHeader[57] = 0; fixedHeader[58] = 0; fixedHeader[59] = 0;
        currentOffset = WriteStringField(fixedHeader, 60, intName,    Ucs2Le, varStream, currentOffset);
        currentOffset = WriteStringField(fixedHeader, 64, language,   Ucs2Le, varStream, currentOffset);
        currentOffset = WriteStringField(fixedHeader, 68, database,   Ucs2Le, varStream, currentOffset);

        // ClientID (MAC, 6 bytes at offset 72) — preserve from original
        // ibSSPI / cbSSPI — clear (no SSPI)
        fixedHeader[78] = 0; fixedHeader[79] = 0; fixedHeader[80] = 0; fixedHeader[81] = 0;
        // ibAtchDBFile / cchAtchDBFile — clear
        fixedHeader[82] = 0; fixedHeader[83] = 0; fixedHeader[84] = 0; fixedHeader[85] = 0;
        // ibChangePassword / cchChangePassword — clear
        fixedHeader[86] = 0; fixedHeader[87] = 0; fixedHeader[88] = 0; fixedHeader[89] = 0;
        // cbSSPILong — clear
        fixedHeader[90] = 0; fixedHeader[91] = 0; fixedHeader[92] = 0; fixedHeader[93] = 0;

        var varBytes   = varStream.ToArray();
        int totalLen   = FixedHeaderSize + varBytes.Length;
        BitConverter.GetBytes(totalLen).CopyTo(fixedHeader, 0); // Length field at offset 0

        var result = new byte[totalLen];
        fixedHeader.CopyTo(result, 0);
        varBytes.CopyTo(result, FixedHeaderSize);
        return result;
    }

    // ---- private helpers ----

    private static string? ReadString(byte[] payload, int offsetField)
    {
        if (offsetField + 4 > payload.Length) return null;
        int offset = BitConverter.ToUInt16(payload, offsetField);
        int length = BitConverter.ToUInt16(payload, offsetField + 2);
        if (length == 0) return "";
        if (offset + length * 2 > payload.Length) return null;
        return Ucs2Le.GetString(payload, offset, length * 2);
    }

    private static string? ReadObfuscatedPassword(byte[] payload, int offsetField)
    {
        if (offsetField + 4 > payload.Length) return null;
        int offset = BitConverter.ToUInt16(payload, offsetField);
        int length = BitConverter.ToUInt16(payload, offsetField + 2);
        if (length == 0) return "";
        if (offset + length * 2 > payload.Length) return null;

        var obf = new byte[length * 2];
        Buffer.BlockCopy(payload, offset, obf, 0, obf.Length);

        // Reverse obfuscation: swap nibbles then XOR 0xA5
        for (int i = 0; i < obf.Length; i++)
            obf[i] = (byte)(((obf[i] >> 4) | (obf[i] << 4)) ^ 0xA5);

        return Ucs2Le.GetString(obf);
    }

    private static int WriteStringField(byte[] header, int offsetField, string text,
        Encoding enc, MemoryStream dest, int currentOffset)
    {
        var bytes = text.Length > 0 ? enc.GetBytes(text) : [];
        BitConverter.GetBytes((ushort)currentOffset).CopyTo(header, offsetField);
        BitConverter.GetBytes((ushort)text.Length).CopyTo(header, offsetField + 2);
        if (bytes.Length > 0) dest.Write(bytes);
        return currentOffset + bytes.Length;
    }

    private static int WritePasswordField(byte[] header, int offsetField, string password,
        MemoryStream dest, int currentOffset)
    {
        var ucs2 = Ucs2Le.GetBytes(password);

        // Obfuscate: XOR 0xA5 then nibble-swap each byte
        for (int i = 0; i < ucs2.Length; i++)
        {
            ucs2[i] ^= 0xA5;
            ucs2[i] = (byte)((ucs2[i] << 4) | (ucs2[i] >> 4));
        }

        BitConverter.GetBytes((ushort)currentOffset).CopyTo(header, offsetField);
        BitConverter.GetBytes((ushort)password.Length).CopyTo(header, offsetField + 2);
        if (ucs2.Length > 0) dest.Write(ucs2);
        return currentOffset + ucs2.Length;
    }
}
