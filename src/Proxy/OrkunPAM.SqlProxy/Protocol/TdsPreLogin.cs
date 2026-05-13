namespace OrkunPAM.SqlProxy.Protocol;

/// <summary>
/// Handles the TDS PreLogin message exchange (packet type 0x12).
///
/// PreLogin payload: a list of option records [token(1) offset(2) length(2)] followed
/// by 0xFF terminator, then the option data at the declared offsets.
/// Offsets are measured from the start of the PreLogin payload (big-endian).
///
/// Key option tokens:
///   0x00 VERSION     — 4-byte version + 2-byte sub-build
///   0x01 ENCRYPTION  — 1 byte: 0x00=OFF, 0x01=ON, 0x02=NOT_SUP, 0x03=REQ
///   0xFF TERMINATOR
/// </summary>
internal static class TdsPreLogin
{
    public const byte EncryptOff    = 0x00;
    public const byte EncryptOn     = 0x01;
    public const byte EncryptNotSup = 0x02;
    public const byte EncryptReq    = 0x03;

    private const byte OptVersion    = 0x00;
    private const byte OptEncryption = 0x01;
    private const byte OptTerminator = 0xFF;

    /// <summary>
    /// Parse the ENCRYPTION byte from a client or server PreLogin payload.
    /// Returns 0xFF if not found.
    /// </summary>
    public static byte ParseEncryption(byte[] payload)
    {
        int pos = 0;
        while (pos < payload.Length)
        {
            byte opt = payload[pos];
            if (opt == OptTerminator) break;
            if (pos + 4 >= payload.Length) break;

            int offset = (payload[pos + 1] << 8) | payload[pos + 2];
            int length = (payload[pos + 3] << 8) | payload[pos + 4];
            pos += 5;

            if (opt == OptEncryption && offset < payload.Length && length >= 1)
                return payload[offset];
        }
        return 0xFF;
    }

    /// <summary>
    /// Build a PreLogin response payload advertising SQL Server 2019 (v15.0)
    /// with ENCRYPT_NOT_SUP, forcing the client to send Login7 in plaintext.
    ///
    /// Layout (18 bytes):
    ///   Option records (11 bytes): VERSION + ENCRYPTION + TERMINATOR
    ///   VERSION data  (6 bytes):   major=15, minor=0, build=0, subbuild=0
    ///   ENCRYPTION    (1 byte):    0x02 (NOT_SUP)
    /// </summary>
    public static byte[] BuildResponseNotSup()
    {
        // 2 option records * 5 bytes + terminator = 11 bytes header
        // VERSION data at offset 11 (6 bytes), ENCRYPTION at offset 17 (1 byte)
        var payload = new byte[18];

        // VERSION option
        payload[0] = OptVersion;
        payload[1] = 0x00; payload[2] = 11; // offset = 11
        payload[3] = 0x00; payload[4] = 6;  // length = 6

        // ENCRYPTION option
        payload[5] = OptEncryption;
        payload[6] = 0x00; payload[7] = 17; // offset = 17
        payload[8] = 0x00; payload[9] = 1;  // length = 1

        // TERMINATOR
        payload[10] = OptTerminator;

        // VERSION data: SQL Server 2019 = 15.0.0000.0000
        payload[11] = 0x0F; // major = 15
        payload[12] = 0x00; // minor = 0
        // bytes [13..16]: build & subbuild = 0
        // ENCRYPTION = NOT_SUP
        payload[17] = EncryptNotSup;

        return payload;
    }

    /// <summary>
    /// Build a PreLogin request payload for the proxy→target connection,
    /// requesting ENCRYPT_NOT_SUP (we want plaintext to target for credential injection).
    /// Identical structure to the response; caller sends it as a PreLogin packet.
    /// </summary>
    public static byte[] BuildRequestNotSup() => BuildResponseNotSup();
}
