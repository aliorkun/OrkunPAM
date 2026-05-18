namespace OrkunPAM.TelnetProxy;

/// <summary>
/// RFC 854 Telnet option negotiation helpers.
/// Stateless — all methods operate on raw byte spans.
/// </summary>
internal static class TelnetNegotiator
{
    public const byte IAC  = 0xFF;
    public const byte DONT = 0xFE;
    public const byte DO   = 0xFD;
    public const byte WONT = 0xFC;
    public const byte WILL = 0xFB;
    public const byte SB   = 0xFA;
    public const byte SE   = 0xF0;

    // Common options
    public const byte OPT_ECHO             = 0x01;
    public const byte OPT_SUPPRESS_GO_AHEAD = 0x03;
    public const byte OPT_TERMINAL_TYPE    = 0x18;
    public const byte OPT_NAWS             = 0x1F;

    public static byte[] Will(byte opt) => [IAC, WILL, opt];
    public static byte[] Wont(byte opt) => [IAC, WONT, opt];
    public static byte[] Do(byte opt)   => [IAC, DO,   opt];
    public static byte[] Dont(byte opt) => [IAC, DONT, opt];

    /// <summary>
    /// Strip IAC sequences from data, returning only printable content for recording.
    /// </summary>
    public static byte[] StripIac(ReadOnlySpan<byte> data)
    {
        var result = new List<byte>(data.Length);
        int i = 0;
        while (i < data.Length)
        {
            if (data[i] != IAC) { result.Add(data[i++]); continue; }
            if (++i >= data.Length) break;
            byte cmd = data[i++];
            if (cmd is WILL or WONT or DO or DONT)
            {
                if (i < data.Length) i++; // skip option byte
            }
            else if (cmd == SB)
            {
                // skip subnegotiation until IAC SE
                while (i < data.Length - 1)
                {
                    if (data[i] == IAC && data[i + 1] == SE) { i += 2; break; }
                    i++;
                }
            }
            // single-byte command: already consumed
        }
        return [.. result];
    }

    /// <summary>
    /// Parse inbound IAC sequences and build polite responses.
    /// Returns response bytes to send back (may be empty if no response needed).
    /// </summary>
    public static byte[] BuildResponse(ReadOnlySpan<byte> data)
    {
        var response = new List<byte>(16);
        int i = 0;
        while (i < data.Length)
        {
            if (data[i] != IAC) { i++; continue; }
            if (++i >= data.Length) break;
            byte cmd = data[i++];
            if (cmd is WILL or WONT or DO or DONT)
            {
                if (i >= data.Length) break;
                byte opt = data[i++];
                switch (cmd)
                {
                    case WILL:
                        // Accept ECHO and SGA from remote
                        response.AddRange(opt is OPT_ECHO or OPT_SUPPRESS_GO_AHEAD
                            ? Do(opt) : Dont(opt));
                        break;
                    case DO:
                        // We can handle SGA; decline ECHO (we handle it explicitly per-phase)
                        response.AddRange(opt == OPT_SUPPRESS_GO_AHEAD
                            ? Will(opt) : Wont(opt));
                        break;
                    // WONT / DONT: no reply needed
                }
            }
            else if (cmd == SB)
            {
                while (i < data.Length - 1)
                {
                    if (data[i] == IAC && data[i + 1] == SE) { i += 2; break; }
                    i++;
                }
            }
        }
        return [.. response];
    }

    /// <summary>
    /// True when the buffer starts with an IAC sequence (not plain data).
    /// </summary>
    public static bool StartsWithIac(ReadOnlySpan<byte> data) =>
        data.Length > 0 && data[0] == IAC;

    /// <summary>
    /// Build the initial option negotiation burst sent to a newly connected client.
    /// We: WILL ECHO (we handle echo), WILL SGA, DO SGA, DONT LINEMODE.
    /// </summary>
    public static byte[] InitialNegotiation() =>
    [
        .. Will(OPT_ECHO),             // server controls echo
        .. Will(OPT_SUPPRESS_GO_AHEAD),
        .. Do(OPT_SUPPRESS_GO_AHEAD),
        IAC, DONT, 0x22               // DONT LINEMODE (0x22) — char-at-a-time mode
    ];

    /// <summary>IAC WONT ECHO — tell client to resume its own local echo (after password).</summary>
    public static byte[] ResumeClientEcho() => Wont(OPT_ECHO);
}
