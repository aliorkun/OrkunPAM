namespace OrkunPAM.SshProxy.Session;

internal sealed record PtyParams(
    string TermType,
    uint WidthChars,
    uint HeightRows,
    uint WidthPixels,
    uint HeightPixels,
    byte[] Modes);
