namespace OrkunPAM.Domain.Entities.Identity;

public class Fido2Credential
{
    public Guid     Id                { get; set; } = Guid.NewGuid();
    public Guid     UserId            { get; set; }
    public byte[]   CredentialIdBytes { get; set; } = [];
    public string   CredentialIdB64   { get; set; } = "";
    public byte[]   PublicKeyX        { get; set; } = [];
    public byte[]   PublicKeyY        { get; set; } = [];
    public uint     SignatureCounter   { get; set; }
    public string   FriendlyName      { get; set; } = "Security Key";
    /// <summary>"cross-platform" (hardware key) or "platform" (Windows Hello / Touch ID)</summary>
    public string   AuthenticatorType { get; set; } = "cross-platform";
    public bool     IsActive          { get; set; } = true;
    public DateTime RegisteredAtUtc   { get; set; } = DateTime.UtcNow;
    public DateTime? LastUsedAtUtc    { get; set; }
}
