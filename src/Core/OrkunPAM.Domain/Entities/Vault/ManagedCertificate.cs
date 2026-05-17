namespace OrkunPAM.Domain.Entities.Vault;

public class ManagedCertificate
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string SubjectCN { get; set; } = "";
    public string? SubjectAltNames { get; set; }
    public string? Issuer { get; set; }
    public string Thumbprint { get; set; } = "";
    public string? SerialNumber { get; set; }
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string? KeyUsage { get; set; }
    public string? KeyAlgorithm { get; set; }
    public int KeySizeBits { get; set; }
    public string? PemCertificateEnc { get; set; } // AES-256-GCM encrypted
    public Guid? DeviceId { get; set; }
    public Guid? FolderId { get; set; }
    public string? Notes { get; set; }
    public string Source { get; set; } = "Manual"; // Manual, Discovered, ACME
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid? CreatedBy { get; set; }
}
