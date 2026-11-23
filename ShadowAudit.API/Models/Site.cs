namespace ShadowAudit.API.Models;

// Sitio web propio que el usuario registra para escanear.
// Solo se puede escanear si demostró que es suyo (verificación de propiedad).
public class Site
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string Host { get; set; } = string.Empty;
    public string VerificationToken { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? VerifiedAtUtc { get; set; }
    public DateTime? LastScanAtUtc { get; set; }
}