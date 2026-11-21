namespace ShadowAudit.API.Models;

// Una sesión es una "familia" de refresh tokens: cada vez que se renueva, se crea
// un token nuevo con el mismo FamilyId y el anterior queda marcado como usado.
public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public Guid FamilyId { get; set; }

    // Huella SHA-256 del token. El token en claro nunca se guarda.a
    public string TokenHash { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? UsedAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
}