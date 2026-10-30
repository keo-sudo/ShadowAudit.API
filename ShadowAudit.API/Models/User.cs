using System.ComponentModel.DataAnnotations;

namespace ShadowAudit.API.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(100)]
    public string Username { get; set; } = string.Empty;

    [Required]
    [MaxLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string PasswordHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // --- Bloqueo por fuerza bruta ---
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockedUntil { get; set; } = null;

    // --- 2FA (TOTP) ---
    public bool TwoFactorEnabled { get; set; } = false;
    // Guarda el secreto CIFRADO con Data Protection, nunca en texto plano
    [MaxLength(512)]
    public string? TwoFactorSecret { get; set; } = null;
    public long? TwoFactorLastUsedStep { get; set; } = null;
}