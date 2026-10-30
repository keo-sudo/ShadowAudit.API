using System.ComponentModel.DataAnnotations;

namespace ShadowAudit.API.Models;

public record RegisterRequest(
    [Required(ErrorMessage = "El usuario es obligatorio.")]
    [StringLength(50, MinimumLength = 3, ErrorMessage = "El usuario debe tener entre 3 y 50 caracteres.")]
    [RegularExpression(@"^[a-zA-Z0-9_.\-]+$", ErrorMessage = "El usuario solo puede tener letras, números, punto, guion y guion bajo.")]
    string Username,

    [Required(ErrorMessage = "El email es obligatorio.")]
    [StringLength(256, ErrorMessage = "El email es demasiado largo.")]
    [EmailAddress(ErrorMessage = "El email no tiene un formato válido.")]
    string Email,

    [Required(ErrorMessage = "La contraseña es obligatoria.")]
    [StringLength(128, ErrorMessage = "La contraseña es demasiado larga.")]
    string Password);

public record LoginRequest(
    [Required(ErrorMessage = "El email es obligatorio.")]
    [StringLength(256, ErrorMessage = "El email es demasiado largo.")]
    string Email,

    [Required(ErrorMessage = "La contraseña es obligatoria.")]
    [StringLength(128, ErrorMessage = "La contraseña es demasiado larga.")]
    string Password,

    [StringLength(10, ErrorMessage = "El código 2FA es demasiado largo.")]
    string? TwoFactorCode = null);

public record AuthResponse(string Token, string Username, string Email, DateTime ExpiresAt);