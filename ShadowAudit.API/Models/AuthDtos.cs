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

    // Código del celular (6 dígitos) o código de recuperación (XXXXX-XXXXX)
    [StringLength(16, ErrorMessage = "El código 2FA es demasiado largo.")]
    string? TwoFactorCode = null);

public record ChangePasswordRequest(
    [Required(ErrorMessage = "La contraseña actual es obligatoria.")]
    [StringLength(128, ErrorMessage = "La contraseña actual es demasiado larga.")]
    string CurrentPassword,

    [Required(ErrorMessage = "La contraseña nueva es obligatoria.")]
    [StringLength(128, ErrorMessage = "La contraseña nueva es demasiado larga.")]
    string NewPassword,

    [StringLength(16, ErrorMessage = "El código 2FA es demasiado largo.")]
    string? TwoFactorCode = null);

public record RefreshRequest(
    [Required(ErrorMessage = "El refresh token es obligatorio.")]
    [StringLength(128, MinimumLength = 20, ErrorMessage = "El refresh token no es válido.")]
    string RefreshToken);

public record AuthResponse(
    string Token,
    string Username,
    string Email,
    DateTime ExpiresAt,
    string RefreshToken,
    DateTime RefreshExpiresAt);