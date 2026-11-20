using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OtpNet;
using QRCoder;
using ShadowAudit.API.Data;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;
using AppUser = ShadowAudit.API.Models.User;

namespace ShadowAudit.API.Controllers;

public record VerifyCodeRequest(
    [Required(ErrorMessage = "El código es obligatorio.")]
    [StringLength(16, ErrorMessage = "El código es demasiado largo.")]
    string Code);

public record TwoFactorConfirmRequest(
    [Required(ErrorMessage = "La contraseña es obligatoria.")]
    [StringLength(128, ErrorMessage = "La contraseña es demasiado larga.")]
    string Password,

    [Required(ErrorMessage = "El código es obligatorio.")]
    [StringLength(16, ErrorMessage = "El código es demasiado largo.")]
    string Code);

[ApiController]
[Authorize]
[Route("api/2fa")]
public class TwoFactorController : ControllerBase
{
    private readonly ShadowAuditDbContext _db;
    private readonly TwoFactorSecretProtector _protector;

    public TwoFactorController(ShadowAuditDbContext db, TwoFactorSecretProtector protector)
    {
        _db = db;
        _protector = protector;
    }

    // Estado del 2FA y cuántos códigos de recuperación quedan
    [HttpGet("status")]
    public async Task<IActionResult> Status()
    {
        var user = await GetCurrentUser();
        if (user is null) return Unauthorized();

        var remaining = await _db.RecoveryCodes
            .CountAsync(r => r.UserId == user.Id && r.UsedAtUtc == null);

        return Ok(new { enabled = user.TwoFactorEnabled, recoveryCodesRemaining = remaining });
    }

    // Paso A: genera el secreto y el QR (aún NO activa el 2FA)
    [HttpPost("setup")]
    public async Task<IActionResult> Setup()
    {
        var user = await GetCurrentUser();
        if (user is null) return Unauthorized();

        if (user.TwoFactorEnabled)
            return Conflict(new { message = "El 2FA ya está activado." });

        var secretBytes = KeyGeneration.GenerateRandomKey(20);
        var secret = Base32Encoding.ToString(secretBytes);

        // El secreto se guarda cifrado; solo se muestra aquí, una vez.
        user.TwoFactorSecret = _protector.Protect(secret);
        user.TwoFactorLastUsedStep = null;
        await _db.SaveChangesAsync();

        var label = Uri.EscapeDataString($"ShadowAudit:{user.Email}");
        var uri = $"otpauth://totp/{label}?secret={secret}&issuer=ShadowAudit";

        using var generator = new QRCodeGenerator();
        using var qrData = generator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(qrData).GetGraphic(10);
        var dataUrl = "data:image/png;base64," + Convert.ToBase64String(png);

        return Ok(new
        {
            message = "Escanea el QR con Google Authenticator y luego confirma con /api/2fa/enable.",
            manualKey = secret,
            qrCodeDataUrl = dataUrl
        });
    }

    // Paso B: confirma con el primer código, activa el 2FA y entrega los códigos de recuperación
    [HttpPost("enable")]
    public async Task<IActionResult> Enable([FromBody] VerifyCodeRequest request)
    {
        var user = await GetCurrentUser();
        if (user is null) return Unauthorized();

        if (user.TwoFactorEnabled)
            return Conflict(new { message = "El 2FA ya está activado." });

        var secret = _protector.Unprotect(user.TwoFactorSecret);
        if (secret is null)
            return BadRequest(new { message = "Primero llama a /api/2fa/setup." });

        var code = (request.Code ?? string.Empty).Replace(" ", "").Trim();
        if (code.Length != 6)
            return BadRequest(new { message = "El código debe tener 6 dígitos." });

        var totp = new Totp(Base32Encoding.ToBytes(secret));
        if (!totp.VerifyTotp(code, out long step, VerificationWindow.RfcSpecifiedNetworkDelay))
            return BadRequest(new { message = "Código inválido." });

        user.TwoFactorEnabled = true;
        user.TwoFactorLastUsedStep = step;

        var codes = await TwoFactorVerifier.ReplaceRecoveryCodesAsync(_db, user.Id);
        await _db.SaveChangesAsync();
        await WriteAudit(user, "TwoFactorEnabled");

        return Ok(new
        {
            message = "2FA activado correctamente. Guarda estos códigos de recuperación en un lugar seguro: no se volverán a mostrar.",
            recoveryCodes = codes
        });
    }

    // Genera 10 códigos de recuperación nuevos y anula los anteriores
    [HttpPost("recovery-codes")]
    public async Task<IActionResult> RegenerateRecoveryCodes([FromBody] TwoFactorConfirmRequest request)
    {
        var user = await GetCurrentUser();
        if (user is null) return Unauthorized();

        if (!user.TwoFactorEnabled)
            return Conflict(new { message = "El 2FA no está activado." });

        var error = await Confirm(user, request, "RecoveryCodesFailed");
        if (error is not null) return error;

        var codes = await TwoFactorVerifier.ReplaceRecoveryCodesAsync(_db, user.Id);
        user.ClearFailedAttempts();
        await _db.SaveChangesAsync();
        await WriteAudit(user, "RecoveryCodesRegenerated");

        return Ok(new
        {
            message = "Códigos nuevos generados. Los anteriores ya no sirven. Guárdalos en un lugar seguro: no se volverán a mostrar.",
            recoveryCodes = codes
        });
    }

    // Desactiva el 2FA (pide contraseña y un código vigente)
    [HttpPost("disable")]
    public async Task<IActionResult> Disable([FromBody] TwoFactorConfirmRequest request)
    {
        var user = await GetCurrentUser();
        if (user is null) return Unauthorized();

        if (!user.TwoFactorEnabled)
            return Conflict(new { message = "El 2FA no está activado." });

        var error = await Confirm(user, request, "TwoFactorDisableFailed");
        if (error is not null) return error;

        user.TwoFactorEnabled = false;
        user.TwoFactorSecret = null;
        user.TwoFactorLastUsedStep = null;
        user.ClearFailedAttempts();
        await TwoFactorVerifier.RemoveRecoveryCodesAsync(_db, user.Id);
        await _db.SaveChangesAsync();
        await WriteAudit(user, "TwoFactorDisabled");

        return Ok(new { message = "2FA desactivado." });
    }

    // Confirma contraseña y código. Un fallo cuenta como intento fallido de la cuenta.
    private async Task<IActionResult?> Confirm(AppUser user, TwoFactorConfirmRequest request, string failAction)
    {
        if (user.IsLocked)
            return Unauthorized(new { message = "Credenciales inválidas." });

        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            user.RegisterFailedAttempt();
            await _db.SaveChangesAsync();
            await WriteAudit(user, failAction);
            return Unauthorized(new { message = "Credenciales inválidas." });
        }

        var result = await TwoFactorVerifier.VerifyAsync(_db, _protector, user, request.Code);
        if (result is TwoFactorResult.Missing or TwoFactorResult.Invalid)
        {
            user.RegisterFailedAttempt();
            await _db.SaveChangesAsync();
            await WriteAudit(user, failAction);
            return Unauthorized(new { message = "Código 2FA inválido." });
        }

        return null;
    }

    private async Task<AppUser?> GetCurrentUser()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!Guid.TryParse(value, out var id)) return null;
        return await _db.Users.FirstOrDefaultAsync(u => u.Id == id);
    }

    private async Task WriteAudit(AppUser user, string action)
    {
        var userAgent = Request.Headers.UserAgent.ToString();
        if (userAgent.Length > 256) userAgent = userAgent[..256];

        _db.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Email = user.Email.Length > 256 ? user.Email[..256] : user.Email,
            Action = action,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}