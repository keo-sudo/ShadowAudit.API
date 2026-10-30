using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OtpNet;
using QRCoder;
using ShadowAudit.API.Data;

namespace ShadowAudit.API.Controllers;

public record VerifyCodeRequest(string Code);

[ApiController]
[Authorize]
[Route("api/2fa")]
public class TwoFactorController : ControllerBase
{
    private readonly ShadowAuditDbContext _db;

    public TwoFactorController(ShadowAuditDbContext db)
    {
        _db = db;
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

        user.TwoFactorSecret = secret;
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

    // Paso B: confirma con el primer código y activa el 2FA
    [HttpPost("enable")]
    public async Task<IActionResult> Enable([FromBody] VerifyCodeRequest request)
    {
        var user = await GetCurrentUser();
        if (user is null) return Unauthorized();

        if (user.TwoFactorEnabled)
            return Conflict(new { message = "El 2FA ya está activado." });

        if (string.IsNullOrEmpty(user.TwoFactorSecret))
            return BadRequest(new { message = "Primero llama a /api/2fa/setup." });

        var code = (request.Code ?? string.Empty).Replace(" ", "").Trim();
        if (code.Length != 6)
            return BadRequest(new { message = "El código debe tener 6 dígitos." });

        var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
        if (!totp.VerifyTotp(code, out long step, VerificationWindow.RfcSpecifiedNetworkDelay))
            return BadRequest(new { message = "Código inválido." });

        user.TwoFactorEnabled = true;
        user.TwoFactorLastUsedStep = step;
        await _db.SaveChangesAsync();

        return Ok(new { message = "2FA activado correctamente." });
    }

    private async Task<Models.User?> GetCurrentUser()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!Guid.TryParse(value, out var id)) return null;
        return await _db.Users.FirstOrDefaultAsync(u => u.Id == id);
    }
}