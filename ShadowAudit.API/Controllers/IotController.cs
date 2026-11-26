using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Data;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.API.Controllers;

public record IotRequest(
    [Required(ErrorMessage = "Pega la salida del escaneo.")]
    [StringLength(20000, MinimumLength = 10, ErrorMessage = "La salida debe tener entre 10 y 20000 caracteres.")]
    string Output,

    [StringLength(100, ErrorMessage = "La etiqueta no puede pasar de 100 caracteres.")]
    string? Label = null);

[ApiController]
[Authorize]
[Route("api/iot")]
public class IotController : ControllerBase
{
    private readonly ShadowAuditDbContext _db;

    public IotController(ShadowAuditDbContext db) => _db = db;

    [HttpPost("ports")]
    [RequestSizeLimit(65536)]
    [SiteRateLimit("iot", 20, 60)]
    public async Task<IActionResult> Ports([FromBody] IotRequest request, CancellationToken ct)
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!Guid.TryParse(value, out var uid)) return Unauthorized();

        var labelError = FindingStore.ValidateLabel(request.Label, out var label);
        if (labelError is not null) return BadRequest(new { message = labelError });

        var result = IotAudit.Analyze(request.Output);
        await WriteAudit(uid);

        FindingSaveResult? finding = null;
        if (label is not null)
            finding = await FindingStore.SaveAsync(_db, uid, FindingSource.Iot, result.Risk, label, ct);

        return Ok(new
        {
            risk = result.Risk,
            findings = result.Findings,
            note = "Usa solo la salida de tus propios dispositivos. El texto que pegaste no se guarda.",
            finding
        });
    }

    // Solo se registra que hubo una consulta, nunca el texto pegado.
    private async Task WriteAudit(Guid userId)
    {
        var email = await _db.Users.AsNoTracking().Where(u => u.Id == userId)
            .Select(u => u.Email).FirstOrDefaultAsync() ?? string.Empty;
        var userAgent = Request.Headers.UserAgent.ToString();
        if (userAgent.Length > 256) userAgent = userAgent[..256];

        _db.AuditLogs.Add(new AuditLog
        {
            UserId = userId,
            Email = email.Length > 256 ? email[..256] : email,
            Action = "IotCheck",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}