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

public record FootprintRequest(
    [Required(ErrorMessage = "El usuario es obligatorio.")]
    [StringLength(39, ErrorMessage = "El usuario no puede pasar de 39 caracteres.")]
    string Username,

    [StringLength(100, ErrorMessage = "La etiqueta no puede pasar de 100 caracteres.")]
    string? Label = null);

[ApiController]
[Authorize]
[Route("api/footprint")]
public class FootprintController : ControllerBase
{
    private readonly ShadowAuditDbContext _db;
    private readonly FootprintChecker _checker;

    public FootprintController(ShadowAuditDbContext db, FootprintChecker checker)
    {
        _db = db;
        _checker = checker;
    }

    [HttpPost("username")]
    [SiteRateLimit("footprint", 5, 60)]
    public async Task<IActionResult> CheckUsername([FromBody] FootprintRequest request, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        if (!UsernameRules.IsValid(request.Username))
            return BadRequest(new { message = "El usuario solo puede tener letras, números, punto, guion y guion bajo (hasta 39 caracteres) y debe empezar con letra o número." });

        var labelError = FindingStore.ValidateLabel(request.Label, out var label, request.Username);
        if (labelError is not null) return BadRequest(new { message = labelError });

        var results = await _checker.CheckAsync(request.Username, ct);
        var risk = FootprintChecker.Risk(results);

        await WriteAudit(uid);

        FindingSaveResult? finding = null;
        if (label is not null)
            finding = await FindingStore.SaveAsync(_db, uid, FindingSource.Footprint, risk, label, ct);

        return Ok(new
        {
            risk,
            found = results.Count(r => r.Status == "existe"),
            results = results.Select(r => new { site = r.Site, status = r.Status }),
            note = "Usa solo tus propios nombres de usuario. 'indeterminado' significa que el sitio no dio una respuesta clara (bloqueo, redirección o error). El nombre de usuario consultado no se guarda.",
            finding
        });
    }

    private Guid? GetCurrentUserId()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    // Solo se registra que hubo una consulta, nunca el usuario consultado.
    private async Task WriteAudit(Guid userId)
    {
        var email = await _db.Users.AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => u.Email)
            .FirstOrDefaultAsync() ?? string.Empty;

        var userAgent = Request.Headers.UserAgent.ToString();
        if (userAgent.Length > 256) userAgent = userAgent[..256];

        _db.AuditLogs.Add(new AuditLog
        {
            UserId = userId,
            Email = email.Length > 256 ? email[..256] : email,
            Action = "FootprintCheck",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}