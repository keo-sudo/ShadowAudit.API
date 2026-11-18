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

public record EmailHeadersRequest(
    [Required(ErrorMessage = "Las cabeceras son obligatorias.")]
    [StringLength(65536, MinimumLength = 20, ErrorMessage = "Las cabeceras deben tener entre 20 y 65536 caracteres.")]
    string Headers);

[ApiController]
[Authorize]
[Route("api/threats")]
public class EmailThreatsController : ControllerBase
{
    private readonly ShadowAuditDbContext _db;

    public EmailThreatsController(ShadowAuditDbContext db)
    {
        _db = db;
    }

    [HttpPost("email-headers")]
    [RequestSizeLimit(131072)]
    public async Task<IActionResult> AnalyzeHeaders([FromBody] EmailHeadersRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var analysis = EmailHeaderAnalyzer.Analyze(request.Headers);

        await WriteAudit(userId.Value);

        return Ok(new
        {
            analysis.Risk,
            analysis.Score,
            analysis.Verdict,
            authentication = new
            {
                spf = analysis.Spf,
                dkim = analysis.Dkim,
                dmarc = analysis.Dmarc
            },
            sender = new
            {
                name = analysis.FromName,
                address = analysis.FromAddress,
                domain = analysis.FromDomain,
                replyToDomain = analysis.ReplyToDomain,
                returnPathDomain = analysis.ReturnPathDomain,
                dkimDomain = analysis.DkimDomain
            },
            route = new
            {
                hops = analysis.Hops,
                publicIps = analysis.PublicIps
            },
            analysis.Findings,
            note = "SPF, DKIM y DMARC solo son confiables si los anotó tu propio proveedor de correo (la cabecera de más arriba). El análisis no revisa el contenido, los enlaces ni los adjuntos."
        });
    }

    private Guid? GetCurrentUserId()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    // Solo se registra que hubo una consulta. Las cabeceras NO se guardan.
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
            Action = "ThreatCheckEmail",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}