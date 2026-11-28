using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Data;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.API.Controllers;

public record AccessReviewRequest(
    [Range(7, 90, ErrorMessage = "Los días deben estar entre 7 y 90.")]
    int Days = 30,

    [StringLength(100, ErrorMessage = "La etiqueta no puede pasar de 100 caracteres.")]
    string? Label = null);

[ApiController]
[Authorize]
[Route("api/access")]
public class AccessController : ControllerBase
{
    private readonly ShadowAuditDbContext _db;

    public AccessController(ShadowAuditDbContext db) => _db = db;

    [HttpPost("review")]
    [SiteRateLimit("access", 20, 60)]
    public async Task<IActionResult> Review(
        [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] AccessReviewRequest? request,
        CancellationToken ct)
    {
        request ??= new AccessReviewRequest();

        var value = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!Guid.TryParse(value, out var uid)) return Unauthorized();

        var labelError = FindingStore.ValidateLabel(request.Label, out var label);
        if (labelError is not null) return BadRequest(new { message = labelError });

        var now = DateTime.UtcNow;
        var since = now.AddDays(-request.Days);
        var events = await _db.AuditLogs.AsNoTracking()
            .Where(a => a.UserId == uid && a.CreatedAt >= since)
            .OrderByDescending(a => a.CreatedAt)
            .Take(5000)
            .Select(a => new AccessEvent(a.Action, a.IpAddress, a.UserAgent, a.CreatedAt))
            .ToListAsync(ct);

        var result = AccessAudit.Analyze(events, now);
        await WriteAudit(uid);

        FindingSaveResult? finding = null;
        if (label is not null)
            finding = await FindingStore.SaveAsync(_db, uid, FindingSource.Access, result.Risk, label, ct);

        return Ok(new
        {
            risk = result.Risk,
            days = request.Days,
            hasBaseline = result.HasBaseline,
            loginSuccesses = result.LoginSuccesses,
            failedLast24h = result.FailedLast24h,
            newIps = result.NewIps,
            newDevices = result.NewDevices,
            findings = result.Findings,
            note = "Solo se revisa el registro de accesos de tu cuenta en ShadowAudit. Las IPs se muestran con el último número oculto.",
            finding
        });
    }

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
            Action = "AccessReview",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}