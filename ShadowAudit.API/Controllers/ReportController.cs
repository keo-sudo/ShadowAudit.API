using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Data;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.API.Controllers;

[ApiController]
[Authorize]
[Route("api")]
public class ReportController : ControllerBase
{
    private static readonly Dictionary<string, string> Advice = new()
    {
        [FindingSource.Password] = "Cambia las contraseñas débiles o filtradas y usa una distinta en cada cuenta.",
        [FindingSource.Url] = "No abras los enlaces marcados y avisa a quien te los envió.",
        [FindingSource.File] = "No abras ni ejecutes los archivos marcados: bórralos y pasa un antivirus.",
        [FindingSource.Email] = "No respondas ni abras enlaces de los correos sospechosos; repórtalos como phishing.",
        [FindingSource.Ip] = "Revisa de dónde viene la conexión de las IPs marcadas y bloquéalas si puedes."
    };

    private readonly ShadowAuditDbContext _db;

    public ReportController(ShadowAuditDbContext db)
    {
        _db = db;
    }

    // Reporte: puntaje de 0 a 100 con lo más urgente primero
    [HttpGet("report")]
    public async Task<IActionResult> GetReport(CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        var open = await _db.ExposureFindings.AsNoTracking()
            .Where(f => f.UserId == uid && f.ResolvedAtUtc == null)
            .ToListAsync(ct);

        var resolvedCount = await _db.ExposureFindings
            .CountAsync(f => f.UserId == uid && f.ResolvedAtUtc != null, ct);

        var score = RiskScoring.Score(open.Select(f => f.Risk));
        var level = open.Count == 0 ? "sin_hallazgos" : RiskScoring.Level(score);

        var ordered = open
            .OrderByDescending(f => RiskLevels.Rank(f.Risk))
            .ThenByDescending(f => f.CreatedAtUtc)
            .ToList();

        var bySource = open
            .GroupBy(f => f.Source)
            .Select(g => new
            {
                source = g.Key,
                count = g.Count(),
                highestRisk = g.OrderByDescending(f => RiskLevels.Rank(f.Risk)).First().Risk
            })
            .OrderByDescending(x => RiskLevels.Rank(x.highestRisk))
            .ThenByDescending(x => x.count)
            .ToList();

        var recommendations = bySource
            .Where(s => s.highestRisk != RiskLevels.Low && Advice.ContainsKey(s.source))
            .Select(s => Advice[s.source])
            .ToList();

        var summary = open.Count == 0
            ? "Todavía no hay hallazgos guardados. Haz consultas con el campo \"label\" para que cuenten en el reporte."
            : $"Tienes {open.Count} hallazgo(s) sin resolver. Nivel de exposición: {level}.";

        await WriteAudit(uid, "ReportView");

        return Ok(new
        {
            score,
            level,
            summary,
            totals = new
            {
                open = open.Count,
                resolved = resolvedCount,
                alto = open.Count(f => f.Risk == RiskLevels.High),
                medio = open.Count(f => f.Risk == RiskLevels.Medium),
                bajo = open.Count(f => f.Risk == RiskLevels.Low)
            },
            bySource,
            topFindings = ordered.Take(10).Select(f => new
            {
                id = f.Id,
                source = f.Source,
                risk = f.Risk,
                label = f.Label,
                createdAtUtc = f.CreatedAtUtc
            }),
            recommendations,
            generatedAtUtc = DateTime.UtcNow,
            note = "El puntaje solo cuenta los hallazgos que guardaste con etiqueta y que no marcaste como resueltos. No es una garantía de seguridad."
        });
    }

    // Lista de hallazgos (por defecto solo los no resueltos)
    [HttpGet("findings")]
    public async Task<IActionResult> List([FromQuery] bool includeResolved = false, CancellationToken ct = default)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        var query = _db.ExposureFindings.AsNoTracking().Where(f => f.UserId == uid);
        if (!includeResolved)
            query = query.Where(f => f.ResolvedAtUtc == null);

        var items = (await query.ToListAsync(ct))
            .OrderByDescending(f => RiskLevels.Rank(f.Risk))
            .ThenByDescending(f => f.CreatedAtUtc)
            .Select(f => new
            {
                id = f.Id,
                source = f.Source,
                risk = f.Risk,
                label = f.Label,
                createdAtUtc = f.CreatedAtUtc,
                resolvedAtUtc = f.ResolvedAtUtc
            })
            .ToList();

        return Ok(new { total = items.Count, items });
    }

    // Marca un hallazgo como resuelto (deja de contar en el puntaje)
    [HttpPost("findings/{id:guid}/resolve")]
    public async Task<IActionResult> Resolve(Guid id, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        var updated = await _db.ExposureFindings
            .Where(f => f.Id == id && f.UserId == uid && f.ResolvedAtUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.ResolvedAtUtc, (DateTime?)DateTime.UtcNow), ct);

        if (updated == 1)
        {
            await WriteAudit(uid, "FindingResolved");
            return Ok(new { message = "Hallazgo marcado como resuelto." });
        }

        var exists = await _db.ExposureFindings.AnyAsync(f => f.Id == id && f.UserId == uid, ct);
        return exists
            ? Conflict(new { message = "Ese hallazgo ya estaba resuelto." })
            : NotFound(new { message = "Hallazgo no encontrado." });
    }

    // Borra un hallazgo
    [HttpDelete("findings/{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        var deleted = await _db.ExposureFindings
            .Where(f => f.Id == id && f.UserId == uid)
            .ExecuteDeleteAsync(ct);

        if (deleted != 1)
            return NotFound(new { message = "Hallazgo no encontrado." });

        await WriteAudit(uid, "FindingDeleted");
        return Ok(new { message = "Hallazgo borrado." });
    }

    private Guid? GetCurrentUserId()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    // Solo se registra la acción, nunca el contenido de los hallazgos.
    private async Task WriteAudit(Guid userId, string action)
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
            Action = action,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}