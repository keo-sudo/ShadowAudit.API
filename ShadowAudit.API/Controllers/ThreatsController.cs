using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Data;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.API.Controllers;

public record ThreatUrlRequest(
    [Required(ErrorMessage = "La dirección es obligatoria.")]
    [StringLength(2048, MinimumLength = 4, ErrorMessage = "La dirección debe tener entre 4 y 2048 caracteres.")]
    string Url,

    // Opcional: si lo mandas, el resultado se guarda como hallazgo para el reporte
    // (solo el riesgo y esta etiqueta; la dirección NO se guarda).
    [StringLength(100, ErrorMessage = "La etiqueta no puede pasar de 100 caracteres.")]
    string? Label = null);

[ApiController]
[Authorize]
[Route("api/threats")]
public class ThreatsController : ControllerBase
{
    private static readonly Regex Sha256Regex = new("^[0-9a-fA-F]{64}$", RegexOptions.Compiled);

    private readonly VirusTotalService _vt;
    private readonly ShadowAuditDbContext _db;

    public ThreatsController(VirusTotalService vt, ShadowAuditDbContext db)
    {
        _vt = vt;
        _db = db;
    }

    [HttpPost("url")]
    public async Task<IActionResult> CheckUrl([FromBody] ThreatUrlRequest request, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var error = ValidateUrl(request.Url.Trim(), out var normalized, out var hasQuery);
        if (error is not null) return BadRequest(new { message = error });

        var labelError = FindingStore.ValidateLabel(
            request.Label, out var findingLabel,
            request.Url.Trim(), normalized, new Uri(normalized).DnsSafeHost);
        if (labelError is not null) return BadRequest(new { message = labelError });

        var report = await _vt.CheckUrlAsync(normalized, ct);
        var finding = await SaveFindingAsync(report, FindingSource.Url, findingLabel, userId.Value, ct);
        await WriteAudit(userId.Value, "ThreatCheckUrl");

        var note = hasQuery
            ? "La dirección tiene parámetros. VirusTotal puede hacer visibles para otros los enlaces que se analizan: evita enlaces con datos privados."
            : null;

        return BuildResponse(report, note, finding);
    }

    [HttpGet("file/{sha256}")]
    public async Task<IActionResult> CheckFile(string sha256, [FromQuery] string? label, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        if (!Sha256Regex.IsMatch(sha256))
            return BadRequest(new { message = "La huella debe ser un SHA-256: 64 caracteres hexadecimales." });

        var labelError = FindingStore.ValidateLabel(label, out var findingLabel, sha256);
        if (labelError is not null) return BadRequest(new { message = labelError });

        var report = await _vt.CheckFileAsync(sha256, ct);
        var finding = await SaveFindingAsync(report, FindingSource.File, findingLabel, userId.Value, ct);
        await WriteAudit(userId.Value, "ThreatCheckFile");

        return BuildResponse(report, null, finding);
    }

    // Guarda el hallazgo solo si el usuario mandó etiqueta y VirusTotal dio un resultado.
    private async Task<FindingSaveResult?> SaveFindingAsync(
        VtReport report, string source, string? findingLabel, Guid userId, CancellationToken ct)
    {
        if (findingLabel is null) return null;

        if (report.Status != VtStatus.Found)
        {
            return new FindingSaveResult(false, null, null,
                "Todavía no hay un resultado de VirusTotal para guardar. Vuelve a consultar con la etiqueta cuando termine el análisis.");
        }

        var (risk, _) = Assess(report.Stats!);
        return await FindingStore.SaveAsync(
            _db, userId, source, RiskNormalizer.FromText(risk), findingLabel, ct);
    }

    private IActionResult BuildResponse(VtReport report, string? note, FindingSaveResult? finding)
    {
        switch (report.Status)
        {
            case VtStatus.Found:
                {
                    var stats = report.Stats!;
                    var (risk, verdict) = Assess(stats);

                    return Ok(new
                    {
                        risk,
                        verdict,
                        stats = new
                        {
                            malicious = stats.Malicious,
                            suspicious = stats.Suspicious,
                            harmless = stats.Harmless,
                            undetected = stats.Undetected,
                            enginesAnalyzed = stats.Total
                        },
                        flaggedBy = report.FlaggedBy,
                        lastAnalysisUtc = report.LastAnalysisUtc,
                        fileType = report.TypeDescription,
                        size = report.Size,
                        note,
                        finding
                    });
                }

            case VtStatus.Submitted:
                return Accepted(new
                {
                    status = "analyzing",
                    message = "VirusTotal está analizando este elemento. Vuelve a consultar en un minuto.",
                    note,
                    finding
                });

            case VtStatus.NotFound:
                return NotFound(new
                {
                    message = "VirusTotal no conoce este archivo. Esto NO significa que sea seguro.",
                    finding
                });

            case VtStatus.RateLimited:
                Response.Headers.RetryAfter = "60";
                return StatusCode(StatusCodes.Status429TooManyRequests, new
                {
                    message = "Se agotó la cuota de consultas a VirusTotal. Intenta más tarde."
                });

            case VtStatus.NotConfigured:
                return StatusCode(StatusCodes.Status503ServiceUnavailable, new
                {
                    message = "El servicio de amenazas no está configurado."
                });

            default:
                return StatusCode(StatusCodes.Status503ServiceUnavailable, new
                {
                    message = "No se pudo consultar VirusTotal. Intenta de nuevo en unos minutos."
                });
        }
    }

    private static (string Risk, string Verdict) Assess(VtStats stats)
    {
        if (stats.Malicious >= 3)
            return ("alto", "Peligroso: varios motores de seguridad lo marcan como malicioso. No lo abras.");

        if (stats.Malicious >= 1 || stats.Suspicious >= 1)
            return ("medio", "Sospechoso: algunos motores lo marcan. Puede ser un falso positivo, pero conviene no abrirlo hasta confirmarlo.");

        return ("sin_detecciones",
            "Ningún motor lo marcó como peligroso. Esto NO garantiza que sea seguro: algo muy reciente puede no estar marcado todavía.");
    }

    private static string? ValidateUrl(string raw, out string normalized, out bool hasQuery)
    {
        normalized = string.Empty;
        hasQuery = false;

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return "Escribe la dirección completa, empezando con http:// o https://.";

        if (!string.IsNullOrEmpty(uri.UserInfo))
            return "La dirección no debe incluir usuario ni contraseña.";

        if (IsInternalHost(uri.DnsSafeHost))
            return "No se pueden analizar direcciones internas o locales.";

        // Sin el fragmento (#...), que VirusTotal no usa
        normalized = uri.GetLeftPart(UriPartial.Query);
        hasQuery = !string.IsNullOrEmpty(uri.Query);
        return null;
    }

    private static bool IsInternalHost(string host)
    {
        host = host.TrimEnd('.').ToLowerInvariant();

        if (host == "localhost" || host.EndsWith(".localhost") || host.EndsWith(".local") ||
            host.EndsWith(".internal") || host.EndsWith(".lan"))
            return true;

        if (IPAddress.TryParse(host, out var ip))
        {
            if (IPAddress.IsLoopback(ip)) return true;

            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                var b = ip.GetAddressBytes();
                return b[0] == 0 || b[0] == 10 || b[0] == 127
                       || (b[0] == 169 && b[1] == 254)
                       || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                       || (b[0] == 192 && b[1] == 168);
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal;

            return false;
        }

        // Nombres sin punto (como "servidor") son de redes internas
        return !host.Contains('.');
    }

    private Guid? GetCurrentUserId()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    // Solo se registra que hubo una consulta. La dirección y el archivo NO se guardan.
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