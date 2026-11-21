using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Sockets;
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
[Route("api/threats")]
public class IpThreatsController : ControllerBase
{
    private readonly AbuseIpDbService _abuse;
    private readonly ShadowAuditDbContext _db;

    public IpThreatsController(AbuseIpDbService abuse, ShadowAuditDbContext db)
    {
        _abuse = abuse;
        _db = db;
    }

    [HttpGet("ip/{ip}")]
    public async Task<IActionResult> CheckIp(string ip, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        if (ip.Length > 45 || !IPAddress.TryParse(ip, out var address))
            return BadRequest(new { message = "Escribe una dirección IP válida (IPv4 o IPv6)." });

        if (!IsPublic(address))
            return BadRequest(new { message = "Solo se pueden consultar IPs públicas de internet, no locales, privadas, de documentación ni reservadas." });

        var report = await _abuse.CheckIpAsync(address.ToString(), ct);
        await WriteAudit(userId.Value);

        switch (report.Status)
        {
            case AbuseStatus.Found:
                {
                    var (risk, verdict) = Assess(report);

                    return Ok(new
                    {
                        ip = address.ToString(),
                        risk,
                        verdict,
                        abuseConfidenceScore = report.Score,
                        totalReports = report.TotalReports,
                        distinctReporters = report.DistinctUsers,
                        lastReportedUtc = report.LastReportedUtc,
                        country = report.CountryCode,
                        usageType = report.UsageType,
                        isp = report.Isp,
                        domain = report.Domain,
                        isTor = report.IsTor,
                        isWhitelisted = report.IsWhitelisted,
                        window = "últimos 90 días"
                    });
                }

            case AbuseStatus.RateLimited:
                Response.Headers.RetryAfter = "60";
                return StatusCode(StatusCodes.Status429TooManyRequests, new
                {
                    message = "Se agotó la cuota de consultas a AbuseIPDB. Intenta más tarde."
                });

            case AbuseStatus.NotConfigured:
                return StatusCode(StatusCodes.Status503ServiceUnavailable, new
                {
                    message = "El servicio de reputación de IPs no está configurado."
                });

            default:
                return StatusCode(StatusCodes.Status503ServiceUnavailable, new
                {
                    message = "No se pudo consultar AbuseIPDB. Esto NO significa que la IP sea segura."
                });
        }
    }

    private static (string Risk, string Verdict) Assess(AbuseReport r)
    {
        // Servicios legítimos conocidos (por ejemplo, DNS públicos): los reportes no cuentan.
        if (r.IsWhitelisted)
            return ("bajo",
                "Esta IP está en la lista blanca de AbuseIPDB (servicio legítimo conocido). Que tenga reportes no la hace peligrosa.");

        if (r.Score >= 75)
            return ("alto",
                "Muy probablemente abusiva: muchos usuarios la reportaron por ataques o spam. No confíes en ella.");

        if (r.Score >= 25)
            return ("medio",
                "Tiene reportes de abuso. Trátala con cautela y revisa de dónde viene la conexión.");

        return ("bajo",
            "AbuseIPDB no la considera abusiva. Esto NO garantiza que sea segura: una IP nueva puede no tener reportes todavía.");
    }

    // Solo IPs de internet: se descartan locales, privadas, compartidas, de documentación y reservadas
    private static bool IsPublic(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return false;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return !(b[0] == 0 || b[0] == 10 || b[0] == 127
                     || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)             // compartida (CGNAT)
                     || (b[0] == 169 && b[1] == 254)                           // enlace local
                     || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                     || (b[0] == 192 && b[1] == 168)
                     || (b[0] == 192 && b[1] == 0 && b[2] == 0)                // protocolos IETF
                     || (b[0] == 192 && b[1] == 0 && b[2] == 2)                // documentación (TEST-NET-1)
                     || (b[0] == 198 && (b[1] == 18 || b[1] == 19))            // pruebas de rendimiento
                     || (b[0] == 198 && b[1] == 51 && b[2] == 100)             // documentación (TEST-NET-2)
                     || (b[0] == 203 && b[1] == 0 && b[2] == 113)              // documentación (TEST-NET-3)
                     || b[0] >= 224);                                          // multidifusión y reservadas
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // IPv4 escrita como IPv6 (::ffff:a.b.c.d): se evalúa como IPv4
            if (ip.IsIPv4MappedToIPv6) return IsPublic(ip.MapToIPv4());

            var b = ip.GetAddressBytes();
            var documentation = b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8; // 2001:db8::/32

            return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal
                     || ip.IsIPv6Multicast || ip.Equals(IPAddress.IPv6Any) || documentation);
        }

        return false;
    }

    private Guid? GetCurrentUserId()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    // Solo se registra que hubo una consulta. La IP consultada NO se guarda.
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
            Action = "ThreatCheckIp",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}