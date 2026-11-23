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

public record AddSiteRequest(
    [Required(ErrorMessage = "El dominio es obligatorio.")]
    [StringLength(300, ErrorMessage = "El dominio es demasiado largo.")]
    string Host);

[ApiController]
[Authorize]
[Route("api/sites")]
public class SitesController : ControllerBase
{
    private const int MaxSites = 5;
    private static readonly TimeSpan VerificationValidity = TimeSpan.FromDays(30);

    private readonly ShadowAuditDbContext _db;
    private readonly OwnershipVerifier _verifier;
    private readonly WebScanner _scanner;

    public SitesController(ShadowAuditDbContext db, OwnershipVerifier verifier, WebScanner scanner)
    {
        _db = db;
        _verifier = verifier;
        _scanner = scanner;
    }

    private static bool IsVerified(Site s) =>
        s.VerifiedAtUtc is { } v && DateTime.UtcNow - v < VerificationValidity;

    private static object Instructions(Site s) => new
    {
        dns = new
        {
            type = "TXT",
            name = OwnershipVerifier.DnsName(s.Host),
            value = OwnershipVerifier.DnsValue(s.VerificationToken)
        },
        file = new
        {
            url = OwnershipVerifier.FileUrl(s.Host),
            content = s.VerificationToken
        }
    };

    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        var sites = await _db.Sites.AsNoTracking()
            .Where(s => s.UserId == uid)
            .OrderBy(s => s.CreatedAtUtc)
            .ToListAsync(ct);

        return Ok(new
        {
            total = sites.Count,
            items = sites.Select(s => new
            {
                id = s.Id,
                host = s.Host,
                verified = IsVerified(s),
                verifiedAtUtc = s.VerifiedAtUtc,
                lastScanAtUtc = s.LastScanAtUtc,
                createdAtUtc = s.CreatedAtUtc
            })
        });
    }

    [HttpPost]
    public async Task<IActionResult> Add([FromBody] AddSiteRequest request, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        var error = HostValidator.Validate(request.Host, out var host);
        if (error is not null) return BadRequest(new { message = error });

        var count = await _db.Sites.CountAsync(s => s.UserId == uid, ct);
        if (count >= MaxSites)
            return Conflict(new { message = $"Llegaste al límite de {MaxSites} sitios. Borra alguno para agregar otro." });

        if (await _db.Sites.AnyAsync(s => s.UserId == uid && s.Host == host, ct))
            return Conflict(new { message = "Ese sitio ya está registrado." });

        var site = new Site { UserId = uid, Host = host, VerificationToken = OwnershipVerifier.NewToken() };
        _db.Sites.Add(site);

        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            return Conflict(new { message = "Ese sitio ya está registrado." });
        }

        await WriteAudit(uid, "SiteAdd");

        return Ok(new
        {
            id = site.Id,
            host = site.Host,
            verified = false,
            message = "Sitio registrado. Para escanearlo debes demostrar que es tuyo: crea el registro DNS TXT o sube el archivo indicado y luego llama a /verify.",
            verification = Instructions(site)
        });
    }

    [HttpPost("{id:guid}/verify")]
    [SiteRateLimit("sitesverify", 10, 10)]
    public async Task<IActionResult> Verify(Guid id, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        var site = await _db.Sites.FirstOrDefaultAsync(s => s.Id == id && s.UserId == uid, ct);
        if (site is null) return NotFound(new { message = "Sitio no encontrado." });

        var result = await _verifier.VerifyAsync(site.Host, site.VerificationToken, ct);

        if (!result.Verified)
        {
            await WriteAudit(uid, "SiteVerifyFailed");
            return BadRequest(new
            {
                verified = false,
                message = "No se pudo verificar. Revisa que el registro DNS o el archivo estén publicados (el DNS puede tardar en propagarse).",
                verification = Instructions(site)
            });
        }

        site.VerifiedAtUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
        await WriteAudit(uid, "SiteVerify");

        return Ok(new
        {
            verified = true,
            method = result.Method,
            validDays = (int)VerificationValidity.TotalDays,
            message = "Sitio verificado. Ya puedes escanearlo durante 30 días."
        });
    }

    [HttpPost("{id:guid}/scan")]
    [SiteRateLimit("scan", 3, 60)]
    public async Task<IActionResult> Scan(Guid id, [FromQuery] string? label, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        var site = await _db.Sites.FirstOrDefaultAsync(s => s.Id == id && s.UserId == uid, ct);
        if (site is null) return NotFound(new { message = "Sitio no encontrado." });

        if (!IsVerified(site))
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                message = "Solo se pueden escanear sitios verificados (la verificación dura 30 días). Llama primero a /verify."
            });

        // La etiqueta no puede contener el dominio: se valida ANTES de escanear.
        var labelError = FindingStore.ValidateLabel(label, out var findingLabel, site.Host);
        if (labelError is not null) return BadRequest(new { message = labelError });

        var report = await _scanner.ScanAsync(site.Host, ct);

        site.LastScanAtUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
        await WriteAudit(uid, "SiteScan");

        FindingSaveResult? finding = null;
        if (findingLabel is not null)
            finding = await FindingStore.SaveAsync(_db, uid, FindingSource.Web, report.Risk, findingLabel, ct);

        var summary = report.Failed == 0
            ? "No se encontraron fallas en las revisiones pasivas."
            : $"Se encontraron {report.Failed} falla(s). Riesgo: {report.Risk}.";

        return Ok(new
        {
            host = report.Host,
            risk = report.Risk,
            failed = report.Failed,
            passed = report.Passed,
            summary,
            checks = report.Checks,
            note = "Es un escaneo pasivo y liviano (HTTPS, certificado, cabeceras, cookies y archivos expuestos comunes). No reemplaza una auditoría completa. El resultado del escaneo no se guarda.",
            finding
        });
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();
        var uid = userId.Value;

        var deleted = await _db.Sites
            .Where(s => s.Id == id && s.UserId == uid)
            .ExecuteDeleteAsync(ct);

        if (deleted != 1) return NotFound(new { message = "Sitio no encontrado." });

        await WriteAudit(uid, "SiteDelete");
        return Ok(new { message = "Sitio borrado." });
    }

    private Guid? GetCurrentUserId()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    // Solo se registra la acción, nunca el dominio.
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