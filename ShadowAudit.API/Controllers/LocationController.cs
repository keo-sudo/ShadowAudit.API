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

public class ExifUploadRequest
{
    [Required(ErrorMessage = "Sube una imagen.")]
    public IFormFile? File { get; set; }

    [StringLength(100, ErrorMessage = "La etiqueta no puede pasar de 100 caracteres.")]
    public string? Label { get; set; }
}

[ApiController]
[Authorize]
[Route("api/location")]
public class LocationController : ControllerBase
{
    private const int MaxBytes = 10_485_760;

    private readonly ShadowAuditDbContext _db;

    public LocationController(ShadowAuditDbContext db) => _db = db;

    [HttpPost("exif")]
    [RequestSizeLimit(MaxBytes)]
    [SiteRateLimit("location", 20, 60)]
    public async Task<IActionResult> Exif([FromForm] ExifUploadRequest request, CancellationToken ct)
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!Guid.TryParse(value, out var uid)) return Unauthorized();

        var labelError = FindingStore.ValidateLabel(request.Label, out var label);
        if (labelError is not null) return BadRequest(new { message = labelError });

        var file = request.File;
        if (file is null || file.Length == 0) return BadRequest(new { message = "Sube una imagen." });
        if (file.Length > MaxBytes) return BadRequest(new { message = "La imagen no puede pasar de 10 MB." });

        await using var ms = new MemoryStream();
        await file.CopyToAsync(ms, ct);
        ms.Position = 0;

        if (!ExifAudit.TryAnalyze(ms, out var result) || result is null)
            return BadRequest(new { message = "El archivo no es una imagen compatible (JPG, PNG, HEIC, TIFF o WebP)." });

        await WriteAudit(uid);

        FindingSaveResult? finding = null;
        if (label is not null)
            finding = await FindingStore.SaveAsync(_db, uid, FindingSource.Location, result.Risk, label, ct);

        return Ok(new
        {
            risk = result.Risk,
            hasGps = result.HasGps,
            latitude = result.Latitude,
            longitude = result.Longitude,
            mapUrl = result.MapUrl,
            device = result.Device,
            takenAt = result.TakenAt,
            findings = result.Findings,
            note = "Usa solo fotos tuyas. La imagen y las coordenadas no se guardan.",
            finding
        });
    }

    // Solo se registra que hubo una consulta, nunca la imagen ni los datos.
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
            Action = "LocationCheck",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}