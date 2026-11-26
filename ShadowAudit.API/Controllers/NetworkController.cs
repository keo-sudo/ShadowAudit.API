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

public record NetworkRequest(
    [Required(ErrorMessage = "Pega la salida del comando.")]
    [StringLength(20000, MinimumLength = 10, ErrorMessage = "La salida debe tener entre 10 y 20000 caracteres.")]
    string Output,

    [StringLength(100, ErrorMessage = "La etiqueta no puede pasar de 100 caracteres.")]
    string? Label = null);

[ApiController]
[Authorize]
[Route("api/network")]
public class NetworkController : ControllerBase
{
    private readonly ShadowAuditDbContext _db;

    public NetworkController(ShadowAuditDbContext db) => _db = db;

    [HttpPost("wifi")]
    [RequestSizeLimit(65536)]
    [SiteRateLimit("network", 20, 60)]
    public async Task<IActionResult> Wifi([FromBody] NetworkRequest request, CancellationToken ct)
    {
        var audit = NetworkAudit.Wifi(request.Output);
        if (audit is null)
            return BadRequest(new { message = "No encontré la línea de autenticación. Pega la salida completa de: netsh wlan show interfaces" });

        return await Finish(request.Label, audit.Risk, new { risk = audit.Risk, security = audit.Security, advice = audit.Advice }, ct);
    }

    [HttpPost("ports")]
    [RequestSizeLimit(65536)]
    [SiteRateLimit("network", 20, 60)]
    public async Task<IActionResult> Ports([FromBody] NetworkRequest request, CancellationToken ct)
    {
        var audit = NetworkAudit.Ports(request.Output);
        return await Finish(request.Label, audit.Risk, new { risk = audit.Risk, riskyPorts = audit.RiskyPorts, advice = audit.Advice }, ct);
    }

    private async Task<IActionResult> Finish(string? rawLabel, string risk, object result, CancellationToken ct)
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!Guid.TryParse(value, out var uid)) return Unauthorized();

        var labelError = FindingStore.ValidateLabel(rawLabel, out var label);
        if (labelError is not null) return BadRequest(new { message = labelError });

        await WriteAudit(uid);

        FindingSaveResult? finding = null;
        if (label is not null)
            finding = await FindingStore.SaveAsync(_db, uid, FindingSource.Network, risk, label, ct);

        return Ok(new { result, note = "El texto que pegaste no se guarda.", finding });
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
            Action = "NetworkCheck",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}