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

public record PasswordCheckRequest(
    [Required(ErrorMessage = "La contraseña es obligatoria.")]
    [StringLength(128, MinimumLength = 1, ErrorMessage = "La contraseña debe tener entre 1 y 128 caracteres.")]
    string Password);

[ApiController]
[Authorize]
[Route("api/passwords")]
public class PasswordsController : ControllerBase
{
    private readonly PasswordCheckService _checker;
    private readonly ShadowAuditDbContext _db;

    public PasswordsController(PasswordCheckService checker, ShadowAuditDbContext db)
    {
        _checker = checker;
        _db = db;
    }

    [HttpPost("check")]
    public async Task<IActionResult> Check([FromBody] PasswordCheckRequest request, CancellationToken ct)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var breach = await _checker.CheckBreachAsync(request.Password, ct);
        var strength = PasswordCheckService.EvaluateStrength(request.Password);

        await WriteAudit(userId.Value);

        // Una contraseña filtrada nunca puede tener buena nota, aunque parezca compleja.
        var score = strength.Score;
        var label = strength.Label;
        var issues = new List<string>(strength.Issues);

        if (breach.Breached == true)
        {
            score = 0;
            label = "Comprometida";
            issues.Insert(0, "Aparece en filtraciones de datos reales.");
        }

        string verdict;
        var recommendations = new List<string>();

        if (breach.Breached == true)
        {
            verdict = "No la uses. Esta contraseña apareció en filtraciones de datos reales.";
            recommendations.Add("Deja de usarla en todas tus cuentas, no solo en una.");
            recommendations.Add("Usa una contraseña distinta y única para cada sitio.");
        }
        else if (breach.Breached is null)
        {
            verdict = "No se pudo verificar contra filtraciones. Esto NO significa que sea segura.";
            recommendations.Add("Vuelve a intentarlo en unos minutos.");
        }
        else if (score <= 1)
        {
            verdict = "No aparece en filtraciones conocidas, pero es débil.";
        }
        else
        {
            verdict = "No aparece en filtraciones conocidas y su fortaleza es " + label.ToLowerInvariant() + ".";
        }

        if (score <= 2)
            recommendations.Add("Usa 14 o más caracteres, o una frase larga de varias palabras sin relación entre sí.");

        recommendations.Add("Un gestor de contraseñas te permite tener una clave larga y distinta en cada cuenta.");
        recommendations.Add("Activa la verificación en dos pasos en tus cuentas importantes.");

        return Ok(new
        {
            breached = breach.Breached,
            timesSeen = breach.TimesSeen,
            strength = new
            {
                score,
                label,
                estimatedBits = strength.EstimatedBits,
                issues
            },
            verdict,
            recommendations
        });
    }

    private Guid? GetCurrentUserId()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    // Solo se registra que hubo una consulta. La contraseña NUNCA se guarda.
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
            Action = "PasswordCheck",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}