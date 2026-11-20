using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Data;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.API.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    // Hash de relleno: se verifica cuando el usuario no existe, para que el
    // tiempo de respuesta sea parecido al de un usuario real.
    private static readonly string DummyHash =
        BCrypt.Net.BCrypt.HashPassword("relleno-para-igualar-tiempos");

    // Lista corta de contraseñas muy comunes que cumplirían la política.
    // La revisión completa contra filtraciones reales está en el módulo de contraseñas.
    private static readonly HashSet<string> CommonPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "Password1234", "Password12345", "Password123!", "Contrasena123",
        "Contrasena1234", "Qwerty123456", "Admin1234567", "Welcome12345",
        "Peru20262026", "Abcdefghij12", "Changeme1234", "Letmein123456"
    };

    private readonly ShadowAuditDbContext _db;
    private readonly SessionService _sessions;
    private readonly TwoFactorSecretProtector _twoFactor;

    public AuthController(ShadowAuditDbContext db, SessionService sessions, TwoFactorSecretProtector twoFactor)
    {
        _db = db;
        _sessions = sessions;
        _twoFactor = twoFactor;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var username = request.Username.Trim();

        var passwordError = ValidatePassword(request.Password, username, email);
        if (passwordError is not null)
            return BadRequest(new { message = passwordError });

        var exists = await _db.Users.AnyAsync(u => u.Email == email || u.Username == username);
        if (exists)
            return Conflict(new { message = "El usuario o el email ya están registrados." });

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = username,
            Email = email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            CreatedAt = DateTime.UtcNow
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        await WriteAudit(user.Id, email, "Register");

        return Ok(new { message = "Usuario registrado correctamente." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);

        // Usuario inexistente: se gasta el mismo tiempo de BCrypt y se responde genérico.
        if (user is null)
        {
            BCrypt.Net.BCrypt.Verify(request.Password, DummyHash);
            await WriteAudit(null, email, "LoginFailed");
            return Unauthorized(new { message = "Credenciales inválidas." });
        }

        // Cuenta bloqueada: se responde igual que una clave incorrecta,
        // pero el audit log guarda el motivo real.
        if (user.IsLocked)
        {
            BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash);
            await WriteAudit(user.Id, email, "LoginBlocked");
            return Unauthorized(new { message = "Credenciales inválidas." });
        }

        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            await RegisterFailure(user);
            await WriteAudit(user.Id, email, "LoginFailed");
            return Unauthorized(new { message = "Credenciales inválidas." });
        }

        var usedRecoveryCode = false;

        if (user.TwoFactorEnabled)
        {
            var result = await TwoFactorVerifier.VerifyAsync(_db, _twoFactor, user, request.TwoFactorCode);

            if (result == TwoFactorResult.Missing)
            {
                await WriteAudit(user.Id, email, "TwoFactorRequired");
                return Unauthorized(new { message = "Se requiere el código 2FA.", twoFactorRequired = true });
            }

            if (result == TwoFactorResult.Invalid)
            {
                await RegisterFailure(user);
                await WriteAudit(user.Id, email, "LoginFailed2FA");
                return Unauthorized(new { message = "Código 2FA inválido.", twoFactorRequired = true });
            }

            usedRecoveryCode = result == TwoFactorResult.ValidRecoveryCode;
        }

        user.ClearFailedAttempts();
        await _db.SaveChangesAsync();

        await WriteAudit(user.Id, email, "LoginSuccess");
        if (usedRecoveryCode)
            await WriteAudit(user.Id, email, "RecoveryCodeUsed");

        return Ok(await _sessions.CreateSessionAsync(user));
    }

    // Cambia un refresh token por un par nuevo (token de acceso y refresh token)
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        var outcome = await _sessions.RefreshAsync(request.RefreshToken.Trim());

        if (outcome.Status == RefreshStatus.Ok)
            return Ok(outcome.Response);

        if (outcome.Status == RefreshStatus.ReuseDetected)
            await WriteAudit(outcome.UserId, outcome.Email ?? string.Empty, "RefreshTokenReuse");

        return Unauthorized(new { message = "Sesión inválida o expirada. Inicia sesión de nuevo." });
    }

    // Cierra la sesión actual
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var userId = GetCurrentUserId();
        var sessionId = GetSessionId();
        if (userId is null || sessionId is null) return Unauthorized();

        await _sessions.RevokeSessionAsync(sessionId.Value);
        await WriteAuditForUser(userId.Value, "Logout");

        return Ok(new { message = "Sesión cerrada." });
    }

    // Cierra todas las sesiones de la cuenta
    [Authorize]
    [HttpPost("logout-all")]
    public async Task<IActionResult> LogoutAll()
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        await _sessions.RevokeAllAsync(userId.Value);
        await WriteAuditForUser(userId.Value, "LogoutAll");

        return Ok(new { message = "Todas las sesiones fueron cerradas." });
    }

    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user is null) return Unauthorized();

        if (user.IsLocked)
        {
            await WriteAudit(user.Id, user.Email, "ChangePasswordBlocked");
            return Unauthorized(new { message = "Credenciales inválidas." });
        }

        if (!BCrypt.Net.BCrypt.Verify(request.CurrentPassword, user.PasswordHash))
        {
            await RegisterFailure(user);
            await WriteAudit(user.Id, user.Email, "ChangePasswordFailed");
            return Unauthorized(new { message = "Credenciales inválidas." });
        }

        // Se valida la contraseña nueva antes del 2FA, para no gastar un código si es inválida
        var passwordError = ValidatePassword(request.NewPassword, user.Username, user.Email);
        if (passwordError is not null)
            return BadRequest(new { message = passwordError });

        if (BCrypt.Net.BCrypt.Verify(request.NewPassword, user.PasswordHash))
            return BadRequest(new { message = "La contraseña nueva debe ser distinta de la actual." });

        if (user.TwoFactorEnabled)
        {
            var result = await TwoFactorVerifier.VerifyAsync(_db, _twoFactor, user, request.TwoFactorCode);

            if (result == TwoFactorResult.Missing)
                return Unauthorized(new { message = "Se requiere el código 2FA.", twoFactorRequired = true });

            if (result == TwoFactorResult.Invalid)
            {
                await RegisterFailure(user);
                await WriteAudit(user.Id, user.Email, "ChangePasswordFailed2FA");
                return Unauthorized(new { message = "Código 2FA inválido.", twoFactorRequired = true });
            }
        }

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
        user.ClearFailedAttempts();
        await _db.SaveChangesAsync();

        // Se cierran las demás sesiones: si alguien más tenía la contraseña vieja, queda fuera
        await _sessions.RevokeAllAsync(user.Id, GetSessionId());

        await WriteAudit(user.Id, user.Email, "PasswordChanged");

        return Ok(new { message = "Contraseña actualizada. Las demás sesiones fueron cerradas." });
    }

    private async Task RegisterFailure(User user)
    {
        user.RegisterFailedAttempt();
        await _db.SaveChangesAsync();
    }

    private static string? ValidatePassword(string password, string username, string email)
    {
        if (password.Length < 12)
            return "La contraseña debe tener al menos 12 caracteres.";

        // BCrypt solo usa los primeros 72 bytes de la contraseña.
        if (Encoding.UTF8.GetByteCount(password) > 72)
            return "La contraseña es demasiado larga (máximo 72 bytes).";

        if (!password.Any(char.IsUpper) || !password.Any(char.IsLower) || !password.Any(char.IsDigit))
            return "La contraseña debe incluir mayúscula, minúscula y número.";

        if (CommonPasswords.Contains(password))
            return "Esa contraseña es demasiado común. Elige otra.";

        if (username.Length >= 3 && password.Contains(username, StringComparison.OrdinalIgnoreCase))
            return "La contraseña no debe contener tu nombre de usuario.";

        var emailLocal = email.Split('@')[0];
        if (emailLocal.Length >= 3 && password.Contains(emailLocal, StringComparison.OrdinalIgnoreCase))
            return "La contraseña no debe contener tu email.";

        return null;
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId);
        if (user is null) return Unauthorized();

        return Ok(new { userId = user.Id, user.Username, user.Email, user.CreatedAt });
    }

    [Authorize]
    [HttpGet("audit-log")]
    public async Task<IActionResult> GetAuditLog()
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var logs = await _db.AuditLogs
            .AsNoTracking()
            .Where(a => a.UserId == userId)
            .OrderByDescending(a => a.CreatedAt)
            .Take(100)
            .Select(a => new { a.Action, a.IpAddress, a.UserAgent, a.CreatedAt })
            .ToListAsync();

        return Ok(logs);
    }

    private Guid? GetCurrentUserId()
    {
        var value = User.FindFirstValue(ClaimTypes.NameIdentifier)
                    ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return Guid.TryParse(value, out var id) ? id : null;
    }

    private Guid? GetSessionId() =>
        Guid.TryParse(User.FindFirstValue("session_id"), out var id) ? id : null;

    private async Task WriteAuditForUser(Guid userId, string action)
    {
        var email = await _db.Users.AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => u.Email)
            .FirstOrDefaultAsync() ?? string.Empty;

        await WriteAudit(userId, email, action);
    }

    private async Task WriteAudit(Guid? userId, string email, string action)
    {
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