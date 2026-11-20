using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Data;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public enum RefreshStatus { Ok, Invalid, ReuseDetected }

public record RefreshOutcome(
    RefreshStatus Status,
    AuthResponse? Response = null,
    Guid? UserId = null,
    string? Email = null);

// Sesiones con refresh tokens rotativos. Cada sesión es una "familia" de tokens.
public class SessionService
{
    private readonly ShadowAuditDbContext _db;
    private readonly JwtService _jwt;
    private readonly IConfiguration _config;

    public SessionService(ShadowAuditDbContext db, JwtService jwt, IConfiguration config)
    {
        _db = db;
        _jwt = jwt;
        _config = config;
    }

    private TimeSpan RefreshLifetime =>
        TimeSpan.FromDays(_config.GetValue<int?>("JwtSettings:RefreshTokenDays") ?? 7);

    // Sesión nueva: devuelve el token de acceso y el primer refresh token
    public Task<AuthResponse> CreateSessionAsync(User user) =>
        IssueAsync(user, Guid.NewGuid());

    // ¿La sesión sigue abierta? Se consulta en cada petición con token.
    public Task<bool> IsSessionActiveAsync(Guid sessionId) =>
        _db.RefreshTokens.AnyAsync(t =>
            t.FamilyId == sessionId && t.RevokedAtUtc == null && t.ExpiresAtUtc > DateTime.UtcNow);

    public async Task<RefreshOutcome> RefreshAsync(string rawToken)
    {
        var hash = Hash(rawToken);
        var token = await _db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == hash);
        if (token is null) return new RefreshOutcome(RefreshStatus.Invalid);

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == token.UserId);
        if (user is null) return new RefreshOutcome(RefreshStatus.Invalid);

        // Un token ya usado vuelve a presentarse: posible robo, se cierra toda la sesión
        if (token.UsedAtUtc is not null)
        {
            await RevokeSessionAsync(token.FamilyId);
            return new RefreshOutcome(RefreshStatus.ReuseDetected, UserId: user.Id, Email: user.Email);
        }

        if (token.RevokedAtUtc is not null || token.ExpiresAtUtc <= DateTime.UtcNow || user.IsLocked)
            return new RefreshOutcome(RefreshStatus.Invalid);

        // Se reclama de forma atómica: solo una petición puede usar este token
        var claimed = await _db.RefreshTokens
            .Where(t => t.Id == token.Id && t.UsedAtUtc == null && t.RevokedAtUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.UsedAtUtc, (DateTime?)DateTime.UtcNow));

        if (claimed != 1)
        {
            await RevokeSessionAsync(token.FamilyId);
            return new RefreshOutcome(RefreshStatus.ReuseDetected, UserId: user.Id, Email: user.Email);
        }

        var response = await IssueAsync(user, token.FamilyId);
        return new RefreshOutcome(RefreshStatus.Ok, response);
    }

    public Task<int> RevokeSessionAsync(Guid sessionId) =>
        _db.RefreshTokens
            .Where(t => t.FamilyId == sessionId && t.RevokedAtUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAtUtc, (DateTime?)DateTime.UtcNow));

    // Cierra todas las sesiones del usuario, salvo (opcionalmente) una
    public async Task<int> RevokeAllAsync(Guid userId, Guid? exceptSessionId = null)
    {
        var query = _db.RefreshTokens.Where(t => t.UserId == userId && t.RevokedAtUtc == null);

        if (exceptSessionId is Guid keep)
            query = query.Where(t => t.FamilyId != keep);

        return await query.ExecuteUpdateAsync(s =>
            s.SetProperty(t => t.RevokedAtUtc, (DateTime?)DateTime.UtcNow));
    }

    private async Task<AuthResponse> IssueAsync(User user, Guid sessionId)
    {
        var rawRefresh = Base64Url(RandomNumberGenerator.GetBytes(32));
        var refreshExpires = DateTime.UtcNow.Add(RefreshLifetime);

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            FamilyId = sessionId,
            TokenHash = Hash(rawRefresh),
            ExpiresAtUtc = refreshExpires
        });
        await _db.SaveChangesAsync();

        var access = _jwt.GenerateToken(user, sessionId);

        return new AuthResponse(
            access.Token, user.Username, user.Email, access.ExpiresAt, rawRefresh, refreshExpires);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}