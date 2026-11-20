using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using OtpNet;
using ShadowAudit.API.Data;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public enum TwoFactorResult { Missing, Invalid, ValidTotp, ValidRecoveryCode }

// Lógica común del segundo factor: código del celular o código de recuperación.
// No guarda cambios: quien la llama decide cuándo hacer SaveChanges.
public static class TwoFactorVerifier
{
    public const int RecoveryCodeCount = 10;

    // Sin letras ni números que se confundan (0/O, 1/I)
    private const string RecoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    public static async Task<TwoFactorResult> VerifyAsync(
        ShadowAuditDbContext db,
        TwoFactorSecretProtector protector,
        User user,
        string? rawCode)
    {
        var code = Normalize(rawCode);
        if (code.Length == 0) return TwoFactorResult.Missing;

        // Código de 6 dígitos del celular
        if (code.Length == 6 && code.All(char.IsDigit))
        {
            var secret = protector.Unprotect(user.TwoFactorSecret);
            if (secret is null) return TwoFactorResult.Invalid;

            var totp = new Totp(Base32Encoding.ToBytes(secret));
            if (totp.VerifyTotp(code, out long step, VerificationWindow.RfcSpecifiedNetworkDelay)
                && (user.TwoFactorLastUsedStep is null || step > user.TwoFactorLastUsedStep))
            {
                user.TwoFactorLastUsedStep = step;
                return TwoFactorResult.ValidTotp;
            }

            return TwoFactorResult.Invalid;
        }

        // Código de recuperación: se compara por su huella y solo sirve una vez
        var hash = Hash(code);
        var recovery = await db.RecoveryCodes.FirstOrDefaultAsync(r =>
            r.UserId == user.Id && r.CodeHash == hash && r.UsedAtUtc == null);

        if (recovery is null) return TwoFactorResult.Invalid;

        recovery.UsedAtUtc = DateTime.UtcNow;
        return TwoFactorResult.ValidRecoveryCode;
    }

    // Borra los códigos anteriores y crea 10 nuevos. Devuelve los códigos en claro,
    // que solo se muestran esta vez. Quien llama debe hacer SaveChanges.
    public static async Task<List<string>> ReplaceRecoveryCodesAsync(ShadowAuditDbContext db, Guid userId)
    {
        var old = await db.RecoveryCodes.Where(r => r.UserId == userId).ToListAsync();
        db.RecoveryCodes.RemoveRange(old);

        var plain = new List<string>();
        for (var i = 0; i < RecoveryCodeCount; i++)
        {
            var chars = new char[10];
            for (var j = 0; j < chars.Length; j++)
                chars[j] = RecoveryAlphabet[RandomNumberGenerator.GetInt32(RecoveryAlphabet.Length)];

            var raw = new string(chars);
            plain.Add($"{raw[..5]}-{raw[5..]}");

            db.RecoveryCodes.Add(new RecoveryCode { UserId = userId, CodeHash = Hash(raw) });
        }

        return plain;
    }

    public static async Task RemoveRecoveryCodesAsync(ShadowAuditDbContext db, Guid userId)
    {
        var old = await db.RecoveryCodes.Where(r => r.UserId == userId).ToListAsync();
        db.RecoveryCodes.RemoveRange(old);
    }

    // Quita espacios y guiones, y pasa a mayúsculas
    private static string Normalize(string? raw) =>
        new string((raw ?? string.Empty).Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

    private static string Hash(string normalized) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))).ToLowerInvariant();
}