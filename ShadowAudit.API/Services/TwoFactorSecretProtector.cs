using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace ShadowAudit.API.Services;

public class TwoFactorSecretProtector
{
    private readonly IDataProtector _protector;

    public TwoFactorSecretProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("ShadowAudit.TwoFactorSecret.v1");
    }

    public string Protect(string secret) => _protector.Protect(secret);

    // Devuelve null si no hay secreto o si no se puede descifrar
    // (por ejemplo, si se perdió la clave de cifrado).
    public string? Unprotect(string? protectedSecret)
    {
        if (string.IsNullOrEmpty(protectedSecret)) return null;

        try
        {
            return _protector.Unprotect(protectedSecret);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}