using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Data;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public record FindingSaveResult(bool Saved, Guid? Id, string? Risk, string? Reason);

public static class FindingStore
{
    public const int MaxLabelLength = 100;
    public const int MaxPerUser = 500;

    // Valida la etiqueta opcional. Devuelve un mensaje de error, o null si está bien.
    // sensitiveValues = datos que se consultaron y que NO pueden aparecer en la etiqueta.
    public static string? ValidateLabel(string? raw, out string? label, params string?[] sensitiveValues)
    {
        label = null;
        if (string.IsNullOrWhiteSpace(raw)) return null;

        var clean = raw.Trim();

        if (clean.Length > MaxLabelLength)
            return $"La etiqueta no puede pasar de {MaxLabelLength} caracteres.";

        if (clean.Any(char.IsControl))
            return "La etiqueta no puede tener caracteres de control.";

        foreach (var value in sensitiveValues)
        {
            if (!string.IsNullOrEmpty(value) && value.Length >= 4 &&
                clean.Contains(value, StringComparison.OrdinalIgnoreCase))
            {
                return "La etiqueta no debe contener el dato consultado. Usa un nombre descriptivo, por ejemplo \"correo del banco\".";
            }
        }

        label = clean;
        return null;
    }

    public static async Task<FindingSaveResult> SaveAsync(
        ShadowAuditDbContext db, Guid userId, string source, string risk, string label, CancellationToken ct)
    {
        var count = await db.ExposureFindings.CountAsync(f => f.UserId == userId, ct);
        if (count >= MaxPerUser)
        {
            return new FindingSaveResult(false, null, null,
                $"Llegaste al límite de {MaxPerUser} hallazgos guardados. Borra algunos y vuelve a intentarlo.");
        }

        var finding = new ExposureFinding
        {
            UserId = userId,
            Source = source,
            Risk = risk,
            Label = label
        };

        db.ExposureFindings.Add(finding);
        await db.SaveChangesAsync(ct);

        return new FindingSaveResult(true, finding.Id, finding.Risk, null);
    }
}