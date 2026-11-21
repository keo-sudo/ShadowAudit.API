namespace ShadowAudit.API.Services;

public static class RiskLevels
{
    public const string Low = "bajo";
    public const string Medium = "medio";
    public const string High = "alto";

    public static int Rank(string risk) => risk switch
    {
        High => 3,
        Medium => 2,
        _ => 1
    };
}

// Cada módulo habla un idioma de riesgo distinto. Aquí se unifica todo en bajo / medio / alto.
public static class RiskNormalizer
{
    // VirusTotal (alto / medio / sin_detecciones), AbuseIPDB y correos (alto / medio / bajo)
    public static string FromText(string? risk)
    {
        var value = (risk ?? string.Empty).Trim().ToLowerInvariant();

        return value switch
        {
            "alto" or "high" or "critico" or "crítico" => RiskLevels.High,
            "medio" or "medium" => RiskLevels.Medium,
            _ => RiskLevels.Low
        };
    }

    // Contraseñas: puntaje 0 a 4. Una contraseña filtrada siempre es riesgo alto.
    public static string FromPassword(int score, bool? breached)
    {
        if (breached == true || score <= 1) return RiskLevels.High;
        if (score == 2) return RiskLevels.Medium;
        return RiskLevels.Low;
    }
}