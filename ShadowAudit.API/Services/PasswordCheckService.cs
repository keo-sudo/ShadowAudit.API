using System.Security.Cryptography;
using System.Text;

namespace ShadowAudit.API.Services;

// Breached: true/false si se pudo verificar, null si no se pudo consultar el servicio
public record BreachResult(bool? Breached, long TimesSeen);

public record StrengthResult(int Score, string Label, double EstimatedBits, List<string> Issues);

public class PasswordCheckService
{
    private readonly HttpClient _http;
    private readonly ILogger<PasswordCheckService> _logger;

    private static readonly string[] KeyboardRows =
    {
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"
    };

    public PasswordCheckService(HttpClient http, ILogger<PasswordCheckService> logger)
    {
        _http = http;
        _logger = logger;
    }

    // Consulta Have I Been Pwned con k-anonimato: solo salen los 5 primeros
    // caracteres de la huella SHA-1. La contraseña nunca sale del servidor.
    public async Task<BreachResult> CheckBreachAsync(string password, CancellationToken ct)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var prefix = hash[..5];
        var suffix = hash[5..];

        try
        {
            using var response = await _http.GetAsync($"range/{prefix}", ct);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Have I Been Pwned respondió {Status}", (int)response.StatusCode);
                return new BreachResult(null, 0);
            }

            var body = await response.Content.ReadAsStringAsync(ct);

            foreach (var line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Trim().Split(':');
                if (parts.Length != 2) continue;
                if (!parts[0].Equals(suffix, StringComparison.OrdinalIgnoreCase)) continue;

                // Con "Add-Padding" llegan filas falsas con conteo 0: se ignoran.
                if (long.TryParse(parts[1], out var count) && count > 0)
                    return new BreachResult(true, count);
            }

            return new BreachResult(false, 0);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            _logger.LogWarning("No se pudo consultar Have I Been Pwned: {Tipo}", ex.GetType().Name);
            return new BreachResult(null, 0);
        }
    }

    // Estimación propia y aproximada. No reemplaza a un gestor de contraseñas.
    public static StrengthResult EvaluateStrength(string password)
    {
        var issues = new List<string>();
        var length = password.Length;

        var hasLower = password.Any(char.IsLower);
        var hasUpper = password.Any(char.IsUpper);
        var hasDigit = password.Any(char.IsDigit);
        var hasSymbol = password.Any(c => !char.IsLetterOrDigit(c) && c < 128);
        var hasOther = password.Any(c => c >= 128);

        var pool = 0;
        if (hasLower) pool += 26;
        if (hasUpper) pool += 26;
        if (hasDigit) pool += 10;
        if (hasSymbol) pool += 33;
        if (hasOther) pool += 100;
        if (pool == 0) pool = 1;

        // Los caracteres repetidos aportan poco: se descuentan.
        var distinct = password.Distinct().Count();
        var effectiveLength = distinct + 0.3 * (length - distinct);
        var bits = effectiveLength * Math.Log2(pool);

        if (length < 12) issues.Add("Tiene menos de 12 caracteres.");
        if (!hasLower && !hasUpper) issues.Add("No tiene letras.");
        if (!hasDigit) issues.Add("No tiene números.");
        if (hasLower && !hasUpper) issues.Add("No tiene mayúsculas.");
        if (hasUpper && !hasLower) issues.Add("No tiene minúsculas.");
        if (!hasSymbol) issues.Add("No tiene símbolos.");

        if (HasRepeatedRun(password, 3))
            issues.Add("Repite el mismo carácter 3 o más veces seguidas.");

        if (HasSequence(password, 4))
        {
            issues.Add("Contiene una secuencia como 1234, abcd o qwerty.");
            bits *= 0.7;
        }

        var (score, label) = bits switch
        {
            < 28 => (0, "Muy débil"),
            < 36 => (1, "Débil"),
            < 60 => (2, "Aceptable"),
            < 80 => (3, "Fuerte"),
            _ => (4, "Muy fuerte")
        };

        return new StrengthResult(score, label, Math.Round(bits, 1), issues);
    }

    private static bool HasRepeatedRun(string text, int runLength)
    {
        var run = 1;
        for (var i = 1; i < text.Length; i++)
        {
            run = text[i] == text[i - 1] ? run + 1 : 1;
            if (run >= runLength) return true;
        }
        return false;
    }

    private static bool HasSequence(string text, int seqLength)
    {
        var lower = text.ToLowerInvariant();

        // Letras o números consecutivos, ascendentes o descendentes
        for (var i = 0; i + seqLength <= lower.Length; i++)
        {
            var asc = true;
            var desc = true;
            for (var j = 1; j < seqLength; j++)
            {
                if (lower[i + j] != lower[i + j - 1] + 1) asc = false;
                if (lower[i + j] != lower[i + j - 1] - 1) desc = false;
            }
            if ((asc || desc) && char.IsLetterOrDigit(lower[i])) return true;
        }

        // Filas del teclado
        foreach (var row in KeyboardRows)
        {
            for (var i = 0; i + seqLength <= row.Length; i++)
            {
                var piece = row.Substring(i, seqLength);
                var reversed = new string(piece.Reverse().ToArray());
                if (lower.Contains(piece) || lower.Contains(reversed)) return true;
            }
        }

        return false;
    }
}