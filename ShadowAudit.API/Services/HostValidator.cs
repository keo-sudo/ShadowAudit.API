using System.Net;

namespace ShadowAudit.API.Services;

public static class HostValidator
{
    private static readonly string[] BlockedSuffixes =
    {
        ".localhost", ".local", ".internal", ".lan", ".home", ".corp", ".intranet", ".test", ".invalid"
    };

    // Devuelve un mensaje de error, o null si el dominio es válido.
    // host = dominio limpio en minúsculas.
    public static string? Validate(string? raw, out string host)
    {
        host = string.Empty;
        if (string.IsNullOrWhiteSpace(raw)) return "El dominio es obligatorio.";

        var h = raw.Trim().ToLowerInvariant();
        if (h.EndsWith('.')) h = h[..^1];

        if (h.Length > 253) return "El dominio es demasiado largo.";

        if (h.Contains("://") || h.Contains('/') || h.Contains(':') || h.Contains('@') ||
            h.Contains('?') || h.Contains('#') || h.Any(char.IsWhiteSpace))
            return "Escribe solo el dominio, sin http://, puerto ni ruta. Ejemplo: ejemplo.com";

        if (IPAddress.TryParse(h, out _))
            return "No se aceptan direcciones IP, solo nombres de dominio.";

        var labels = h.Split('.');
        if (labels.Length < 2) return "Escribe un dominio completo, por ejemplo ejemplo.com";

        foreach (var label in labels)
        {
            if (label.Length == 0 || label.Length > 63 || label.StartsWith('-') || label.EndsWith('-'))
                return "El dominio no es válido.";

            foreach (var c in label)
            {
                var ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                if (!ok) return "El dominio solo puede tener letras, números y guiones.";
            }
        }

        if (labels[^1].All(char.IsDigit)) return "El dominio no es válido.";

        foreach (var suffix in BlockedSuffixes)
        {
            if (h.EndsWith(suffix) || h == suffix[1..]) return "Ese dominio no es público.";
        }

        host = h;
        return null;
    }
}