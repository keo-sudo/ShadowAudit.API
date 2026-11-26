using System.Text.RegularExpressions;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public record FootprintSite(string Name, string UrlTemplate);

public record FootprintResult(string Site, string Status);

public static class UsernameRules
{
    // Solo letras, números, punto, guion y guion bajo; empieza con letra o número.
    // Así el usuario no puede alterar la dirección que se consulta.
    public static bool IsValid(string? username) =>
        username is not null && Regex.IsMatch(username, @"^[A-Za-z0-9][A-Za-z0-9._-]{0,38}\z");
}

// Revisa si un nombre de usuario PROPIO existe en sitios públicos.
// Reutiliza SiteProbe: solo IPs públicas, solo puertos 80/443 y sin redirecciones automáticas.
public class FootprintChecker
{
    public static readonly IReadOnlyList<FootprintSite> Sites = new List<FootprintSite>
    {
        new("GitHub", "https://github.com/{u}"),
        new("GitLab", "https://gitlab.com/{u}"),
        new("DEV Community", "https://dev.to/{u}"),
        new("Keybase", "https://keybase.io/{u}"),
        new("Codeberg", "https://codeberg.org/{u}")
    };

    private readonly SiteProbe _probe;

    public FootprintChecker(SiteProbe probe) => _probe = probe;

    public async Task<List<FootprintResult>> CheckAsync(string username, CancellationToken ct)
    {
        var tasks = Sites.Select(async site =>
        {
            var url = site.UrlTemplate.Replace("{u}", Uri.EscapeDataString(username));
            var response = await _probe.GetAsync(url, 256, ct);
            var status = response?.StatusCode switch
            {
                200 => "existe",
                404 => "no_existe",
                _ => "indeterminado"
            };
            return new FootprintResult(site.Name, status);
        });

        return (await Task.WhenAll(tasks)).ToList();
    }

    // Tener perfil público no es una falla: solo sube a medio si aparece en 3 o más sitios.
    public static string Risk(IEnumerable<FootprintResult> results) =>
        results.Count(r => r.Status == "existe") >= 3 ? RiskLevels.Medium : RiskLevels.Low;
}