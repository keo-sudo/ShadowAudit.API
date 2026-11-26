using System.Text.Json;
using System.Text.RegularExpressions;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public record FootprintSite(
    string Name, string UrlTemplate, string ProfileTemplate, string Category,
    int ExistsCode, string ExistsText, int MissingCode, string MissingText, string StripChars);

public record FootprintResult(string Site, string Status, string? Url = null, string? Category = null);

public static class UsernameRules
{
    // Solo letras, numeros, punto, guion y guion bajo: el usuario no puede alterar la direccion consultada.
    public static bool IsValid(string? username) =>
        username is not null && Regex.IsMatch(username, @"^[A-Za-z0-9][A-Za-z0-9._-]{0,38}\z");
}

// Lista de sitios (proyecto WhatsMyName, CC BY-SA 4.0) incluida como recurso del proyecto.
public static class FootprintCatalog
{
    private static readonly Lazy<IReadOnlyList<FootprintSite>> _sites =
        new Lazy<IReadOnlyList<FootprintSite>>(Load);

    private static readonly HashSet<string> BlockedCategories =
        new(StringComparer.OrdinalIgnoreCase) { "xx NSFW xx", "archived" };

    public static IReadOnlyList<FootprintSite> Sites => _sites.Value;

    public static IReadOnlyList<string> Categories =>
        Sites.Select(s => s.Category).Where(c => c.Length > 0)
             .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(c => c).ToList();

    private static IReadOnlyList<FootprintSite> Load()
    {
        using var stream = typeof(FootprintCatalog).Assembly.GetManifestResourceStream("wmn-data.json")
            ?? throw new InvalidOperationException("Falta el recurso wmn-data.json.");
        using var doc = JsonDocument.Parse(stream);

        var list = new List<FootprintSite>();
        foreach (var s in doc.RootElement.GetProperty("sites").EnumerateArray())
        {
            // Solo sitios que se pueden revisar con un GET simple.
            if (Has(s, "post_body") || Has(s, "headers") || Has(s, "protection")) continue;
            if (s.TryGetProperty("valid", out var valid) && valid.ValueKind == JsonValueKind.False) continue;

            var name = Str(s, "name");
            var uri = Str(s, "uri_check");
            var cat = Str(s, "cat");
            if (name.Length == 0 || BlockedCategories.Contains(cat)) continue;
            if (!uri.StartsWith("https://", StringComparison.Ordinal) || !uri.Contains("{account}")) continue;
            if (!s.TryGetProperty("e_code", out var ec) || ec.ValueKind != JsonValueKind.Number) continue;
            if (!s.TryGetProperty("m_code", out var mc) || mc.ValueKind != JsonValueKind.Number) continue;

            var pretty = Str(s, "uri_pretty");
            if (!pretty.Contains("{account}")) pretty = uri;

            list.Add(new FootprintSite(name, uri, pretty, cat, ec.GetInt32(), Str(s, "e_string"),
                mc.GetInt32(), Str(s, "m_string"), Str(s, "strip_bad_char")));
        }
        return list;
    }

    private static bool Has(JsonElement e, string p)
    {
        if (!e.TryGetProperty(p, out var v)) return false;
        return v.ValueKind switch
        {
            JsonValueKind.Null => false,
            JsonValueKind.String => v.GetString()!.Length > 0,
            JsonValueKind.Array => v.GetArrayLength() > 0,
            JsonValueKind.Object => v.EnumerateObject().Any(),
            _ => true
        };
    }

    private static string Str(JsonElement e, string p) =>
        e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
}

// Revisa si un nombre de usuario PROPIO existe en cientos de sitios publicos.
// Reutiliza SiteProbe: solo IPs publicas, solo puertos 80/443 y sin redirecciones automaticas.
public class FootprintChecker
{
    private const int MaxBodyBytes = 120_000;
    private const int MaxParallel = 40;
    private static readonly TimeSpan SiteTimeout = TimeSpan.FromSeconds(8);

    // Redes grandes que bloquean consultas automaticas: se devuelve el enlace para abrirlo a mano.
    private static readonly (string Name, string Template)[] ManualSites =
    {
        ("Instagram", "https://www.instagram.com/{u}/"),
        ("TikTok", "https://www.tiktok.com/@{u}"),
        ("X (Twitter)", "https://x.com/{u}"),
        ("Facebook", "https://www.facebook.com/{u}"),
        ("Threads", "https://www.threads.net/@{u}"),
        ("Snapchat", "https://www.snapchat.com/add/{u}"),
        ("YouTube", "https://www.youtube.com/@{u}"),
        ("Telegram", "https://t.me/{u}"),
        ("LinkedIn", "https://www.linkedin.com/in/{u}"),
        ("Twitch", "https://www.twitch.tv/{u}")
    };

    private readonly SiteProbe _probe;

    public FootprintChecker(SiteProbe probe) => _probe = probe;

    public static IEnumerable<object> ManualLinks(string username) =>
        ManualSites.Select(s => (object)new
        {
            site = s.Name,
            url = s.Template.Replace("{u}", Uri.EscapeDataString(username))
        });

    public async Task<List<FootprintResult>> CheckAsync(
        string username, CancellationToken ct, IReadOnlyCollection<string>? categories = null)
    {
        var sites = FootprintCatalog.Sites
            .Where(s => categories is null || categories.Count == 0
                        || categories.Contains(s.Category, StringComparer.OrdinalIgnoreCase))
            .ToList();

        using var gate = new SemaphoreSlim(MaxParallel);
        var tasks = sites.Select(site => CheckSiteAsync(site, username, gate, ct));
        return (await Task.WhenAll(tasks)).ToList();
    }

    private async Task<FootprintResult> CheckSiteAsync(
        FootprintSite site, string username, SemaphoreSlim gate, CancellationToken ct)
    {
        var name = site.StripChars.Length == 0
            ? username
            : new string(username.Where(c => !site.StripChars.Contains(c)).ToArray());
        if (name.Length == 0) return new FootprintResult(site.Name, "indeterminado", null, site.Category);

        var encoded = Uri.EscapeDataString(name);
        var url = site.UrlTemplate.Replace("{account}", encoded);
        var profile = site.ProfileTemplate.Replace("{account}", encoded);

        await gate.WaitAsync(ct);
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(SiteTimeout);
            var response = await _probe.GetAsync(url, MaxBodyBytes, cts.Token);
            return new FootprintResult(site.Name, Classify(site, response), profile, site.Category);
        }
        finally
        {
            gate.Release();
        }
    }

    public static string Classify(FootprintSite site, ProbeResponse? r)
    {
        if (r is null) return "indeterminado";

        var exists = r.StatusCode == site.ExistsCode
                     && (site.ExistsText.Length == 0 || r.BodyText.Contains(site.ExistsText, StringComparison.Ordinal));
        var missing = r.StatusCode == site.MissingCode
                      && (site.MissingText.Length == 0 || r.BodyText.Contains(site.MissingText, StringComparison.Ordinal));

        if (missing && site.MissingText.Length > 0) return "no_existe";
        if (exists) return "existe";
        return missing ? "no_existe" : "indeterminado";
    }

    // Con cientos de sitios es normal aparecer en varios: sube a medio desde 10 coincidencias.
    public static string Risk(IEnumerable<FootprintResult> results) =>
        results.Count(r => r.Status == "existe") >= 10 ? RiskLevels.Medium : RiskLevels.Low;
}