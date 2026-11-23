using System.Net.Security;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public record ScanCheck(string Id, string Title, string Status, string? Severity, string Detail, string? Fix)
{
    public static ScanCheck Pass(string id, string title, string detail) =>
        new(id, title, "pasa", null, detail, null);

    public static ScanCheck Fail(string id, string title, string severity, string detail, string fix) =>
        new(id, title, "falla", severity, detail, fix);
}

public record WebScanReport(
    string Host,
    string Risk,
    int Failed,
    int Passed,
    IReadOnlyList<ScanCheck> Checks,
    DateTime ScannedAtUtc);

public static class TlsChecks
{
    public static List<ScanCheck> Analyze(TlsInfo t, DateTime now)
    {
        var list = new List<ScanCheck>();

        if (!t.Connected)
        {
            list.Add(ScanCheck.Fail("https", "HTTPS activo", RiskLevels.High,
                "El sitio no acepta conexiones HTTPS en el puerto 443.",
                "Activa HTTPS con un certificado válido (por ejemplo, Let's Encrypt)."));
            return list;
        }

        list.Add(ScanCheck.Pass("https", "HTTPS activo", "El sitio acepta conexiones HTTPS."));

        if (t.NotAfterUtc is { } end)
        {
            var days = (end - now).TotalDays;
            const string fix = "Renueva el certificado y activa la renovación automática.";
            if (days < 0)
                list.Add(ScanCheck.Fail("cert-expiry", "Vencimiento del certificado", RiskLevels.High,
                    "El certificado ya venció.", fix));
            else if (days < 14)
                list.Add(ScanCheck.Fail("cert-expiry", "Vencimiento del certificado", RiskLevels.High,
                    "El certificado vence en menos de 14 días.", fix));
            else if (days < 30)
                list.Add(ScanCheck.Fail("cert-expiry", "Vencimiento del certificado", RiskLevels.Medium,
                    "El certificado vence en menos de 30 días.", fix));
            else
                list.Add(ScanCheck.Pass("cert-expiry", "Vencimiento del certificado",
                    $"El certificado vence en {(int)days} días."));
        }

        if (t.PolicyErrors == SslPolicyErrors.None)
            list.Add(ScanCheck.Pass("cert-trust", "Certificado de confianza", "El certificado es válido y de confianza."));
        else
            list.Add(ScanCheck.Fail("cert-trust", "Certificado de confianza", RiskLevels.High,
                "El certificado no es de confianza (nombre incorrecto, cadena incompleta o vencido).",
                "Instala un certificado emitido por una autoridad reconocida para este dominio."));

        if (t.Protocol is SslProtocols.Tls12 or SslProtocols.Tls13)
            list.Add(ScanCheck.Pass("tls-protocol", "Versión de TLS", "Usa TLS 1.2 o superior."));
        else
            list.Add(ScanCheck.Fail("tls-protocol", "Versión de TLS", RiskLevels.Medium,
                "El sitio negoció un protocolo TLS antiguo.",
                "Desactiva TLS 1.0 y 1.1 y deja solo TLS 1.2 y 1.3."));

        return list;
    }
}

public static class HeaderChecks
{
    private static string? Get(IReadOnlyDictionary<string, string> h, string name) =>
        h.TryGetValue(name, out var v) ? v : null;

    public static List<ScanCheck> Analyze(IReadOnlyDictionary<string, string> h, bool isHttps)
    {
        var list = new List<ScanCheck>();

        if (isHttps)
        {
            var hsts = Get(h, "Strict-Transport-Security");
            if (hsts is null)
                list.Add(ScanCheck.Fail("hsts", "HSTS", RiskLevels.Medium,
                    "Falta la cabecera Strict-Transport-Security.",
                    "Agrega Strict-Transport-Security: max-age=31536000; includeSubDomains"));
            else
            {
                var m = Regex.Match(hsts, @"max-age=(\d+)", RegexOptions.IgnoreCase);
                if (!m.Success || long.Parse(m.Groups[1].Value) < 15552000)
                    list.Add(ScanCheck.Fail("hsts", "HSTS", RiskLevels.Low,
                        "HSTS dura menos de 180 días.", "Sube max-age a 31536000 (un año)."));
                else
                    list.Add(ScanCheck.Pass("hsts", "HSTS", "HSTS activo con duración suficiente."));
            }
        }

        var csp = Get(h, "Content-Security-Policy");
        if (csp is null)
            list.Add(ScanCheck.Fail("csp", "Content-Security-Policy", RiskLevels.Medium,
                "Falta la cabecera Content-Security-Policy.",
                "Define una política CSP que limite de dónde se cargan scripts y recursos."));
        else if (csp.Contains("unsafe-inline", StringComparison.OrdinalIgnoreCase) ||
                 csp.Contains("unsafe-eval", StringComparison.OrdinalIgnoreCase))
            list.Add(ScanCheck.Fail("csp", "Content-Security-Policy", RiskLevels.Low,
                "La política CSP permite unsafe-inline o unsafe-eval.",
                "Quita unsafe-inline y unsafe-eval; usa nonces o hashes."));
        else
            list.Add(ScanCheck.Pass("csp", "Content-Security-Policy", "Hay una política CSP sin directivas inseguras."));

        var nosniff = Get(h, "X-Content-Type-Options");
        if (nosniff is not null && nosniff.Contains("nosniff", StringComparison.OrdinalIgnoreCase))
            list.Add(ScanCheck.Pass("nosniff", "X-Content-Type-Options", "Está en nosniff."));
        else
            list.Add(ScanCheck.Fail("nosniff", "X-Content-Type-Options", RiskLevels.Low,
                "Falta X-Content-Type-Options: nosniff.", "Agrega X-Content-Type-Options: nosniff"));

        if (Get(h, "X-Frame-Options") is not null ||
            (csp is not null && csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase)))
            list.Add(ScanCheck.Pass("clickjacking", "Protección contra clickjacking", "El sitio no se puede incrustar en otras páginas."));
        else
            list.Add(ScanCheck.Fail("clickjacking", "Protección contra clickjacking", RiskLevels.Low,
                "Otras páginas podrían incrustar tu sitio en un marco.",
                "Agrega X-Frame-Options: DENY o la directiva frame-ancestors en la CSP."));

        if (Get(h, "Referrer-Policy") is not null)
            list.Add(ScanCheck.Pass("referrer", "Referrer-Policy", "Está definida."));
        else
            list.Add(ScanCheck.Fail("referrer", "Referrer-Policy", RiskLevels.Low,
                "Falta Referrer-Policy.", "Agrega Referrer-Policy: strict-origin-when-cross-origin"));

        if (Get(h, "Permissions-Policy") is not null)
            list.Add(ScanCheck.Pass("permissions", "Permissions-Policy", "Está definida."));
        else
            list.Add(ScanCheck.Fail("permissions", "Permissions-Policy", RiskLevels.Low,
                "Falta Permissions-Policy.", "Agrega Permissions-Policy para desactivar funciones del navegador que no uses."));

        var server = Get(h, "Server");
        var leaks = Get(h, "X-Powered-By") is not null || (server is not null && server.Any(char.IsDigit));
        if (leaks)
            list.Add(ScanCheck.Fail("info-leak", "Información del servidor", RiskLevels.Low,
                "El sitio publica la tecnología o versión del servidor.",
                "Oculta las cabeceras Server y X-Powered-By."));
        else
            list.Add(ScanCheck.Pass("info-leak", "Información del servidor", "No publica versiones del servidor."));

        return list;
    }
}

public static class CookieChecks
{
    // Nunca devuelve nombres ni valores de las cookies.
    public static List<ScanCheck> Analyze(IReadOnlyList<string> setCookies)
    {
        var list = new List<ScanCheck>();

        if (setCookies.Count == 0)
        {
            list.Add(ScanCheck.Pass("cookies", "Cookies", "La página principal no puso cookies."));
            return list;
        }

        static HashSet<string> Attrs(string cookie) =>
            cookie.Split(';').Skip(1)
                .Select(a => a.Trim().ToLowerInvariant())
                .Select(a => a.Split('=')[0])
                .ToHashSet();

        var all = setCookies.Select(Attrs).ToList();
        var noSecure = all.Count(a => !a.Contains("secure"));
        var noHttpOnly = all.Count(a => !a.Contains("httponly"));
        var noSameSite = all.Count(a => !a.Contains("samesite"));

        if (noSecure > 0)
            list.Add(ScanCheck.Fail("cookie-secure", "Cookies con Secure", RiskLevels.Medium,
                $"{noSecure} cookie(s) sin el atributo Secure.", "Agrega el atributo Secure a todas las cookies."));
        else
            list.Add(ScanCheck.Pass("cookie-secure", "Cookies con Secure", "Todas las cookies tienen Secure."));

        if (noHttpOnly > 0)
            list.Add(ScanCheck.Fail("cookie-httponly", "Cookies con HttpOnly", RiskLevels.Low,
                $"{noHttpOnly} cookie(s) sin el atributo HttpOnly.", "Agrega HttpOnly a las cookies que JavaScript no necesite leer."));
        else
            list.Add(ScanCheck.Pass("cookie-httponly", "Cookies con HttpOnly", "Todas las cookies tienen HttpOnly."));

        if (noSameSite > 0)
            list.Add(ScanCheck.Fail("cookie-samesite", "Cookies con SameSite", RiskLevels.Low,
                $"{noSameSite} cookie(s) sin el atributo SameSite.", "Agrega SameSite=Lax o SameSite=Strict."));
        else
            list.Add(ScanCheck.Pass("cookie-samesite", "Cookies con SameSite", "Todas las cookies tienen SameSite."));

        return list;
    }
}

public record ExposedProbe(string Path, string Severity, Func<ProbeResponse, bool> Matches);

public static class ExposedFiles
{
    private static bool Rx(ProbeResponse r, string pattern) => Regex.IsMatch(r.BodyText, pattern);

    // Solo cuenta si el contenido parece de verdad el archivo (no una página 200 genérica).
    public static readonly IReadOnlyList<ExposedProbe> Probes = new List<ExposedProbe>
    {
        new("/.env", RiskLevels.High, r => Rx(r, @"(?m)^[A-Z][A-Z0-9_]{2,}=.+")),
        new("/.git/HEAD", RiskLevels.High, r => r.BodyText.TrimStart().StartsWith("ref:")),
        new("/.git/config", RiskLevels.High, r => r.BodyText.Contains("[core]")),
        new("/backup.zip", RiskLevels.High, r => r.BodyText.StartsWith("PK")),
        new("/backup.sql", RiskLevels.High, r => Rx(r, @"(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)")),
        new("/dump.sql", RiskLevels.High, r => Rx(r, @"(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)")),
        new("/appsettings.json", RiskLevels.High, r => Rx(r, @"(?i)""(ConnectionStrings|Logging|AllowedHosts|Jwt)""")),
        new("/phpinfo.php", RiskLevels.Medium, r => r.BodyText.Contains("phpinfo()") || r.BodyText.Contains("PHP Version")),
        new("/server-status", RiskLevels.Medium, r => r.BodyText.Contains("Apache Server Status")),
        new("/.DS_Store", RiskLevels.Low, r => r.BodyText.Contains("Bud1"))
    };
}

public class WebScanner
{
    private const int MaxRedirects = 4;

    private readonly SiteProbe _probe;
    private readonly ITlsProbe _tls;

    // Pausa entre pruebas de archivos para no cargar el sitio. Las pruebas la ponen en cero.
    public static TimeSpan DefaultProbeDelay { get; set; } = TimeSpan.FromMilliseconds(200);

    public TimeSpan ProbeDelay { get; init; } = DefaultProbeDelay;

    public WebScanner(SiteProbe probe, ITlsProbe tls)
    {
        _probe = probe;
        _tls = tls;
    }

    public async Task<WebScanReport> ScanAsync(string host, CancellationToken ct)
    {
        var checks = new List<ScanCheck>();

        var tls = await _tls.InspectAsync(host, ct);
        checks.AddRange(TlsChecks.Analyze(tls, DateTime.UtcNow));

        if (tls.Connected)
        {
            var (home, finalHost) = await FetchHomeAsync(host, ct);

            var redirect = await CheckHttpRedirectAsync(host, ct);
            if (redirect is not null) checks.Add(redirect);

            if (home is null)
            {
                checks.Add(ScanCheck.Fail("https-page", "Página principal por HTTPS", RiskLevels.Medium,
                    "La conexión HTTPS funciona pero la página principal no respondió; no se pudieron revisar las cabeceras.",
                    "Revisa que el sitio responda correctamente por HTTPS."));
            }
            else
            {
                checks.AddRange(HeaderChecks.Analyze(home.Headers, isHttps: true));
                checks.AddRange(CookieChecks.Analyze(home.SetCookies));
                checks.AddRange(await CheckExposedFilesAsync(finalHost, ct));
            }
        }

        var ordered = checks
            .OrderBy(c => c.Status == "falla" ? 0 : 1)
            .ThenByDescending(c => c.Severity is null ? -1 : RiskLevels.Rank(c.Severity))
            .ToList();

        var failed = ordered.Where(c => c.Status == "falla").ToList();
        var risk = failed.Count == 0
            ? RiskLevels.Low
            : failed.OrderByDescending(c => RiskLevels.Rank(c.Severity!)).First().Severity!;

        return new WebScanReport(host, risk, failed.Count, ordered.Count - failed.Count, ordered, DateTime.UtcNow);
    }

    // Pide la página principal y sigue hasta 4 redirecciones, solo dentro del mismo sitio.
    private async Task<(ProbeResponse? Response, string Host)> FetchHomeAsync(string host, CancellationToken ct)
    {
        var current = new Uri($"https://{host}/");

        for (var i = 0; i <= MaxRedirects; i++)
        {
            var response = await _probe.GetAsync(current.ToString(), 65536, ct);
            if (response is null) return (null, current.Host);

            var isRedirect = response.StatusCode is 301 or 302 or 303 or 307 or 308;
            if (isRedirect && !string.IsNullOrEmpty(response.Location))
            {
                if (!Uri.TryCreate(current, response.Location, out var next) || !SameSite(host, next))
                    return (response, current.Host);

                current = next;
                continue;
            }

            return (response, current.Host);
        }

        return (null, current.Host);
    }

    private static bool SameSite(string host, Uri next) =>
        next.Scheme == Uri.UriSchemeHttps && next.IsDefaultPort &&
        (next.Host == host || next.Host == "www." + host || host == "www." + next.Host);

    private async Task<ScanCheck?> CheckHttpRedirectAsync(string host, CancellationToken ct)
    {
        var response = await _probe.GetAsync($"http://{host}/", 2048, ct);
        if (response is null) return null;

        var redirects = response.StatusCode is 301 or 302 or 303 or 307 or 308;
        if (redirects && response.Location is not null &&
            response.Location.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return ScanCheck.Pass("http-redirect", "Redirección de HTTP a HTTPS", "El sitio redirige HTTP a HTTPS.");

        if (redirects || response.StatusCode == 200)
            return ScanCheck.Fail("http-redirect", "Redirección de HTTP a HTTPS", RiskLevels.Medium,
                "El sitio responde por HTTP sin redirigir a HTTPS.",
                "Configura una redirección permanente (301) de HTTP a HTTPS.");

        return null;
    }

    private async Task<List<ScanCheck>> CheckExposedFilesAsync(string host, CancellationToken ct)
    {
        var found = new List<ScanCheck>();

        foreach (var probe in ExposedFiles.Probes)
        {
            if (ProbeDelay > TimeSpan.Zero) await Task.Delay(ProbeDelay, ct);

            var response = await _probe.GetAsync($"https://{host}{probe.Path}", 16384, ct);
            if (response is { StatusCode: 200 } && probe.Matches(response))
            {
                var id = "exposed-" + probe.Path.Trim('/').Replace('.', '-').Replace('/', '-');
                found.Add(ScanCheck.Fail(id, $"Archivo expuesto: {probe.Path}", probe.Severity,
                    "El archivo es accesible públicamente desde internet.",
                    "Quita el archivo del servidor web o bloquea su acceso."));
            }
        }

        if (found.Count == 0)
            found.Add(ScanCheck.Pass("exposed-files", "Archivos sensibles",
                $"No se encontraron los {ExposedFiles.Probes.Count} archivos sensibles comunes que se revisan."));

        return found;
    }
}