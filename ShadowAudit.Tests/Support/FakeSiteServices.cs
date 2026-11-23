using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Support;

// DNS falso: devuelve los registros TXT que la prueba prepare.
public sealed class FakeDnsTxtResolver : IDnsTxtResolver
{
    public Dictionary<string, List<string>> Records { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Task<IReadOnlyList<string>> GetTxtAsync(string name, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<string>>(
            Records.TryGetValue(name, out var list) ? list.ToList() : new List<string>());
}

// Sonda TLS falsa: por defecto el sitio tiene HTTPS sano.
public sealed class FakeTlsProbe : ITlsProbe
{
    public Func<string, TlsInfo> Respond { get; set; } = _ => HealthyInfo();

    public List<string> Inspected { get; } = new();

    public Task<TlsInfo> InspectAsync(string host, CancellationToken ct)
    {
        Inspected.Add(host);
        return Task.FromResult(Respond(host));
    }

    public static TlsInfo HealthyInfo() =>
        new(true, SslProtocols.Tls13, DateTime.UtcNow.AddDays(90), SslPolicyErrors.None);
}

public static class FakeSites
{
    public static readonly Dictionary<string, string> SecureHeaders = new()
    {
        ["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains",
        ["Content-Security-Policy"] = "default-src 'self'",
        ["X-Content-Type-Options"] = "nosniff",
        ["X-Frame-Options"] = "DENY",
        ["Referrer-Policy"] = "strict-origin-when-cross-origin",
        ["Permissions-Policy"] = "geolocation=()"
    };

    public static HttpResponseMessage Response(
        HttpStatusCode status,
        string body = "",
        IDictionary<string, string>? headers = null,
        string? location = null,
        params string[] setCookies)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body) };

        if (headers is not null)
            foreach (var (key, value) in headers)
                response.Headers.TryAddWithoutValidation(key, value);

        if (location is not null)
            response.Headers.Location = new Uri(location, UriKind.RelativeOrAbsolute);

        foreach (var cookie in setCookies)
            response.Headers.TryAddWithoutValidation("Set-Cookie", cookie);

        return response;
    }

    // Sitio sano: HTTPS devuelve la home con todas las cabeceras, HTTP redirige a HTTPS, lo demas es 404.
    public static HttpResponseMessage Healthy(SentRequest request)
    {
        if (request.Uri.Scheme == "https" && request.Uri.AbsolutePath == "/")
            return Response(HttpStatusCode.OK, "<html>ok</html>", SecureHeaders);

        if (request.Uri.Scheme == "http")
            return Response(HttpStatusCode.MovedPermanently, "", null, $"https://{request.Uri.Host}/");

        return Response(HttpStatusCode.NotFound);
    }
}