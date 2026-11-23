using System.Text;

namespace ShadowAudit.API.Services;

public record ProbeResponse(
    int StatusCode,
    IReadOnlyDictionary<string, string> Headers,
    IReadOnlyList<string> SetCookies,
    string BodyText,
    string? Location);

public class SiteProbe
{
    private readonly HttpClient _http;
    private readonly ILogger<SiteProbe> _logger;

    public SiteProbe(HttpClient http, ILogger<SiteProbe> logger)
    {
        _http = http;
        _logger = logger;
    }

    // Devuelve null si no se pudo conectar o no respondió. Lee como máximo maxBodyBytes.
    public async Task<ProbeResponse?> GetAsync(string url, int maxBodyBytes, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in response.Headers) headers[h.Key] = string.Join(", ", h.Value);
            foreach (var h in response.Content.Headers) headers[h.Key] = string.Join(", ", h.Value);

            var cookies = response.Headers.TryGetValues("Set-Cookie", out var values)
                ? values.ToList()
                : new List<string>();

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[maxBodyBytes];
            var total = 0;
            while (total < maxBodyBytes)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(total, maxBodyBytes - total), ct);
                if (read == 0) break;
                total += read;
            }

            return new ProbeResponse(
                (int)response.StatusCode,
                headers,
                cookies,
                Encoding.Latin1.GetString(buffer, 0, total),
                response.Headers.Location?.OriginalString);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or InvalidOperationException)
        {
            // Solo el tipo de error: nunca la URL consultada.
            _logger.LogDebug("Sondeo fallido: {ErrorType}", ex.GetType().Name);
            return null;
        }
    }
}