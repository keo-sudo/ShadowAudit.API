using System.Net;
using System.Text;
using System.Text.Json;

namespace ShadowAudit.API.Services;

public enum VtStatus { Found, NotFound, Submitted, RateLimited, NotConfigured, Unavailable }

public record VtStats(int Malicious, int Suspicious, int Harmless, int Undetected, int Timeout)
{
    // Motores que dieron un veredicto
    public int Total => Malicious + Suspicious + Harmless + Undetected;
}

public record VtReport(
    VtStatus Status,
    VtStats? Stats = null,
    DateTime? LastAnalysisUtc = null,
    List<string>? FlaggedBy = null,
    string? TypeDescription = null,
    long? Size = null);

public class VirusTotalService
{
    private readonly HttpClient _http;
    private readonly ILogger<VirusTotalService> _logger;

    public VirusTotalService(HttpClient http, ILogger<VirusTotalService> logger)
    {
        _http = http;
        _logger = logger;
    }

    private bool HasKey => _http.DefaultRequestHeaders.Contains("x-apikey");

    public async Task<VtReport> CheckUrlAsync(string url, CancellationToken ct)
    {
        if (!HasKey) return new VtReport(VtStatus.NotConfigured);

        // Identificador de URL en VirusTotal: base64 seguro para URL, sin relleno "="
        var id = Convert.ToBase64String(Encoding.UTF8.GetBytes(url))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var lookup = await GetReportAsync($"urls/{id}", ct);
        if (lookup.Status != VtStatus.NotFound) return lookup;

        // VirusTotal nunca vio esta URL: se envía a analizar.
        try
        {
            using var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("url", url)
            });
            using var response = await _http.PostAsync("urls", content, ct);

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return new VtReport(VtStatus.RateLimited);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("VirusTotal respondió {Status} al enviar una URL", (int)response.StatusCode);
                return new VtReport(VtStatus.Unavailable);
            }

            return new VtReport(VtStatus.Submitted);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            _logger.LogWarning("No se pudo consultar VirusTotal: {Tipo}", ex.GetType().Name);
            return new VtReport(VtStatus.Unavailable);
        }
    }

    public Task<VtReport> CheckFileAsync(string sha256, CancellationToken ct)
    {
        if (!HasKey) return Task.FromResult(new VtReport(VtStatus.NotConfigured));
        return GetReportAsync($"files/{sha256.ToLowerInvariant()}", ct);
    }

    private async Task<VtReport> GetReportAsync(string path, CancellationToken ct)
    {
        try
        {
            using var response = await _http.GetAsync(path, ct);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return new VtReport(VtStatus.NotFound);

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return new VtReport(VtStatus.RateLimited);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("VirusTotal respondió {Status}", (int)response.StatusCode);
                return new VtReport(VtStatus.Unavailable);
            }

            var json = await response.Content.ReadAsStringAsync(ct);
            return ParseReport(json);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            _logger.LogWarning("No se pudo consultar VirusTotal: {Tipo}", ex.GetType().Name);
            return new VtReport(VtStatus.Unavailable);
        }
    }

    private static VtReport ParseReport(string json)
    {
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("data", out var data) ||
            !data.TryGetProperty("attributes", out var attrs))
            return new VtReport(VtStatus.Unavailable);

        VtStats? stats = null;
        if (attrs.TryGetProperty("last_analysis_stats", out var s) && s.ValueKind == JsonValueKind.Object)
        {
            stats = new VtStats(
                ReadInt(s, "malicious"),
                ReadInt(s, "suspicious"),
                ReadInt(s, "harmless"),
                ReadInt(s, "undetected"),
                ReadInt(s, "timeout"));
        }

        // Todavía sin resultados de análisis
        if (stats is null || stats.Total == 0)
            return new VtReport(VtStatus.Submitted);

        DateTime? lastAnalysis = null;
        if (attrs.TryGetProperty("last_analysis_date", out var d) && d.TryGetInt64(out var unix))
            lastAnalysis = DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime;

        var flagged = new List<string>();
        if (attrs.TryGetProperty("last_analysis_results", out var results) &&
            results.ValueKind == JsonValueKind.Object)
        {
            foreach (var engine in results.EnumerateObject())
            {
                if (engine.Value.TryGetProperty("category", out var category) &&
                    category.GetString() is "malicious" or "suspicious")
                {
                    flagged.Add(engine.Name);
                    if (flagged.Count >= 10) break;
                }
            }
        }

        string? typeDescription = null;
        if (attrs.TryGetProperty("type_description", out var td) && td.ValueKind == JsonValueKind.String)
            typeDescription = td.GetString();

        long? size = null;
        if (attrs.TryGetProperty("size", out var sz) && sz.TryGetInt64(out var sizeValue))
            size = sizeValue;

        return new VtReport(VtStatus.Found, stats, lastAnalysis, flagged, typeDescription, size);
    }

    private static int ReadInt(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) ? number : 0;
}