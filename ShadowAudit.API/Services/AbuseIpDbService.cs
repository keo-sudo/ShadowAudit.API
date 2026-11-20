using System.Net;
using System.Text.Json;

namespace ShadowAudit.API.Services;

public enum AbuseStatus { Found, RateLimited, NotConfigured, Unavailable }

public record AbuseReport(
    AbuseStatus Status,
    int Score = 0,
    int TotalReports = 0,
    int DistinctUsers = 0,
    DateTime? LastReportedUtc = null,
    string? CountryCode = null,
    string? UsageType = null,
    string? Isp = null,
    string? Domain = null,
    bool IsTor = false,
    bool IsWhitelisted = false);

public class AbuseIpDbService
{
    private readonly HttpClient _http;
    private readonly ILogger<AbuseIpDbService> _logger;

    public AbuseIpDbService(HttpClient http, ILogger<AbuseIpDbService> logger)
    {
        _http = http;
        _logger = logger;
    }

    private bool HasKey => _http.DefaultRequestHeaders.Contains("Key");

    public async Task<AbuseReport> CheckIpAsync(string ip, CancellationToken ct)
    {
        if (!HasKey) return new AbuseReport(AbuseStatus.NotConfigured);

        try
        {
            using var response = await _http.GetAsync(
                $"check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90", ct);

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return new AbuseReport(AbuseStatus.RateLimited);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("AbuseIPDB respondió {Status}", (int)response.StatusCode);
                return new AbuseReport(AbuseStatus.Unavailable);
            }

            var json = await response.Content.ReadAsStringAsync(ct);
            return Parse(json);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            _logger.LogWarning("No se pudo consultar AbuseIPDB: {Tipo}", ex.GetType().Name);
            return new AbuseReport(AbuseStatus.Unavailable);
        }
    }

    private static AbuseReport Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("data", out var data))
            return new AbuseReport(AbuseStatus.Unavailable);

        DateTime? lastReported = null;
        if (data.TryGetProperty("lastReportedAt", out var last) &&
            last.ValueKind == JsonValueKind.String &&
            DateTimeOffset.TryParse(last.GetString(), out var parsed))
        {
            lastReported = parsed.UtcDateTime;
        }

        return new AbuseReport(
            AbuseStatus.Found,
            ReadInt(data, "abuseConfidenceScore"),
            ReadInt(data, "totalReports"),
            ReadInt(data, "numDistinctUsers"),
            lastReported,
            ReadString(data, "countryCode"),
            ReadString(data, "usageType"),
            ReadString(data, "isp"),
            ReadString(data, "domain"),
            ReadBool(data, "isTor"),
            ReadBool(data, "isWhitelisted"));
    }

    private static int ReadInt(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) ? number : 0;

    private static string? ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool ReadBool(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
}