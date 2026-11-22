using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using ShadowAudit.API.Services;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Unit;

public class AbuseIpDbServiceTests
{
    private const string FoundJson = """{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":42,"totalReports":7,"numDistinctUsers":3,"lastReportedAt":"2026-11-01T10:00:00+00:00","countryCode":"US","usageType":"Data Center/Web Hosting/Transit","isp":"Example ISP","domain":"example.com","isTor":true,"isWhitelisted":false}}""";

    private static AbuseIpDbService Create(FakeHttpHandler handler, bool withKey = true)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.abuseipdb.com/api/v2/") };
        if (withKey) http.DefaultRequestHeaders.Add("Key", "clave-falsa");
        return new AbuseIpDbService(http, NullLogger<AbuseIpDbService>.Instance);
    }

    [Fact]
    public async Task Without_a_key_nothing_is_sent_to_the_service()
    {
        var handler = FakeHttpHandler.Always(HttpStatusCode.OK, FoundJson);

        var report = await Create(handler, withKey: false).CheckIpAsync("8.8.8.8", CancellationToken.None);

        Assert.Equal(AbuseStatus.NotConfigured, report.Status);
        Assert.Empty(handler.Sent);
    }

    [Fact]
    public async Task A_report_is_parsed_completely()
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, FoundJson));

        var report = await service.CheckIpAsync("8.8.8.8", CancellationToken.None);

        Assert.Equal(AbuseStatus.Found, report.Status);
        Assert.Equal(42, report.Score);
        Assert.Equal(7, report.TotalReports);
        Assert.Equal(3, report.DistinctUsers);
        Assert.Equal(new DateTime(2026, 11, 1, 10, 0, 0, DateTimeKind.Utc), report.LastReportedUtc);
        Assert.Equal("US", report.CountryCode);
        Assert.Equal("Data Center/Web Hosting/Transit", report.UsageType);
        Assert.Equal("Example ISP", report.Isp);
        Assert.Equal("example.com", report.Domain);
        Assert.True(report.IsTor);
        Assert.False(report.IsWhitelisted);
    }

    [Fact]
    public async Task The_request_asks_for_90_days_of_history()
    {
        var handler = FakeHttpHandler.Always(HttpStatusCode.OK, FoundJson);

        await Create(handler).CheckIpAsync("8.8.8.8", CancellationToken.None);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal(HttpMethod.Get, sent.Method);
        Assert.Equal("/api/v2/check", sent.Uri.AbsolutePath);
        Assert.Equal("?ipAddress=8.8.8.8&maxAgeInDays=90", sent.Uri.Query);
    }

    [Fact]
    public async Task An_ipv6_address_is_escaped_in_the_url()
    {
        var handler = FakeHttpHandler.Always(HttpStatusCode.OK, FoundJson);

        await Create(handler).CheckIpAsync("2001:db8::1", CancellationToken.None);

        Assert.Contains("ipAddress=2001%3Adb8%3A%3A1", handler.Sent[0].Uri.Query);
    }

    [Fact]
    public async Task Missing_fields_fall_back_to_safe_defaults()
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, """{"data":{}}"""));

        var report = await service.CheckIpAsync("8.8.8.8", CancellationToken.None);

        Assert.Equal(AbuseStatus.Found, report.Status);
        Assert.Equal(0, report.Score);
        Assert.Null(report.LastReportedUtc);
        Assert.Null(report.CountryCode);
        Assert.False(report.IsTor);
        Assert.False(report.IsWhitelisted);
    }

    [Fact]
    public async Task An_ip_never_reported_has_no_last_report_date()
    {
        var json = """{"data":{"abuseConfidenceScore":0,"lastReportedAt":null,"isWhitelisted":true}}""";
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, json));

        var report = await service.CheckIpAsync("8.8.8.8", CancellationToken.None);

        Assert.Null(report.LastReportedUtc);
        Assert.True(report.IsWhitelisted);
    }

    [Fact]
    public async Task Too_many_requests_gives_rate_limited()
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.TooManyRequests));

        var report = await service.CheckIpAsync("8.8.8.8", CancellationToken.None);

        Assert.Equal(AbuseStatus.RateLimited, report.Status);
    }

    [Fact]
    public async Task A_server_error_gives_unavailable_never_a_clean_score()
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.InternalServerError));

        var report = await service.CheckIpAsync("8.8.8.8", CancellationToken.None);

        Assert.Equal(AbuseStatus.Unavailable, report.Status);
        Assert.Equal(0, report.Score);
    }

    [Fact]
    public async Task Network_failures_and_timeouts_give_unavailable()
    {
        var network = Create(FakeHttpHandler.Throwing(new HttpRequestException("sin red")));
        var timeout = Create(FakeHttpHandler.Throwing(new TaskCanceledException()));

        Assert.Equal(AbuseStatus.Unavailable, (await network.CheckIpAsync("8.8.8.8", CancellationToken.None)).Status);
        Assert.Equal(AbuseStatus.Unavailable, (await timeout.CheckIpAsync("8.8.8.8", CancellationToken.None)).Status);
    }

    [Theory]
    [InlineData("esto no es json")]
    [InlineData("{}")]
    public async Task A_broken_or_unexpected_response_gives_unavailable(string body)
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, body));

        var report = await service.CheckIpAsync("8.8.8.8", CancellationToken.None);

        Assert.Equal(AbuseStatus.Unavailable, report.Status);
    }
}