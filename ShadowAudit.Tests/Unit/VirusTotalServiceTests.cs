using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using ShadowAudit.API.Services;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Unit;

public class VirusTotalServiceTests
{
    private const string FoundJson = """{"data":{"attributes":{"last_analysis_stats":{"malicious":5,"suspicious":1,"harmless":60,"undetected":10,"timeout":2},"last_analysis_date":1700000000,"last_analysis_results":{"EngineA":{"category":"malicious"},"EngineB":{"category":"harmless"},"EngineC":{"category":"suspicious"}},"type_description":"Win32 EXE","size":12345}}}""";

    private const string Sha256 = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";

    private static VirusTotalService Create(FakeHttpHandler handler, bool withKey = true)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") };
        if (withKey) http.DefaultRequestHeaders.Add("x-apikey", "clave-falsa");
        return new VirusTotalService(http, NullLogger<VirusTotalService>.Instance);
    }

    [Fact]
    public async Task Without_a_key_nothing_is_sent_to_the_service()
    {
        var handler = FakeHttpHandler.Always(HttpStatusCode.OK, FoundJson);
        var service = Create(handler, withKey: false);

        var url = await service.CheckUrlAsync("https://example.com/", CancellationToken.None);
        var file = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(VtStatus.NotConfigured, url.Status);
        Assert.Equal(VtStatus.NotConfigured, file.Status);
        Assert.Empty(handler.Sent);
    }

    [Fact]
    public async Task A_known_file_report_is_parsed_completely()
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, FoundJson));

        var report = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(VtStatus.Found, report.Status);
        Assert.Equal(new VtStats(5, 1, 60, 10, 2), report.Stats);
        Assert.Equal(76, report.Stats!.Total);
        Assert.Equal(new[] { "EngineA", "EngineC" }, report.FlaggedBy);
        Assert.Equal("Win32 EXE", report.TypeDescription);
        Assert.Equal(12345, report.Size);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1700000000).UtcDateTime, report.LastAnalysisUtc);
    }

    [Fact]
    public async Task The_file_hash_is_sent_in_lowercase()
    {
        var handler = FakeHttpHandler.Always(HttpStatusCode.OK, FoundJson);

        await Create(handler).CheckFileAsync(Sha256, CancellationToken.None);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal(HttpMethod.Get, sent.Method);
        Assert.Equal("/api/v3/files/" + Sha256.ToLowerInvariant(), sent.Uri.AbsolutePath);
    }

    [Fact]
    public async Task An_unknown_file_gives_not_found()
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.NotFound));

        var report = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(VtStatus.NotFound, report.Status);
    }

    [Fact]
    public async Task Too_many_requests_gives_rate_limited()
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.TooManyRequests));

        var report = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(VtStatus.RateLimited, report.Status);
    }

    [Fact]
    public async Task A_server_error_gives_unavailable_never_safe()
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.InternalServerError));

        var report = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(VtStatus.Unavailable, report.Status);
        Assert.Null(report.Stats);
    }

    [Fact]
    public async Task A_network_failure_gives_unavailable()
    {
        var service = Create(FakeHttpHandler.Throwing(new HttpRequestException("sin red")));

        var report = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(VtStatus.Unavailable, report.Status);
    }

    [Fact]
    public async Task A_timeout_gives_unavailable()
    {
        var service = Create(FakeHttpHandler.Throwing(new TaskCanceledException()));

        var report = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(VtStatus.Unavailable, report.Status);
    }

    [Theory]
    [InlineData("esto no es json")]
    [InlineData("{}")]
    [InlineData("""{"data":{}}""")]
    public async Task A_broken_or_unexpected_response_gives_unavailable(string body)
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, body));

        var report = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(VtStatus.Unavailable, report.Status);
    }

    [Theory]
    [InlineData("""{"data":{"attributes":{}}}""")]
    [InlineData("""{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":0,"undetected":0,"timeout":0}}}}""")]
    public async Task A_report_without_analysis_results_yet_is_submitted_not_clean(string body)
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, body));

        var report = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(VtStatus.Submitted, report.Status);
    }

    [Fact]
    public async Task At_most_ten_flagging_engines_are_listed()
    {
        var engines = string.Join(",",
            Enumerable.Range(1, 15).Select(i => $"\"Motor{i}\":{{\"category\":\"malicious\"}}"));
        var json = "{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":15,\"suspicious\":0," +
                   "\"harmless\":0,\"undetected\":0,\"timeout\":0},\"last_analysis_results\":{" + engines + "}}}}";
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, json));

        var report = await service.CheckFileAsync(Sha256, CancellationToken.None);

        Assert.Equal(10, report.FlaggedBy!.Count);
        Assert.Equal("Motor1", report.FlaggedBy[0]);
    }

    [Fact]
    public async Task A_url_already_known_is_not_submitted_again()
    {
        var handler = FakeHttpHandler.Always(HttpStatusCode.OK, FoundJson);

        var report = await Create(handler).CheckUrlAsync("https://example.com/", CancellationToken.None);

        Assert.Equal(VtStatus.Found, report.Status);
        Assert.Single(handler.Sent);
    }

    [Fact]
    public async Task An_unknown_url_is_submitted_for_analysis()
    {
        const string url = "https://example.com/pagina?x=1";
        var handler = new FakeHttpHandler(request => request.Method == HttpMethod.Get
            ? FakeHttpHandler.Response(HttpStatusCode.NotFound)
            : FakeHttpHandler.Response(HttpStatusCode.OK, "{}"));

        var report = await Create(handler).CheckUrlAsync(url, CancellationToken.None);

        Assert.Equal(VtStatus.Submitted, report.Status);
        Assert.Equal(2, handler.Sent.Count);

        var post = handler.Sent[1];
        Assert.Equal(HttpMethod.Post, post.Method);
        Assert.Equal("/api/v3/urls", post.Uri.AbsolutePath);
        Assert.StartsWith("url=", post.Body);
        Assert.Equal(url, Uri.UnescapeDataString(post.Body!["url=".Length..]));
    }

    [Theory]
    [InlineData("http://a.io/???", "Pz8_")]
    [InlineData("http://a.io/>>>", "Pj4-")]
    public async Task The_url_identifier_is_url_safe_base64_without_padding(string url, string expectedEnding)
    {
        var handler = FakeHttpHandler.Always(HttpStatusCode.OK, FoundJson);

        await Create(handler).CheckUrlAsync(url, CancellationToken.None);

        var id = handler.Sent[0].Uri.AbsolutePath["/api/v3/urls/".Length..];
        Assert.EndsWith(expectedEnding, id);
        Assert.DoesNotContain('+', id);
        Assert.DoesNotContain('/', id);
        Assert.DoesNotContain('=', id);
    }

    [Fact]
    public async Task Rate_limit_on_the_lookup_stops_before_submitting()
    {
        var handler = FakeHttpHandler.Always(HttpStatusCode.TooManyRequests);

        var report = await Create(handler).CheckUrlAsync("https://example.com/", CancellationToken.None);

        Assert.Equal(VtStatus.RateLimited, report.Status);
        Assert.Single(handler.Sent);
    }

    [Fact]
    public async Task Rate_limit_when_submitting_gives_rate_limited()
    {
        var handler = new FakeHttpHandler(request => request.Method == HttpMethod.Get
            ? FakeHttpHandler.Response(HttpStatusCode.NotFound)
            : FakeHttpHandler.Response(HttpStatusCode.TooManyRequests));

        var report = await Create(handler).CheckUrlAsync("https://example.com/", CancellationToken.None);

        Assert.Equal(VtStatus.RateLimited, report.Status);
    }

    [Fact]
    public async Task A_failure_when_submitting_gives_unavailable()
    {
        var serverError = new FakeHttpHandler(request => request.Method == HttpMethod.Get
            ? FakeHttpHandler.Response(HttpStatusCode.NotFound)
            : FakeHttpHandler.Response(HttpStatusCode.InternalServerError));

        var networkError = new FakeHttpHandler(request => request.Method == HttpMethod.Get
            ? FakeHttpHandler.Response(HttpStatusCode.NotFound)
            : throw new HttpRequestException("sin red"));

        var first = await Create(serverError).CheckUrlAsync("https://example.com/", CancellationToken.None);
        var second = await Create(networkError).CheckUrlAsync("https://example.com/", CancellationToken.None);

        Assert.Equal(VtStatus.Unavailable, first.Status);
        Assert.Equal(VtStatus.Unavailable, second.Status);
    }
}