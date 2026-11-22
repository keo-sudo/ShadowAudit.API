using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using ShadowAudit.API.Services;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Unit;

public class PasswordBreachTests
{
    private const string Password = "ClaveDePrueba-Solo-Test-77";

    private static (string Prefix, string Suffix) Sha1Parts(string password)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        return (hash[..5], hash[5..]);
    }

    private static PasswordCheckService Create(FakeHttpHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        return new PasswordCheckService(http, NullLogger<PasswordCheckService>.Instance);
    }

    private static string RangeBody(string suffix, int count) =>
        $"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{suffix}:{count}\r\n{new string('F', 35)}:9\r\n";

    [Fact]
    public async Task A_password_found_in_the_range_is_breached_with_its_count()
    {
        var (_, suffix) = Sha1Parts(Password);
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, RangeBody(suffix, 12345)));

        var result = await service.CheckBreachAsync(Password, CancellationToken.None);

        Assert.True(result.Breached);
        Assert.Equal(12345, result.TimesSeen);
    }

    [Fact]
    public async Task Only_the_five_character_prefix_leaves_the_server()
    {
        var (prefix, suffix) = Sha1Parts(Password);
        var handler = FakeHttpHandler.Always(HttpStatusCode.OK, RangeBody(suffix, 1));

        await Create(handler).CheckBreachAsync(Password, CancellationToken.None);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal(HttpMethod.Get, sent.Method);
        Assert.Equal("/range/" + prefix, sent.Uri.AbsolutePath);
        Assert.Equal(string.Empty, sent.Uri.Query);
        Assert.Null(sent.Body);
        Assert.DoesNotContain(suffix, sent.Uri.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Password, sent.Uri.ToString());
    }

    [Fact]
    public async Task A_password_missing_from_the_range_is_not_breached()
    {
        var body = $"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{new string('F', 35)}:9\r\n";
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, body));

        var result = await service.CheckBreachAsync(Password, CancellationToken.None);

        Assert.False(result.Breached);
        Assert.Equal(0, result.TimesSeen);
    }

    [Fact]
    public async Task Padding_rows_with_count_zero_are_ignored()
    {
        var (_, suffix) = Sha1Parts(Password);
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, RangeBody(suffix, 0)));

        var result = await service.CheckBreachAsync(Password, CancellationToken.None);

        Assert.False(result.Breached);
    }

    [Fact]
    public async Task The_match_ignores_upper_and_lower_case()
    {
        var (_, suffix) = Sha1Parts(Password);
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, RangeBody(suffix.ToLowerInvariant(), 5)));

        var result = await service.CheckBreachAsync(Password, CancellationToken.None);

        Assert.True(result.Breached);
    }

    [Fact]
    public async Task Malformed_lines_are_skipped()
    {
        var (_, suffix) = Sha1Parts(Password);
        var body = $"basura sin dos puntos\r\n{suffix}:77\r\n:::\r\n";
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, body));

        var result = await service.CheckBreachAsync(Password, CancellationToken.None);

        Assert.True(result.Breached);
        Assert.Equal(77, result.TimesSeen);
    }

    [Fact]
    public async Task An_empty_range_is_not_breached()
    {
        var service = Create(FakeHttpHandler.Always(HttpStatusCode.OK, ""));

        var result = await service.CheckBreachAsync(Password, CancellationToken.None);

        Assert.False(result.Breached);
    }

    [Fact]
    public async Task If_the_service_fails_the_answer_is_unknown_never_not_breached()
    {
        var serverError = Create(FakeHttpHandler.Always(HttpStatusCode.InternalServerError));
        var tooMany = Create(FakeHttpHandler.Always(HttpStatusCode.TooManyRequests));
        var network = Create(FakeHttpHandler.Throwing(new HttpRequestException("sin red")));
        var timeout = Create(FakeHttpHandler.Throwing(new TaskCanceledException()));

        foreach (var service in new[] { serverError, tooMany, network, timeout })
        {
            var result = await service.CheckBreachAsync(Password, CancellationToken.None);

            Assert.Null(result.Breached);
            Assert.Equal(0, result.TimesSeen);
        }
    }
}

public class PasswordStrengthTests
{
    [Theory]
    [InlineData("12345678", 0, "Muy débil")]
    [InlineData("password", 1, "Débil")]
    [InlineData("Hola2024", 2, "Aceptable")]
    [InlineData("Zq7mK2xP9vL", 3, "Fuerte")]
    [InlineData("Zq7!mK2#xP9$vL4&", 4, "Muy fuerte")]
    public void Each_level_gets_its_score_and_label(string password, int score, string label)
    {
        var result = PasswordCheckService.EvaluateStrength(password);

        Assert.Equal(score, result.Score);
        Assert.Equal(label, result.Label);
    }

    [Fact]
    public void A_strong_password_has_no_issues()
    {
        var result = PasswordCheckService.EvaluateStrength("Zq7!mK2#xP9$vL4&");

        Assert.Empty(result.Issues);
    }

    [Fact]
    public void A_weak_password_lists_what_it_lacks()
    {
        var result = PasswordCheckService.EvaluateStrength("password");

        Assert.Contains("Tiene menos de 12 caracteres.", result.Issues);
        Assert.Contains("No tiene números.", result.Issues);
        Assert.Contains("No tiene mayúsculas.", result.Issues);
        Assert.Contains("No tiene símbolos.", result.Issues);
    }

    [Fact]
    public void Digits_only_has_no_letters()
    {
        var result = PasswordCheckService.EvaluateStrength("12345678");

        Assert.Contains("No tiene letras.", result.Issues);
    }

    [Theory]
    [InlineData("MiClaveQwerty99")]
    [InlineData("xx1234xx")]
    [InlineData("Zq7!abcd-Kp")]
    public void Sequences_are_detected(string password)
    {
        var result = PasswordCheckService.EvaluateStrength(password);

        Assert.Contains("Contiene una secuencia como 1234, abcd o qwerty.", result.Issues);
    }

    [Fact]
    public void A_sequence_lowers_the_estimated_strength()
    {
        var clean = PasswordCheckService.EvaluateStrength("Zq7!mK2#xP9$vL4&");
        var withSequence = PasswordCheckService.EvaluateStrength("Zq7!mK2#xP9$vL4&abcd");

        Assert.True(withSequence.EstimatedBits < clean.EstimatedBits);
    }

    [Fact]
    public void Repeating_the_same_character_is_penalized()
    {
        var result = PasswordCheckService.EvaluateStrength("aaaaaaaaaaaa");

        Assert.Contains("Repite el mismo carácter 3 o más veces seguidas.", result.Issues);
        Assert.Equal(0, result.Score);
    }

    [Fact]
    public void A_longer_password_never_scores_lower_than_a_shorter_one_with_the_same_kind_of_characters()
    {
        var shorter = PasswordCheckService.EvaluateStrength("Zq7mK2xP");
        var longer = PasswordCheckService.EvaluateStrength("Zq7mK2xP9vLhTn5R");

        Assert.True(longer.EstimatedBits > shorter.EstimatedBits);
    }
}