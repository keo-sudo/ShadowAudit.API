using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Unit;

public class FootprintCheckerTests
{
    private static (FootprintChecker Checker, FakeHttpHandler Handler) Build(Func<SentRequest, HttpResponseMessage> responder)
    {
        var handler = new FakeHttpHandler(responder);
        var probe = new SiteProbe(new HttpClient(handler), NullLogger<SiteProbe>.Instance);
        return (new FootprintChecker(probe), handler);
    }

    [Theory]
    [InlineData("keo")]
    [InlineData("keo-sudo")]
    [InlineData("a.b_c-1")]
    [InlineData("1abc")]
    public void Acepta_usuarios_validos(string usuario) => Assert.True(UsernameRules.IsValid(usuario));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("../x")]
    [InlineData(".oculto")]
    [InlineData("a b")]
    [InlineData("a/b")]
    [InlineData("-x")]
    [InlineData("a?b=1")]
    [InlineData("abc\n")]
    public void Rechaza_usuarios_que_podrian_alterar_la_direccion(string? usuario) =>
        Assert.False(UsernameRules.IsValid(usuario));

    [Fact]
    public async Task Traduce_el_estado_http_a_existe_no_existe_o_indeterminado()
    {
        var (checker, _) = Build(r => r.Uri.Host switch
        {
            "github.com" => FakeHttpHandler.Response(HttpStatusCode.OK),
            "gitlab.com" => FakeHttpHandler.Response(HttpStatusCode.NotFound),
            "dev.to" => FakeHttpHandler.Response(HttpStatusCode.Forbidden),
            _ => throw new HttpRequestException("sin respuesta")
        });

        var results = await checker.CheckAsync("keo", CancellationToken.None);

        Assert.Equal("existe", results.Single(r => r.Site == "GitHub").Status);
        Assert.Equal("no_existe", results.Single(r => r.Site == "GitLab").Status);
        Assert.Equal("indeterminado", results.Single(r => r.Site == "DEV Community").Status);
        Assert.Equal("indeterminado", results.Single(r => r.Site == "Keybase").Status);
    }

    [Fact]
    public async Task Hace_una_peticion_https_por_sitio_y_escapa_el_usuario()
    {
        var (checker, handler) = Build(_ => FakeHttpHandler.Response(HttpStatusCode.NotFound));

        await checker.CheckAsync("a.b", CancellationToken.None);

        Assert.Equal(FootprintChecker.Sites.Count, handler.Sent.Count);
        Assert.All(handler.Sent, r => Assert.Equal("https", r.Uri.Scheme));
        Assert.All(handler.Sent, r => Assert.EndsWith("/a.b", r.Uri.AbsolutePath));
    }

    [Fact]
    public void El_riesgo_sube_a_medio_con_3_o_mas_sitios()
    {
        var tres = new[] { new FootprintResult("A", "existe"), new FootprintResult("B", "existe"), new FootprintResult("C", "existe") };
        var dos = new[] { new FootprintResult("A", "existe"), new FootprintResult("B", "existe"), new FootprintResult("C", "no_existe") };

        Assert.Equal(RiskLevels.Medium, FootprintChecker.Risk(tres));
        Assert.Equal(RiskLevels.Low, FootprintChecker.Risk(dos));
    }
}