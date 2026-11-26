using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Unit;

public class FootprintCheckerTests
{
    private static readonly FootprintSite Sitio = new(
        "Sitio", "https://sitio.test/{account}", "https://sitio.test/{account}", "social",
        200, "perfil", 404, "no encontrado", "");

    private static ProbeResponse Resp(int code, string body = "") =>
        new(code, new Dictionary<string, string>(), new List<string>(), body, null);

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
    public void Clasifica_segun_codigo_y_texto_de_la_pagina()
    {
        Assert.Equal("existe", FootprintChecker.Classify(Sitio, Resp(200, "hola perfil de keo")));
        Assert.Equal("no_existe", FootprintChecker.Classify(Sitio, Resp(404, "no encontrado")));
        Assert.Equal("indeterminado", FootprintChecker.Classify(Sitio, Resp(404, "")));
        Assert.Equal("indeterminado", FootprintChecker.Classify(Sitio, Resp(200, "pagina cualquiera")));
        Assert.Equal("indeterminado", FootprintChecker.Classify(Sitio, Resp(403, "perfil")));
        Assert.Equal("indeterminado", FootprintChecker.Classify(Sitio, null));
    }

    [Fact]
    public void El_catalogo_carga_cientos_de_sitios_seguros()
    {
        var sites = FootprintCatalog.Sites;

        Assert.True(sites.Count >= 100);
        Assert.All(sites, s => Assert.StartsWith("https://", s.UrlTemplate));
        Assert.All(sites, s => Assert.Contains("{account}", s.UrlTemplate));
        Assert.DoesNotContain(sites, s => s.Category == "xx NSFW xx" || s.Category == "archived");
    }

    [Fact]
    public async Task Hace_una_peticion_https_por_sitio_con_el_usuario()
    {
        var (checker, handler) = Build(_ => FakeHttpHandler.Response(HttpStatusCode.NotFound));

        await checker.CheckAsync("keo", CancellationToken.None);

        Assert.Equal(FootprintCatalog.Sites.Count, handler.Sent.Count);
        Assert.All(handler.Sent, r => Assert.Equal("https", r.Uri.Scheme));
        Assert.All(handler.Sent, r => Assert.Contains("keo", r.Uri.AbsoluteUri));
    }

    [Fact]
    public void El_riesgo_sube_a_medio_con_10_o_mas_sitios()
    {
        var diez = Enumerable.Range(0, 10).Select(i => new FootprintResult($"S{i}", "existe")).ToArray();
        var nueve = Enumerable.Range(0, 9).Select(i => new FootprintResult($"S{i}", "existe"))
            .Append(new FootprintResult("Z", "no_existe")).ToArray();

        Assert.Equal(RiskLevels.Medium, FootprintChecker.Risk(diez));
        Assert.Equal(RiskLevels.Low, FootprintChecker.Risk(nueve));
    }
}