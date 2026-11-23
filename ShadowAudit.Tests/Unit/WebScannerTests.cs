using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Unit;

public class OwnershipVerifierTests
{
    private const string Host = "ejemplo.com";
    private const string Token = "token-de-prueba-123";

    private static (OwnershipVerifier Verifier, FakeDnsTxtResolver Dns, FakeHttpHandler Handler) Build(
        Func<SentRequest, HttpResponseMessage>? responder = null)
    {
        var dns = new FakeDnsTxtResolver();
        var handler = new FakeHttpHandler(responder ?? (_ => FakeHttpHandler.Response(HttpStatusCode.NotFound)));
        var probe = new SiteProbe(new HttpClient(handler), NullLogger<SiteProbe>.Instance);
        return (new OwnershipVerifier(dns, probe), dns, handler);
    }

    [Fact]
    public void El_token_tiene_43_caracteres_url_seguros_y_es_unico()
    {
        var a = OwnershipVerifier.NewToken();
        var b = OwnershipVerifier.NewToken();

        Assert.Equal(43, a.Length);
        Assert.NotEqual(a, b);
        Assert.Matches("^[A-Za-z0-9_-]+$", a);
    }

    [Fact]
    public void Los_formatos_de_las_instrucciones_son_los_esperados()
    {
        Assert.Equal("_shadowaudit-verify.ejemplo.com", OwnershipVerifier.DnsName(Host));
        Assert.Equal("shadowaudit-verify=abc", OwnershipVerifier.DnsValue("abc"));
        Assert.Equal("https://ejemplo.com/.well-known/shadowaudit-verify.txt", OwnershipVerifier.FileUrl(Host));
    }

    [Fact]
    public async Task Verifica_por_dns_sin_hacer_peticiones_http()
    {
        var (verifier, dns, handler) = Build();
        dns.Records[OwnershipVerifier.DnsName(Host)] = new List<string> { "otro-registro", OwnershipVerifier.DnsValue(Token) };

        var result = await verifier.VerifyAsync(Host, Token, CancellationToken.None);

        Assert.True(result.Verified);
        Assert.Equal("dns", result.Method);
        Assert.Empty(handler.Sent);
    }

    [Fact]
    public async Task Un_registro_dns_con_otro_token_no_sirve_y_prueba_el_archivo_por_https_y_http()
    {
        var (verifier, dns, handler) = Build();
        dns.Records[OwnershipVerifier.DnsName(Host)] = new List<string> { OwnershipVerifier.DnsValue("otro-token") };

        var result = await verifier.VerifyAsync(Host, Token, CancellationToken.None);

        Assert.False(result.Verified);
        Assert.Null(result.Method);
        Assert.Equal(2, handler.Sent.Count);
        Assert.Equal("https", handler.Sent[0].Uri.Scheme);
        Assert.Equal("http", handler.Sent[1].Uri.Scheme);
    }

    [Fact]
    public async Task Verifica_por_archivo_en_https()
    {
        var (verifier, _, _) = Build(_ => FakeHttpHandler.Response(HttpStatusCode.OK, Token + "\n"));

        var result = await verifier.VerifyAsync(Host, Token, CancellationToken.None);

        Assert.True(result.Verified);
        Assert.Equal("archivo", result.Method);
    }

    [Fact]
    public async Task Si_https_falla_prueba_el_archivo_por_http()
    {
        var (verifier, _, _) = Build(r => r.Uri.Scheme == "https"
            ? throw new HttpRequestException("sin https")
            : FakeHttpHandler.Response(HttpStatusCode.OK, Token));

        var result = await verifier.VerifyAsync(Host, Token, CancellationToken.None);

        Assert.True(result.Verified);
        Assert.Equal("archivo", result.Method);
    }

    [Fact]
    public async Task Un_archivo_con_estado_404_no_verifica_aunque_contenga_el_token()
    {
        var (verifier, _, _) = Build(_ => FakeHttpHandler.Response(HttpStatusCode.NotFound, Token));

        var result = await verifier.VerifyAsync(Host, Token, CancellationToken.None);

        Assert.False(result.Verified);
    }

    [Fact]
    public async Task Un_archivo_con_otro_contenido_no_verifica()
    {
        var (verifier, _, _) = Build(_ => FakeHttpHandler.Response(HttpStatusCode.OK, "<html>pagina cualquiera</html>"));

        var result = await verifier.VerifyAsync(Host, Token, CancellationToken.None);

        Assert.False(result.Verified);
    }
}

public class WebScannerTests
{
    private const string Host = "ejemplo.com";

    private static (WebScanner Scanner, FakeHttpHandler Handler, FakeTlsProbe Tls) Build(
        Func<SentRequest, HttpResponseMessage> responder, TlsInfo? tls = null)
    {
        var handler = new FakeHttpHandler(responder);
        var probe = new SiteProbe(new HttpClient(handler), NullLogger<SiteProbe>.Instance);
        var fakeTls = new FakeTlsProbe { Respond = _ => tls ?? FakeTlsProbe.HealthyInfo() };
        return (new WebScanner(probe, fakeTls) { ProbeDelay = TimeSpan.Zero }, handler, fakeTls);
    }

    private static bool IsHome(SentRequest r) =>
        r.Uri.Scheme == "https" && r.Uri.AbsolutePath == "/";

    [Fact]
    public async Task Un_sitio_sano_tiene_riesgo_bajo_y_ninguna_falla()
    {
        var (scanner, _, _) = Build(FakeSites.Healthy);

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.Equal(RiskLevels.Low, report.Risk);
        Assert.Equal(0, report.Failed);
        Assert.True(report.Passed > 0);
        Assert.Equal(Host, report.Host);
    }

    [Fact]
    public async Task Sin_https_el_riesgo_es_alto_y_no_se_hace_ninguna_peticion()
    {
        var (scanner, handler, _) = Build(FakeSites.Healthy,
            new TlsInfo(false, SslProtocols.None, null, SslPolicyErrors.None));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.Equal(RiskLevels.High, report.Risk);
        Assert.Equal("https", Assert.Single(report.Checks).Id);
        Assert.Empty(handler.Sent);
    }

    [Fact]
    public async Task Sin_cabeceras_de_seguridad_el_riesgo_es_medio()
    {
        var (scanner, _, _) = Build(r => IsHome(r)
            ? FakeSites.Response(HttpStatusCode.OK, "<html>hola</html>")
            : FakeSites.Healthy(r));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.Equal(RiskLevels.Medium, report.Risk);
        Assert.Contains(report.Checks, c => c.Id == "hsts" && c.Status == "falla");
        Assert.Contains(report.Checks, c => c.Id == "csp" && c.Status == "falla");
    }

    [Fact]
    public async Task Las_fallas_aparecen_primero_en_la_lista()
    {
        var (scanner, _, _) = Build(r => IsHome(r)
            ? FakeSites.Response(HttpStatusCode.OK, "<html>hola</html>")
            : FakeSites.Healthy(r));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        var checks = report.Checks.ToList();
        var ultimaFalla = checks.FindLastIndex(c => c.Status == "falla");
        var primeraQuePasa = checks.FindIndex(c => c.Status == "pasa");
        Assert.True(ultimaFalla < primeraQuePasa);
    }

    [Fact]
    public async Task Una_cookie_sin_secure_sube_el_riesgo_a_medio()
    {
        var (scanner, _, _) = Build(r => IsHome(r)
            ? FakeSites.Response(HttpStatusCode.OK, "<html>ok</html>", FakeSites.SecureHeaders, null, "sid=abc123; Path=/")
            : FakeSites.Healthy(r));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.Equal(RiskLevels.Medium, report.Risk);
        Assert.Contains(report.Checks, c => c.Id == "cookie-secure" && c.Status == "falla");
    }

    [Fact]
    public async Task Sigue_la_redireccion_a_la_variante_www_del_mismo_sitio()
    {
        var (scanner, handler, _) = Build(r => IsHome(r) && r.Uri.Host == Host
            ? FakeSites.Response(HttpStatusCode.MovedPermanently, "", null, "https://www.ejemplo.com/")
            : FakeSites.Healthy(r));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.Equal(RiskLevels.Low, report.Risk);
        Assert.Contains(handler.Sent, r => r.Uri.Host == "www.ejemplo.com" && r.Uri.AbsolutePath == "/");
        Assert.Contains(handler.Sent, r => r.Uri.Host == "www.ejemplo.com" && r.Uri.AbsolutePath == "/.env");
    }

    [Fact]
    public async Task No_sigue_redirecciones_a_otro_dominio()
    {
        var (scanner, handler, _) = Build(r => IsHome(r)
            ? FakeSites.Response(HttpStatusCode.Found, "", null, "https://otro-sitio.example.org/")
            : FakeSites.Healthy(r));

        await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.DoesNotContain(handler.Sent, r => r.Uri.Host == "otro-sitio.example.org");
    }

    [Fact]
    public async Task Un_bucle_de_redirecciones_se_corta_y_se_reporta()
    {
        var (scanner, handler, _) = Build(_ =>
            FakeSites.Response(HttpStatusCode.MovedPermanently, "", null, "https://ejemplo.com/"));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        var pedidosHttps = handler.Sent.Count(r => r.Uri.Scheme == "https");
        Assert.InRange(pedidosHttps, 1, 5);
        Assert.Contains(report.Checks, c => c.Id == "https-page" && c.Status == "falla");
    }

    [Fact]
    public async Task Si_http_entrega_contenido_sin_redirigir_es_riesgo_medio()
    {
        var (scanner, _, _) = Build(r => r.Uri.Scheme == "http"
            ? FakeSites.Response(HttpStatusCode.OK, "<html>sin https</html>")
            : FakeSites.Healthy(r));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.Equal(RiskLevels.Medium, report.Risk);
        Assert.Contains(report.Checks, c => c.Id == "http-redirect" && c.Status == "falla");
    }

    [Fact]
    public async Task Un_env_expuesto_es_riesgo_alto_y_su_contenido_no_aparece_en_el_reporte()
    {
        var (scanner, _, _) = Build(r => r.Uri.Scheme == "https" && r.Uri.AbsolutePath == "/.env"
            ? FakeSites.Response(HttpStatusCode.OK, "DB_PASSWORD=supersecreto123")
            : FakeSites.Healthy(r));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.Equal(RiskLevels.High, report.Risk);
        Assert.Contains(report.Checks, c => c.Status == "falla" && c.Title.Contains("/.env"));
        Assert.DoesNotContain("supersecreto", JsonSerializer.Serialize(report));
    }

    [Fact]
    public async Task Un_certificado_vencido_es_riesgo_alto()
    {
        var (scanner, _, _) = Build(FakeSites.Healthy,
            new TlsInfo(true, SslProtocols.Tls13, DateTime.UtcNow.AddDays(-1), SslPolicyErrors.None));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.Equal(RiskLevels.High, report.Risk);
        Assert.Contains(report.Checks, c => c.Id == "cert-expiry" && c.Status == "falla");
    }

    [Fact]
    public async Task Si_https_conecta_pero_la_pagina_no_responde_se_reporta()
    {
        var (scanner, _, _) = Build(r => r.Uri.Scheme == "https"
            ? throw new HttpRequestException("sin respuesta")
            : FakeSites.Healthy(r));

        var report = await scanner.ScanAsync(Host, CancellationToken.None);

        Assert.Contains(report.Checks, c => c.Id == "https-page" && c.Status == "falla");
        Assert.Equal(RiskLevels.Medium, report.Risk);
    }
}