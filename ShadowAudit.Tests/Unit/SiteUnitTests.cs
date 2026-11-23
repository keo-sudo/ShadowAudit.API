using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Unit;

public class HostValidatorTests
{
    [Theory]
    [InlineData("Example.COM", "example.com")]
    [InlineData("  www.ejemplo.com  ", "www.ejemplo.com")]
    [InlineData("mi-sitio.com.pe", "mi-sitio.com.pe")]
    [InlineData("ejemplo.com.", "ejemplo.com")]
    public void Acepta_dominios_validos_y_los_normaliza(string raw, string esperado)
    {
        var error = HostValidator.Validate(raw, out var host);

        Assert.Null(error);
        Assert.Equal(esperado, host);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("localhost")]
    [InlineData("https://example.com")]
    [InlineData("example.com/ruta")]
    [InlineData("example.com:8080")]
    [InlineData("usuario@example.com")]
    [InlineData("example.com?x=1")]
    [InlineData("192.168.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("::1")]
    [InlineData("exa mple.com")]
    [InlineData("-malo.com")]
    [InlineData("malo-.com")]
    [InlineData("exa_mple.com")]
    [InlineData("example.123")]
    [InlineData("mi.local")]
    [InlineData("router.lan")]
    [InlineData("servidor.internal")]
    [InlineData("algo.test")]
    [InlineData("algo.localhost")]
    public void Rechaza_dominios_invalidos_o_no_publicos(string? raw)
    {
        var error = HostValidator.Validate(raw, out var host);

        Assert.NotNull(error);
        Assert.Equal(string.Empty, host);
    }

    [Fact]
    public void Rechaza_etiquetas_de_mas_de_63_caracteres()
    {
        var error = HostValidator.Validate(new string('a', 64) + ".com", out _);
        Assert.NotNull(error);
    }

    [Fact]
    public void Rechaza_dominios_de_mas_de_253_caracteres()
    {
        var largo = string.Join(".", Enumerable.Repeat("abcdefgh", 40)) + ".com";
        var error = HostValidator.Validate(largo, out _);
        Assert.NotNull(error);
    }
}

public class PublicIpTests
{
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("93.184.216.34")]
    [InlineData("11.0.0.1")]
    [InlineData("172.32.0.1")]
    [InlineData("100.128.0.1")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("::ffff:8.8.8.8")]
    public void Reconoce_direcciones_publicas(string ip) =>
        Assert.True(PublicIp.IsPublic(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]
    [InlineData("100.64.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("198.18.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.5")]
    [InlineData("::1")]
    [InlineData("::")]
    [InlineData("fe80::1")]
    [InlineData("fec0::1")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456::1")]
    [InlineData("ff02::1")]
    [InlineData("2001:db8::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:192.168.0.1")]
    [InlineData("::8.8.8.8")]
    [InlineData("64:ff9b::808:808")]
    public void Rechaza_direcciones_privadas_o_reservadas(string ip) =>
        Assert.False(PublicIp.IsPublic(IPAddress.Parse(ip)));
}

public class SafeConnectTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("localhost")]
    [InlineData("10.1.2.3")]
    [InlineData("192.168.0.10")]
    [InlineData("::1")]
    public async Task No_se_conecta_a_direcciones_no_publicas(string host)
    {
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            SafeConnect.ResolvePublicAddressesAsync(host, CancellationToken.None));
    }

    [Fact]
    public async Task Acepta_una_ip_publica()
    {
        var addresses = await SafeConnect.ResolvePublicAddressesAsync("8.8.8.8", CancellationToken.None);

        Assert.Single(addresses);
        Assert.Equal(IPAddress.Parse("8.8.8.8"), addresses[0]);
    }
}

public class HeaderChecksTests
{
    private static Dictionary<string, string> Secure() =>
        new(FakeSites.SecureHeaders, StringComparer.OrdinalIgnoreCase);

    private static ScanCheck Get(List<ScanCheck> checks, string id) => checks.Single(c => c.Id == id);

    [Fact]
    public void Un_sitio_con_todas_las_cabeceras_no_falla()
    {
        var checks = HeaderChecks.Analyze(Secure(), isHttps: true);

        Assert.DoesNotContain(checks, c => c.Status == "falla");
    }

    [Fact]
    public void Sin_cabeceras_fallan_con_la_gravedad_esperada()
    {
        var checks = HeaderChecks.Analyze(new Dictionary<string, string>(), isHttps: true);

        Assert.Equal(RiskLevels.Medium, Get(checks, "hsts").Severity);
        Assert.Equal(RiskLevels.Medium, Get(checks, "csp").Severity);
        Assert.Equal(RiskLevels.Low, Get(checks, "nosniff").Severity);
        Assert.Equal(RiskLevels.Low, Get(checks, "clickjacking").Severity);
        Assert.Equal(RiskLevels.Low, Get(checks, "referrer").Severity);
        Assert.Equal(RiskLevels.Low, Get(checks, "permissions").Severity);
    }

    [Fact]
    public void Hsts_con_duracion_corta_es_riesgo_bajo()
    {
        var headers = Secure();
        headers["Strict-Transport-Security"] = "max-age=3600";

        var checks = HeaderChecks.Analyze(headers, isHttps: true);

        Assert.Equal("falla", Get(checks, "hsts").Status);
        Assert.Equal(RiskLevels.Low, Get(checks, "hsts").Severity);
    }

    [Fact]
    public void Sin_https_no_se_revisa_hsts()
    {
        var checks = HeaderChecks.Analyze(new Dictionary<string, string>(), isHttps: false);

        Assert.DoesNotContain(checks, c => c.Id == "hsts");
    }

    [Fact]
    public void Csp_con_unsafe_inline_es_riesgo_bajo()
    {
        var headers = Secure();
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'";

        var checks = HeaderChecks.Analyze(headers, isHttps: true);

        Assert.Equal("falla", Get(checks, "csp").Status);
        Assert.Equal(RiskLevels.Low, Get(checks, "csp").Severity);
    }

    [Fact]
    public void Frame_ancestors_en_la_csp_cuenta_como_proteccion_contra_clickjacking()
    {
        var headers = Secure();
        headers.Remove("X-Frame-Options");
        headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'";

        var checks = HeaderChecks.Analyze(headers, isHttps: true);

        Assert.Equal("pasa", Get(checks, "clickjacking").Status);
    }

    [Theory]
    [InlineData("nginx/1.18.0", true)]
    [InlineData("Apache/2.4.58", true)]
    [InlineData("nginx", false)]
    public void Detecta_versiones_publicadas_en_la_cabecera_Server(string server, bool falla)
    {
        var headers = Secure();
        headers["Server"] = server;

        var checks = HeaderChecks.Analyze(headers, isHttps: true);

        Assert.Equal(falla ? "falla" : "pasa", Get(checks, "info-leak").Status);
    }

    [Fact]
    public void X_Powered_By_se_marca_como_fuga_de_informacion()
    {
        var headers = Secure();
        headers["X-Powered-By"] = "PHP/8.2";

        var checks = HeaderChecks.Analyze(headers, isHttps: true);

        Assert.Equal("falla", Get(checks, "info-leak").Status);
    }
}

public class CookieChecksTests
{
    [Fact]
    public void Sin_cookies_pasa()
    {
        var checks = CookieChecks.Analyze(new List<string>());

        var unico = Assert.Single(checks);
        Assert.Equal("pasa", unico.Status);
    }

    [Fact]
    public void Cookie_sin_atributos_falla_en_los_tres()
    {
        var checks = CookieChecks.Analyze(new List<string> { "sessionid=abc123; Path=/" });

        Assert.Equal(RiskLevels.Medium, checks.Single(c => c.Id == "cookie-secure").Severity);
        Assert.Equal(RiskLevels.Low, checks.Single(c => c.Id == "cookie-httponly").Severity);
        Assert.Equal(RiskLevels.Low, checks.Single(c => c.Id == "cookie-samesite").Severity);
    }

    [Fact]
    public void Cookie_bien_configurada_pasa()
    {
        var checks = CookieChecks.Analyze(new List<string> { "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax" });

        Assert.DoesNotContain(checks, c => c.Status == "falla");
    }

    [Fact]
    public void El_resultado_nunca_incluye_nombres_ni_valores_de_cookies()
    {
        var checks = CookieChecks.Analyze(new List<string> { "sessionid=valorsecreto; Path=/" });

        var texto = string.Join(" ", checks.Select(c => c.Title + c.Detail + c.Fix));
        Assert.DoesNotContain("sessionid", texto);
        Assert.DoesNotContain("valorsecreto", texto);
    }
}

public class TlsChecksTests
{
    private static readonly DateTime Now = new(2026, 11, 22, 12, 0, 0, DateTimeKind.Utc);

    private static TlsInfo Info(
        double days = 90,
        SslPolicyErrors errors = SslPolicyErrors.None,
        SslProtocols protocol = SslProtocols.Tls13) =>
        new(true, protocol, Now.AddDays(days), errors);

    private static ScanCheck Get(List<ScanCheck> checks, string id) => checks.Single(c => c.Id == id);

    [Fact]
    public void Sin_conexion_solo_falla_https_con_riesgo_alto()
    {
        var checks = TlsChecks.Analyze(new TlsInfo(false, SslProtocols.None, null, SslPolicyErrors.None), Now);

        var unico = Assert.Single(checks);
        Assert.Equal("https", unico.Id);
        Assert.Equal(RiskLevels.High, unico.Severity);
    }

    [Fact]
    public void Un_sitio_sano_no_falla()
    {
        var checks = TlsChecks.Analyze(Info(), Now);

        Assert.DoesNotContain(checks, c => c.Status == "falla");
    }

    [Theory]
    [InlineData(-1, "alto")]
    [InlineData(10, "alto")]
    [InlineData(20, "medio")]
    public void Certificado_por_vencer_o_vencido(double dias, string gravedad)
    {
        var checks = TlsChecks.Analyze(Info(dias), Now);

        Assert.Equal("falla", Get(checks, "cert-expiry").Status);
        Assert.Equal(gravedad, Get(checks, "cert-expiry").Severity);
    }

    [Fact]
    public void Certificado_que_vence_en_mas_de_30_dias_pasa()
    {
        var checks = TlsChecks.Analyze(Info(31), Now);

        Assert.Equal("pasa", Get(checks, "cert-expiry").Status);
    }

    [Fact]
    public void Certificado_no_confiable_es_riesgo_alto()
    {
        var checks = TlsChecks.Analyze(Info(errors: SslPolicyErrors.RemoteCertificateNameMismatch), Now);

        Assert.Equal("falla", Get(checks, "cert-trust").Status);
        Assert.Equal(RiskLevels.High, Get(checks, "cert-trust").Severity);
    }

    [Fact]
    public void Tls12_pasa()
    {
        var checks = TlsChecks.Analyze(Info(protocol: SslProtocols.Tls12), Now);

        Assert.Equal("pasa", Get(checks, "tls-protocol").Status);
    }

    [Fact]
    public void Protocolo_antiguo_es_riesgo_medio()
    {
        var checks = TlsChecks.Analyze(Info(protocol: SslProtocols.None), Now);

        Assert.Equal("falla", Get(checks, "tls-protocol").Status);
        Assert.Equal(RiskLevels.Medium, Get(checks, "tls-protocol").Severity);
    }
}

public class ExposedFilesTests
{
    private static ProbeResponse R(string body) =>
        new(200, new Dictionary<string, string>(), new List<string>(), body, null);

    [Theory]
    [InlineData("/.env", "DB_PASSWORD=abc123\nAPI_KEY=xyz")]
    [InlineData("/.git/HEAD", "ref: refs/heads/main")]
    [InlineData("/.git/config", "[core]\n\trepositoryformatversion = 0")]
    [InlineData("/backup.zip", "PK\u0003\u0004datos")]
    [InlineData("/backup.sql", "CREATE TABLE users (id int);")]
    [InlineData("/dump.sql", "INSERT INTO t VALUES (1);")]
    [InlineData("/appsettings.json", "{ \"ConnectionStrings\": {} }")]
    [InlineData("/phpinfo.php", "<title>phpinfo()</title>")]
    [InlineData("/server-status", "Apache Server Status for ejemplo")]
    [InlineData("/.DS_Store", "\u0000\u0000\u0000\u0001Bud1")]
    public void Reconoce_el_contenido_real_del_archivo(string path, string body)
    {
        var probe = ExposedFiles.Probes.Single(p => p.Path == path);

        Assert.True(probe.Matches(R(body)));
    }

    [Fact]
    public void Una_pagina_html_generica_no_cuenta_como_archivo_expuesto()
    {
        var html = R("<!doctype html><html><body>Hola mundo</body></html>");

        foreach (var probe in ExposedFiles.Probes)
            Assert.False(probe.Matches(html), probe.Path);
    }

    [Fact]
    public void Las_gravedades_son_las_esperadas()
    {
        Assert.Equal(RiskLevels.High, ExposedFiles.Probes.Single(p => p.Path == "/.env").Severity);
        Assert.Equal(RiskLevels.High, ExposedFiles.Probes.Single(p => p.Path == "/.git/HEAD").Severity);
        Assert.Equal(RiskLevels.Medium, ExposedFiles.Probes.Single(p => p.Path == "/phpinfo.php").Severity);
        Assert.Equal(RiskLevels.Low, ExposedFiles.Probes.Single(p => p.Path == "/.DS_Store").Severity);
    }
}