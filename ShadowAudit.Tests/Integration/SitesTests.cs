using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Authentication;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ShadowAudit.API.Data;
using ShadowAudit.API.Services;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Integration;

[Collection("api")]
public class SitesTests
{
    private readonly TestApiFactory _f;

    public SitesTests(ApiFixture fixture)
    {
        _f = fixture.Factory;

        // Cada prueba arranca con un mundo falso limpio.
        _f.SiteResponder = FakeSites.Healthy;
        _f.Tls.Respond = _ => FakeTlsProbe.HealthyInfo();
        _f.Tls.Inspected.Clear();
        _f.Dns.Records.Clear();
        _f.SiteHandler.Sent.Clear();
    }

    private sealed record Owner(TestUser User, string Token);

    private async Task<Owner> NewOwnerAsync()
    {
        var client = _f.NewClient();
        var user = TestUser.New();
        (await client.Register(user)).EnsureSuccessStatusCode();
        var session = await client.LoginOk(user);
        return new Owner(user, session.Token);
    }

    private HttpClient Api(Owner owner, string? ip = null) => _f.NewClient(ip).Bearer(owner.Token);

    private static string NewHost() => $"site{Guid.NewGuid():N}.example.com";

    private async Task<(Guid Id, string Host, string SiteToken)> AddSiteAsync(Owner owner, string? host = null)
    {
        host ??= NewHost();
        var response = await Api(owner).PostAsJsonAsync("/api/sites", new { host });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Json();
        return (
            json.GetProperty("id").GetGuid(),
            json.GetProperty("host").GetString()!,
            json.GetProperty("verification").GetProperty("file").GetProperty("content").GetString()!);
    }

    private async Task<(Guid Id, string Host, string SiteToken)> AddVerifiedSiteAsync(Owner owner)
    {
        var site = await AddSiteAsync(owner);
        _f.Dns.Records[OwnershipVerifier.DnsName(site.Host)] =
            new List<string> { OwnershipVerifier.DnsValue(site.SiteToken) };

        var response = await Api(owner).PostAsync($"/api/sites/{site.Id}/verify", null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return site;
    }

    private Task<HttpResponseMessage> ScanAsync(Owner owner, Guid id, string? label = null, string? ip = null)
    {
        var url = $"/api/sites/{id}/scan" + (label is null ? "" : "?label=" + Uri.EscapeDataString(label));
        return Api(owner, ip).PostAsync(url, null);
    }

    [Fact]
    public async Task Todos_los_endpoints_exigen_login()
    {
        var client = _f.NewClient();
        var id = Guid.NewGuid();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/sites")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/sites", new { host = "ejemplo.com" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync($"/api/sites/{id}/verify", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync($"/api/sites/{id}/scan", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.DeleteAsync($"/api/sites/{id}")).StatusCode);
    }

    [Fact]
    public async Task Agregar_un_sitio_normaliza_el_dominio_y_da_instrucciones()
    {
        var owner = await NewOwnerAsync();

        var response = await Api(owner).PostAsJsonAsync("/api/sites", new { host = "  WWW.Mi-Sitio-Prueba.COM  " });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Json();
        Assert.Equal("www.mi-sitio-prueba.com", json.GetProperty("host").GetString());
        Assert.False(json.GetProperty("verified").GetBoolean());

        var dns = json.GetProperty("verification").GetProperty("dns");
        Assert.Equal("TXT", dns.GetProperty("type").GetString());
        Assert.Equal("_shadowaudit-verify.www.mi-sitio-prueba.com", dns.GetProperty("name").GetString());
        Assert.StartsWith("shadowaudit-verify=", dns.GetProperty("value").GetString());

        var file = json.GetProperty("verification").GetProperty("file");
        Assert.Equal("https://www.mi-sitio-prueba.com/.well-known/shadowaudit-verify.txt", file.GetProperty("url").GetString());
        Assert.Equal(43, file.GetProperty("content").GetString()!.Length);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("https://example.com")]
    [InlineData("192.168.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("mi.local")]
    [InlineData("a b.com")]
    [InlineData("")]
    public async Task Dominios_invalidos_se_rechazan_con_400(string host)
    {
        var owner = await NewOwnerAsync();

        var response = await Api(owner).PostAsJsonAsync("/api/sites", new { host });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task El_mismo_sitio_dos_veces_da_409_aunque_cambie_la_capitalizacion()
    {
        var owner = await NewOwnerAsync();
        var host = NewHost();
        await AddSiteAsync(owner, host);

        var repetido = await Api(owner).PostAsJsonAsync("/api/sites", new { host = host.ToUpperInvariant() });

        Assert.Equal(HttpStatusCode.Conflict, repetido.StatusCode);
    }

    [Fact]
    public async Task Otro_usuario_puede_registrar_el_mismo_dominio()
    {
        var a = await NewOwnerAsync();
        var b = await NewOwnerAsync();
        var host = NewHost();

        await AddSiteAsync(a, host);
        var site = await AddSiteAsync(b, host);

        Assert.Equal(host, site.Host);
    }

    [Fact]
    public async Task El_limite_es_de_5_sitios_por_usuario()
    {
        var owner = await NewOwnerAsync();
        for (var i = 0; i < 5; i++) await AddSiteAsync(owner);

        var sexto = await Api(owner).PostAsJsonAsync("/api/sites", new { host = NewHost() });

        Assert.Equal(HttpStatusCode.Conflict, sexto.StatusCode);
    }

    [Fact]
    public async Task La_lista_solo_muestra_los_sitios_propios()
    {
        var a = await NewOwnerAsync();
        var b = await NewOwnerAsync();
        var hostA = NewHost();
        await AddSiteAsync(a, hostA);
        await AddSiteAsync(b);

        var json = await (await Api(a).GetAsync("/api/sites")).Json();

        Assert.Equal(1, json.GetProperty("total").GetInt32());
        Assert.Equal(hostA, json.GetProperty("items")[0].GetProperty("host").GetString());
        Assert.False(json.GetProperty("items")[0].GetProperty("verified").GetBoolean());
    }

    [Fact]
    public async Task Verificar_sin_registro_ni_archivo_da_400_con_instrucciones_y_prueba_dos_urls()
    {
        var owner = await NewOwnerAsync();
        var site = await AddSiteAsync(owner);

        var response = await Api(owner).PostAsync($"/api/sites/{site.Id}/verify", null);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Json();
        Assert.False(json.GetProperty("verified").GetBoolean());
        Assert.True(json.TryGetProperty("verification", out _));
        Assert.Equal(2, _f.SiteHandler.Sent.Count(r => r.Uri.Host == site.Host));
    }

    [Fact]
    public async Task Escanear_un_sitio_sin_verificar_da_403_y_no_hace_ninguna_peticion()
    {
        var owner = await NewOwnerAsync();
        var site = await AddSiteAsync(owner);

        var response = await ScanAsync(owner, site.Id);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.DoesNotContain(_f.SiteHandler.Sent, r => r.Uri.Host == site.Host);
        Assert.DoesNotContain(_f.Tls.Inspected, h => h == site.Host);
    }

    [Fact]
    public async Task Verifica_por_dns_y_el_sitio_queda_verificado()
    {
        var owner = await NewOwnerAsync();
        var site = await AddSiteAsync(owner);
        _f.Dns.Records[OwnershipVerifier.DnsName(site.Host)] =
            new List<string> { OwnershipVerifier.DnsValue(site.SiteToken) };

        var response = await Api(owner).PostAsync($"/api/sites/{site.Id}/verify", null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Json();
        Assert.True(json.GetProperty("verified").GetBoolean());
        Assert.Equal("dns", json.GetProperty("method").GetString());

        var lista = await (await Api(owner).GetAsync("/api/sites")).Json();
        Assert.True(lista.GetProperty("items")[0].GetProperty("verified").GetBoolean());
    }

    [Fact]
    public async Task Verifica_por_archivo()
    {
        var owner = await NewOwnerAsync();
        var site = await AddSiteAsync(owner);
        _f.SiteResponder = r => r.Uri.ToString() == OwnershipVerifier.FileUrl(site.Host)
            ? FakeSites.Response(HttpStatusCode.OK, site.SiteToken)
            : FakeSites.Healthy(r);

        var response = await Api(owner).PostAsync($"/api/sites/{site.Id}/verify", null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("archivo", (await response.Json()).GetProperty("method").GetString());
    }

    [Fact]
    public async Task La_verificacion_vence_a_los_30_dias()
    {
        var owner = await NewOwnerAsync();
        var site = await AddVerifiedSiteAsync(owner);

        using (var scope = _f.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShadowAuditDbContext>();
            await db.Sites.Where(s => s.Id == site.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.VerifiedAtUtc, (DateTime?)DateTime.UtcNow.AddDays(-31)));
        }

        Assert.Equal(HttpStatusCode.Forbidden, (await ScanAsync(owner, site.Id)).StatusCode);

        var lista = await (await Api(owner).GetAsync("/api/sites")).Json();
        Assert.False(lista.GetProperty("items")[0].GetProperty("verified").GetBoolean());
    }

    [Fact]
    public async Task Escanear_sin_etiqueta_no_guarda_nada()
    {
        var owner = await NewOwnerAsync();
        var site = await AddVerifiedSiteAsync(owner);

        var response = await ScanAsync(owner, site.Id);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Json();
        Assert.Equal("bajo", json.GetProperty("risk").GetString());
        Assert.Equal(0, json.GetProperty("failed").GetInt32());
        Assert.True(json.GetProperty("checks").GetArrayLength() > 0);
        Assert.Equal(JsonValueKind.Null, json.GetProperty("finding").ValueKind);

        var hallazgos = await (await Api(owner).GetAsync("/api/findings")).Json();
        Assert.Equal(0, hallazgos.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Escanear_con_etiqueta_guarda_un_hallazgo_web_y_cuenta_en_el_reporte()
    {
        var owner = await NewOwnerAsync();
        var site = await AddVerifiedSiteAsync(owner);
        _f.SiteResponder = r => r.Uri.Scheme == "https" && r.Uri.AbsolutePath == "/.env"
            ? FakeSites.Response(HttpStatusCode.OK, "DB_PASSWORD=secreto123")
            : FakeSites.Healthy(r);

        var response = await ScanAsync(owner, site.Id, "mi sitio web");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Json();
        Assert.Equal("alto", json.GetProperty("risk").GetString());
        Assert.True(json.GetProperty("finding").GetProperty("saved").GetBoolean());
        Assert.DoesNotContain("secreto123", json.ToString());

        var hallazgos = await (await Api(owner).GetAsync("/api/findings")).Json();
        var item = hallazgos.GetProperty("items")[0];
        Assert.Equal("web", item.GetProperty("source").GetString());
        Assert.Equal("alto", item.GetProperty("risk").GetString());
        Assert.Equal("mi sitio web", item.GetProperty("label").GetString());
        Assert.DoesNotContain(site.Host, item.ToString());

        var reporte = await (await Api(owner).GetAsync("/api/report")).Json();
        Assert.Equal(50, reporte.GetProperty("score").GetDouble());
    }

    [Fact]
    public async Task Una_etiqueta_con_el_dominio_se_rechaza_antes_de_escanear()
    {
        var owner = await NewOwnerAsync();
        var site = await AddVerifiedSiteAsync(owner);

        var response = await ScanAsync(owner, site.Id, "revisar " + site.Host);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain(_f.Tls.Inspected, h => h == site.Host);
        Assert.DoesNotContain(_f.SiteHandler.Sent, r => r.Uri.Host == site.Host);
    }

    [Fact]
    public async Task Una_etiqueta_de_mas_de_100_caracteres_se_rechaza()
    {
        var owner = await NewOwnerAsync();
        var site = await AddVerifiedSiteAsync(owner);

        var response = await ScanAsync(owner, site.Id, new string('a', 101));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Un_sitio_sin_https_se_reporta_como_riesgo_alto()
    {
        var owner = await NewOwnerAsync();
        var site = await AddVerifiedSiteAsync(owner);
        _f.Tls.Respond = _ => new TlsInfo(false, SslProtocols.None, null, SslPolicyErrors.None);

        var response = await ScanAsync(owner, site.Id);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("alto", (await response.Json()).GetProperty("risk").GetString());
    }

    [Fact]
    public async Task Los_sitios_de_otro_usuario_dan_404()
    {
        var duenio = await NewOwnerAsync();
        var otro = await NewOwnerAsync();
        var site = await AddVerifiedSiteAsync(duenio);

        Assert.Equal(HttpStatusCode.NotFound, (await Api(otro).PostAsync($"/api/sites/{site.Id}/verify", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await ScanAsync(otro, site.Id)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Api(otro).DeleteAsync($"/api/sites/{site.Id}")).StatusCode);

        var lista = await (await Api(duenio).GetAsync("/api/sites")).Json();
        Assert.Equal(1, lista.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Borrar_un_sitio_funciona_una_sola_vez()
    {
        var owner = await NewOwnerAsync();
        var site = await AddSiteAsync(owner);

        Assert.Equal(HttpStatusCode.OK, (await Api(owner).DeleteAsync($"/api/sites/{site.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Api(owner).DeleteAsync($"/api/sites/{site.Id}")).StatusCode);

        var lista = await (await Api(owner).GetAsync("/api/sites")).Json();
        Assert.Equal(0, lista.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Escanear_tiene_limite_de_3_por_hora_por_ip()
    {
        var owner = await NewOwnerAsync();
        var site = await AddVerifiedSiteAsync(owner);
        var ip = TestApiFactory.NextIp();

        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.OK, (await ScanAsync(owner, site.Id, null, ip)).StatusCode);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await ScanAsync(owner, site.Id, null, ip)).StatusCode);
    }

    [Fact]
    public async Task Verificar_tiene_limite_de_10_cada_10_minutos_por_ip()
    {
        var owner = await NewOwnerAsync();
        var site = await AddSiteAsync(owner);
        var ip = TestApiFactory.NextIp();

        for (var i = 0; i < 10; i++)
            Assert.Equal(HttpStatusCode.BadRequest, (await Api(owner, ip).PostAsync($"/api/sites/{site.Id}/verify", null)).StatusCode);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await Api(owner, ip).PostAsync($"/api/sites/{site.Id}/verify", null)).StatusCode);
    }

    [Fact]
    public async Task El_registro_de_auditoria_guarda_las_acciones_pero_no_el_dominio()
    {
        var owner = await NewOwnerAsync();
        var site = await AddVerifiedSiteAsync(owner);
        await ScanAsync(owner, site.Id);

        using var scope = _f.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ShadowAuditDbContext>();
        var logs = await db.AuditLogs.Where(a => a.Email == owner.User.Email).ToListAsync();
        var acciones = logs.Select(a => a.Action).ToList();

        Assert.Contains("SiteAdd", acciones);
        Assert.Contains("SiteVerify", acciones);
        Assert.Contains("SiteScan", acciones);
        Assert.DoesNotContain(logs, a => (a.Action + a.UserAgent).Contains(site.Host));
    }
}