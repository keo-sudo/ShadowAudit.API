using System.Net;
using System.Net.Http.Json;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Integration;

[Collection("api")]
public class FootprintTests
{
    private readonly TestApiFactory _f;

    public FootprintTests(ApiFixture fixture)
    {
        _f = fixture.Factory;
        _f.SiteResponder = FakeSites.Healthy;
        _f.SiteHandler.Sent.Clear();
    }

    private async Task<string> NewTokenAsync()
    {
        var client = _f.NewClient();
        var user = TestUser.New();
        (await client.Register(user)).EnsureSuccessStatusCode();
        return (await client.LoginOk(user)).Token;
    }

    private Task<HttpResponseMessage> Check(string token, string username, string? label = null, string? ip = null) =>
        _f.NewClient(ip).Bearer(token).PostAsJsonAsync("/api/footprint/username", new { username, label });

    [Fact]
    public async Task Exige_login()
    {
        var response = await _f.NewClient().PostAsJsonAsync("/api/footprint/username", new { username = "keo" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("../x")]
    [InlineData("a b")]
    [InlineData(".oculto")]
    [InlineData("")]
    public async Task Usuarios_invalidos_dan_400_y_no_hacen_peticiones(string username)
    {
        var token = await NewTokenAsync();

        var response = await Check(token, username);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_f.SiteHandler.Sent);
    }

    [Fact]
    public async Task Sin_etiqueta_responde_y_no_guarda_nada()
    {
        var token = await NewTokenAsync();

        var response = await Check(token, "keo-prueba");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Json();
        Assert.Equal(5, json.GetProperty("results").GetArrayLength());
        Assert.Equal("bajo", json.GetProperty("risk").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, json.GetProperty("finding").ValueKind);

        var hallazgos = await (await _f.NewClient().Bearer(token).GetAsync("/api/findings")).Json();
        Assert.Equal(0, hallazgos.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Con_etiqueta_guarda_un_hallazgo_footprint_sin_el_usuario()
    {
        var token = await NewTokenAsync();
        _f.SiteResponder = _ => FakeSites.Response(HttpStatusCode.OK);

        var response = await Check(token, "keo-prueba", "mis perfiles");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Json();
        Assert.Equal("medio", json.GetProperty("risk").GetString());
        Assert.True(json.GetProperty("finding").GetProperty("saved").GetBoolean());

        var hallazgos = await (await _f.NewClient().Bearer(token).GetAsync("/api/findings")).Json();
        var item = hallazgos.GetProperty("items")[0];
        Assert.Equal("footprint", item.GetProperty("source").GetString());
        Assert.DoesNotContain("keo-prueba", item.ToString());
    }

    [Fact]
    public async Task Una_etiqueta_con_el_usuario_se_rechaza_antes_de_consultar()
    {
        var token = await NewTokenAsync();

        var response = await Check(token, "keo-prueba", "perfil de keo-prueba");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_f.SiteHandler.Sent);
    }

    [Fact]
    public async Task Tiene_limite_de_5_consultas_por_hora_por_ip()
    {
        var token = await NewTokenAsync();
        var ip = TestApiFactory.NextIp();

        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.OK, (await Check(token, "keo-prueba", null, ip)).StatusCode);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await Check(token, "keo-prueba", null, ip)).StatusCode);
    }
}