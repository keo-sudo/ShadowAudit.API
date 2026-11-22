using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Integration;

[Collection("api")]
public class FindingsTests
{
    private readonly TestApiFactory _f;

    public FindingsTests(ApiFixture fixture)
    {
        _f = fixture.Factory;
    }

    private async Task<HttpClient> NewAuthedClient()
    {
        var ip = TestApiFactory.NextIp();
        var user = TestUser.New();
        var anonymous = _f.NewClient(ip);
        await anonymous.Register(user);
        var session = await anonymous.LoginOk(user);
        return _f.NewClient(ip).Bearer(session.Token);
    }

    private static async Task<string> SaveAndGetId(HttpClient client, string label)
    {
        var response = await client.SaveEmailFinding(label);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Json();
        return json.GetProperty("finding").GetProperty("id").GetString()!;
    }

    private static async Task<JsonElement> Report(HttpClient client)
    {
        var response = await client.GetAsync("/api/report");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Json();
    }

    [Fact]
    public async Task An_empty_report_has_score_zero_and_no_findings()
    {
        var client = await NewAuthedClient();

        var report = await Report(client);

        Assert.Equal(0, report.GetProperty("score").GetInt32());
        Assert.Equal("sin_hallazgos", report.GetProperty("level").GetString());
        Assert.Equal(0, report.GetProperty("totals").GetProperty("open").GetInt32());
    }

    [Fact]
    public async Task Without_a_label_nothing_is_saved()
    {
        var client = await NewAuthedClient();

        var response = await client.SaveEmailFinding(null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(JsonValueKind.Null, (await response.Json()).GetProperty("finding").ValueKind);

        var list = await (await client.GetAsync("/api/findings")).Json();
        Assert.Equal(0, list.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task With_a_label_the_server_saves_the_finding_with_the_risk_it_calculated()
    {
        var client = await NewAuthedClient();

        var response = await client.SaveEmailFinding("correo del banco");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Json();
        var finding = json.GetProperty("finding");

        Assert.True(finding.GetProperty("saved").GetBoolean());
        Assert.Equal("alto", finding.GetProperty("risk").GetString());
        Assert.Equal(json.GetProperty("risk").GetString(), finding.GetProperty("risk").GetString());

        var list = await (await client.GetAsync("/api/findings")).Json();
        Assert.Equal(1, list.GetProperty("total").GetInt32());
        Assert.Equal("correo del banco", list.GetProperty("items")[0].GetProperty("label").GetString());
    }

    [Fact]
    public async Task The_score_follows_the_formula_and_resolving_lowers_it()
    {
        var client = await NewAuthedClient();

        var firstId = await SaveAndGetId(client, "primer correo");
        var one = await Report(client);
        Assert.Equal(50, one.GetProperty("score").GetInt32());
        Assert.Equal("alto", one.GetProperty("level").GetString());

        await SaveAndGetId(client, "segundo correo");
        var two = await Report(client);
        Assert.Equal(75, two.GetProperty("score").GetInt32());
        Assert.Equal("critico", two.GetProperty("level").GetString());
        Assert.Equal(2, two.GetProperty("totals").GetProperty("alto").GetInt32());

        var resolve = await client.PostAsync($"/api/findings/{firstId}/resolve", null);
        Assert.Equal(HttpStatusCode.OK, resolve.StatusCode);

        var after = await Report(client);
        Assert.Equal(50, after.GetProperty("score").GetInt32());
        Assert.Equal(1, after.GetProperty("totals").GetProperty("open").GetInt32());
        Assert.Equal(1, after.GetProperty("totals").GetProperty("resolved").GetInt32());
        Assert.NotEmpty(after.GetProperty("recommendations").EnumerateArray());
    }

    [Fact]
    public async Task Resolving_twice_gives_conflict_and_an_unknown_id_gives_not_found()
    {
        var client = await NewAuthedClient();
        var id = await SaveAndGetId(client, "correo sospechoso");

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync($"/api/findings/{id}/resolve", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsync($"/api/findings/{id}/resolve", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await client.PostAsync($"/api/findings/{Guid.NewGuid()}/resolve", null)).StatusCode);
    }

    [Fact]
    public async Task Resolved_findings_are_hidden_from_the_list_unless_requested()
    {
        var client = await NewAuthedClient();
        var id = await SaveAndGetId(client, "correo sospechoso");
        await client.PostAsync($"/api/findings/{id}/resolve", null);

        var open = await (await client.GetAsync("/api/findings")).Json();
        var all = await (await client.GetAsync("/api/findings?includeResolved=true")).Json();

        Assert.Equal(0, open.GetProperty("total").GetInt32());
        Assert.Equal(1, all.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Deleting_a_finding_removes_it()
    {
        var client = await NewAuthedClient();
        var id = await SaveAndGetId(client, "correo sospechoso");

        Assert.Equal(HttpStatusCode.OK, (await client.DeleteAsync($"/api/findings/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync($"/api/findings/{id}")).StatusCode);

        var list = await (await client.GetAsync("/api/findings?includeResolved=true")).Json();
        Assert.Equal(0, list.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Findings_are_private_to_each_user()
    {
        var owner = await NewAuthedClient();
        var intruder = await NewAuthedClient();
        var id = await SaveAndGetId(owner, "correo del banco");

        var intruderList = await (await intruder.GetAsync("/api/findings?includeResolved=true")).Json();
        Assert.Equal(0, intruderList.GetProperty("total").GetInt32());

        var intruderReport = await Report(intruder);
        Assert.Equal(0, intruderReport.GetProperty("score").GetInt32());

        Assert.Equal(HttpStatusCode.NotFound, (await intruder.PostAsync($"/api/findings/{id}/resolve", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await intruder.DeleteAsync($"/api/findings/{id}")).StatusCode);

        var ownerList = await (await owner.GetAsync("/api/findings")).Json();
        Assert.Equal(1, ownerList.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task A_label_longer_than_100_characters_is_rejected()
    {
        var client = await NewAuthedClient();

        var response = await client.SaveEmailFinding(new string('x', 101));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_label_with_control_characters_is_rejected()
    {
        var client = await NewAuthedClient();

        var response = await client.SaveEmailFinding("hola\nmundo");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_password_check_label_cannot_contain_the_password()
    {
        var client = await NewAuthedClient();

        // Se rechaza ANTES de consultar a Have I Been Pwned, asi que no usa internet
        var response = await client.PostAsJsonAsync("/api/passwords/check",
            new { password = "Secreta12345", label = "mi clave Secreta12345" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
