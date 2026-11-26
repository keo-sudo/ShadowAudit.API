using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Unit;

public class IotAuditTests
{
    [Fact]
    public void Telnet_abierto_es_riesgo_alto()
    {
        var result = IotAudit.Analyze("23/tcp   open  telnet\n80/tcp   open  http");

        Assert.Equal(RiskLevels.High, result.Risk);
        Assert.Equal(23, Assert.Single(result.Findings).Port);
    }

    [Fact]
    public void Solo_puertos_medios_dan_riesgo_medio()
    {
        var result = IotAudit.Analyze("554/tcp  open  rtsp");

        Assert.Equal(RiskLevels.Medium, result.Risk);
    }

    [Fact]
    public void Puertos_normales_no_se_marcan()
    {
        var result = IotAudit.Analyze("80/tcp   open  http\n443/tcp  open  https");

        Assert.Equal(RiskLevels.Low, result.Risk);
        Assert.Empty(result.Findings);
    }
}