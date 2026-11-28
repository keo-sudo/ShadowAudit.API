using System.Text;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Unit;

public class ExifAuditTests
{
    private static readonly DateTime Fecha = new(2026, 11, 1, 10, 30, 0);

    [Fact]
    public void Con_gps_el_riesgo_es_alto_y_da_enlace_al_mapa()
    {
        var r = ExifAudit.Build(-12.0464, -77.0428, "Apple", "iPhone 13", Fecha, null);

        Assert.True(r.HasGps);
        Assert.Equal("alto", r.Risk);
        Assert.Contains("-12.046400,-77.042800", r.MapUrl);
    }

    [Fact]
    public void Sin_gps_pero_con_modelo_y_fecha_el_riesgo_es_bajo()
    {
        var r = ExifAudit.Build(null, null, "Apple", "iPhone 13", Fecha, null);

        Assert.False(r.HasGps);
        Assert.Equal(RiskLevels.Low, r.Risk);
        Assert.Equal("Apple iPhone 13", r.Device);
    }

    [Fact]
    public void Con_nombre_de_autor_sube_a_medio()
    {
        var r = ExifAudit.Build(null, null, null, null, null, "Renzo");

        Assert.Equal(RiskLevels.Medium, r.Risk);
    }

    [Fact]
    public void Coordenadas_0_0_se_ignoran()
    {
        var r = ExifAudit.Build(0, 0, null, null, null, null);

        Assert.False(r.HasGps);
        Assert.Null(r.MapUrl);
    }

    [Fact]
    public void Un_archivo_que_no_es_imagen_se_rechaza()
    {
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes("esto no es una imagen"));

        Assert.False(ExifAudit.TryAnalyze(ms, out var result));
        Assert.Null(result);
    }
}