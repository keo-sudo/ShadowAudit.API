using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Unit;

public class RiskNormalizerTests
{
    [Theory]
    [InlineData("alto", "alto")]
    [InlineData("ALTO", "alto")]
    [InlineData("  alto  ", "alto")]
    [InlineData("high", "alto")]
    [InlineData("medio", "medio")]
    [InlineData("medium", "medio")]
    [InlineData("bajo", "bajo")]
    [InlineData("sin_detecciones", "bajo")]
    [InlineData("", "bajo")]
    [InlineData(null, "bajo")]
    public void FromText_unifies_the_risk_of_each_service(string? input, string expected)
    {
        Assert.Equal(expected, RiskNormalizer.FromText(input));
    }

    [Theory]
    [InlineData(0, false, "alto")]
    [InlineData(1, false, "alto")]
    [InlineData(2, false, "medio")]
    [InlineData(3, false, "bajo")]
    [InlineData(4, false, "bajo")]
    [InlineData(4, true, "alto")]
    [InlineData(3, null, "bajo")]
    public void FromPassword_uses_strength_and_breaches(int score, bool? breached, string expected)
    {
        Assert.Equal(expected, RiskNormalizer.FromPassword(score, breached));
    }

    [Fact]
    public void A_breached_password_is_always_high_risk_even_if_it_looks_strong()
    {
        Assert.Equal("alto", RiskNormalizer.FromPassword(4, true));
    }

    [Fact]
    public void Rank_orders_high_above_medium_above_low()
    {
        Assert.True(RiskLevels.Rank("alto") > RiskLevels.Rank("medio"));
        Assert.True(RiskLevels.Rank("medio") > RiskLevels.Rank("bajo"));
        Assert.Equal(RiskLevels.Rank("bajo"), RiskLevels.Rank("desconocido"));
    }
}
