using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Unit;

public class RiskScoringTests
{
    [Fact]
    public void Without_findings_the_score_is_zero()
    {
        Assert.Equal(0, RiskScoring.Score(Array.Empty<string>()));
    }

    [Theory]
    [InlineData(new[] { "alto" }, 50)]
    [InlineData(new[] { "alto", "alto" }, 75)]
    [InlineData(new[] { "alto", "alto", "alto" }, 88)]
    [InlineData(new[] { "medio" }, 20)]
    [InlineData(new[] { "medio", "medio" }, 36)]
    [InlineData(new[] { "bajo" }, 5)]
    [InlineData(new[] { "bajo", "bajo", "bajo" }, 14)]
    [InlineData(new[] { "alto", "medio" }, 60)]
    [InlineData(new[] { "cualquier-cosa" }, 5)]
    public void Score_combines_risks_with_the_documented_formula(string[] risks, int expected)
    {
        Assert.Equal(expected, RiskScoring.Score(risks));
    }

    [Fact]
    public void The_order_of_the_findings_does_not_change_the_score()
    {
        var a = RiskScoring.Score(new[] { "alto", "medio", "bajo" });
        var b = RiskScoring.Score(new[] { "bajo", "alto", "medio" });

        Assert.Equal(a, b);
    }

    [Theory]
    [InlineData(0, "bajo")]
    [InlineData(24, "bajo")]
    [InlineData(25, "medio")]
    [InlineData(49, "medio")]
    [InlineData(50, "alto")]
    [InlineData(74, "alto")]
    [InlineData(75, "critico")]
    [InlineData(100, "critico")]
    public void Level_follows_the_documented_thresholds(int score, string expected)
    {
        Assert.Equal(expected, RiskScoring.Level(score));
    }
}
