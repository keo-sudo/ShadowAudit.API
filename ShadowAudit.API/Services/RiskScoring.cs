namespace ShadowAudit.API.Services;

// Puntaje de exposición de 0 a 100 (más alto = más expuesto).
// Cada hallazgo sin resolver aporta una "probabilidad de problema" y se combinan así:
// puntaje = 100 x (1 - producto de (1 - peso)). Un hallazgo alto solo ya da 50.
public static class RiskScoring
{
    private static double Weight(string risk) => risk switch
    {
        RiskLevels.High => 0.50,
        RiskLevels.Medium => 0.20,
        _ => 0.05
    };

    public static int Score(IEnumerable<string> unresolvedRisks)
    {
        var safe = 1.0;
        foreach (var risk in unresolvedRisks)
            safe *= 1 - Weight(risk);

        return (int)Math.Round((1 - safe) * 100, MidpointRounding.AwayFromZero);
    }

    public static string Level(int score) => score switch
    {
        >= 75 => "critico",
        >= 50 => "alto",
        >= 25 => "medio",
        _ => "bajo"
    };
}