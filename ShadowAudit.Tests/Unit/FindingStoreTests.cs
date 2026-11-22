using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Unit;

public class FindingStoreTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("    ")]
    public void An_empty_label_is_allowed_and_means_do_not_save(string? raw)
    {
        var error = FindingStore.ValidateLabel(raw, out var label);

        Assert.Null(error);
        Assert.Null(label);
    }

    [Fact]
    public void The_label_is_trimmed()
    {
        var error = FindingStore.ValidateLabel("  correo del banco  ", out var label);

        Assert.Null(error);
        Assert.Equal("correo del banco", label);
    }

    [Fact]
    public void A_label_of_exactly_100_characters_is_accepted()
    {
        var error = FindingStore.ValidateLabel(new string('x', 100), out var label);

        Assert.Null(error);
        Assert.NotNull(label);
    }

    [Fact]
    public void A_label_longer_than_100_characters_is_rejected()
    {
        var error = FindingStore.ValidateLabel(new string('x', 101), out var label);

        Assert.NotNull(error);
        Assert.Null(label);
    }

    [Theory]
    [InlineData("hola\nmundo")]
    [InlineData("hola\tmundo")]
    [InlineData("hola\u0007mundo")]
    public void Control_characters_are_rejected(string raw)
    {
        var error = FindingStore.ValidateLabel(raw, out var label);

        Assert.NotNull(error);
        Assert.Null(label);
    }

    [Theory]
    [InlineData("mi clave Secreta12345")]
    [InlineData("MI CLAVE SECRETA12345")]
    public void The_label_cannot_contain_the_consulted_data(string raw)
    {
        var error = FindingStore.ValidateLabel(raw, out var label, "Secreta12345");

        Assert.NotNull(error);
        Assert.Null(label);
    }

    [Fact]
    public void Very_short_sensitive_values_are_ignored_to_avoid_false_positives()
    {
        var error = FindingStore.ValidateLabel("abc de prueba", out var label, "abc");

        Assert.Null(error);
        Assert.Equal("abc de prueba", label);
    }

    [Fact]
    public void Null_or_empty_sensitive_values_are_ignored()
    {
        var error = FindingStore.ValidateLabel("correo del banco", out var label, new string?[] { null, "" });

        Assert.Null(error);
        Assert.Equal("correo del banco", label);
    }
}
