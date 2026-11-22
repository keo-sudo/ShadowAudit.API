using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Unit;

public class JwtServiceTests
{
    private static JwtService CreateService()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["JwtSettings:SecretKey"] = "clave-falsa-solo-para-pruebas-automaticas-no-es-un-secreto-0123456789",
                ["JwtSettings:Issuer"] = "ShadowAudit.API",
                ["JwtSettings:Audience"] = "ShadowAudit.Users",
                ["JwtSettings:ExpiryMinutes"] = "15"
            })
            .Build();

        return new JwtService(config);
    }

    [Fact]
    public void The_token_carries_the_user_and_the_session()
    {
        var user = new User { Username = "ana", Email = "ana@test.com" };
        var sessionId = Guid.NewGuid();

        var result = CreateService().GenerateToken(user, sessionId);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(result.Token);

        Assert.Equal(user.Id.ToString(), jwt.Subject);
        Assert.Equal(sessionId.ToString(), jwt.Claims.First(c => c.Type == "session_id").Value);
        Assert.Equal("ShadowAudit.API", jwt.Issuer);
        Assert.Contains("ShadowAudit.Users", jwt.Audiences);
    }

    [Fact]
    public void The_access_token_lasts_15_minutes()
    {
        var result = CreateService().GenerateToken(new User { Username = "ana", Email = "ana@test.com" }, Guid.NewGuid());

        Assert.InRange(result.ExpiresAt, DateTime.UtcNow.AddMinutes(14), DateTime.UtcNow.AddMinutes(16));
    }

    [Fact]
    public void Each_token_has_its_own_identifier()
    {
        var service = CreateService();
        var user = new User { Username = "ana", Email = "ana@test.com" };
        var sessionId = Guid.NewGuid();

        var first = new JwtSecurityTokenHandler().ReadJwtToken(service.GenerateToken(user, sessionId).Token);
        var second = new JwtSecurityTokenHandler().ReadJwtToken(service.GenerateToken(user, sessionId).Token);

        Assert.NotEqual(first.Id, second.Id);
    }
}
