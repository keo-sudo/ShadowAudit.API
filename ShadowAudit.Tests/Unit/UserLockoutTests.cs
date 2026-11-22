using ShadowAudit.API.Models;

namespace ShadowAudit.Tests.Unit;

public class UserLockoutTests
{
    [Fact]
    public void A_new_user_is_not_locked()
    {
        Assert.False(new User().IsLocked);
    }

    [Fact]
    public void Four_failed_attempts_do_not_lock_the_account()
    {
        var user = new User();

        for (var i = 0; i < User.MaxFailedAttempts - 1; i++)
            user.RegisterFailedAttempt();

        Assert.False(user.IsLocked);
        Assert.Equal(User.MaxFailedAttempts - 1, user.FailedLoginAttempts);
    }

    [Fact]
    public void The_fifth_failed_attempt_locks_the_account_for_15_minutes()
    {
        var user = new User();

        for (var i = 0; i < User.MaxFailedAttempts; i++)
            user.RegisterFailedAttempt();

        Assert.True(user.IsLocked);
        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.InRange(user.LockedUntil!.Value,
            DateTime.UtcNow.AddMinutes(14), DateTime.UtcNow.AddMinutes(16));
    }

    [Fact]
    public void Clearing_the_attempts_unlocks_the_account()
    {
        var user = new User();
        for (var i = 0; i < User.MaxFailedAttempts; i++)
            user.RegisterFailedAttempt();

        user.ClearFailedAttempts();

        Assert.False(user.IsLocked);
        Assert.Null(user.LockedUntil);
        Assert.Equal(0, user.FailedLoginAttempts);
    }
}
