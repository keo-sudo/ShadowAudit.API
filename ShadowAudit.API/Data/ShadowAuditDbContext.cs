using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Data;

public class ShadowAuditDbContext : DbContext
{
    public ShadowAuditDbContext(DbContextOptions<ShadowAuditDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    public DbSet<RecoveryCode> RecoveryCodes => Set<RecoveryCode>();

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    public DbSet<ExposureFinding> ExposureFindings => Set<ExposureFinding>();

    public DbSet<Site> Sites => Set<Site>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(e =>
        {
            e.HasIndex(u => u.Email).IsUnique();
            e.HasIndex(u => u.Username).IsUnique();
        });

        modelBuilder.Entity<AuditLog>(e =>
        {
            e.HasIndex(a => a.UserId);
            e.HasIndex(a => a.CreatedAt);
            e.Property(a => a.Email).HasMaxLength(256);
            e.Property(a => a.Action).HasMaxLength(50);
            e.Property(a => a.IpAddress).HasMaxLength(64);
            e.Property(a => a.UserAgent).HasMaxLength(256);
        });

        modelBuilder.Entity<RecoveryCode>(e =>
        {
            e.Property(r => r.CodeHash).HasMaxLength(64).IsRequired();
            e.HasIndex(r => new { r.UserId, r.CodeHash });
            e.HasOne<User>()
                .WithMany()
                .HasForeignKey(r => r.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<RefreshToken>(e =>
        {
            e.Property(r => r.TokenHash).HasMaxLength(64).IsRequired();
            e.HasIndex(r => r.TokenHash).IsUnique();
            e.HasIndex(r => r.FamilyId);
            e.HasIndex(r => r.UserId);
            e.HasOne<User>()
                .WithMany()
                .HasForeignKey(r => r.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ExposureFinding>(e =>
        {
            e.Property(f => f.Source).HasMaxLength(20).IsRequired();
            e.Property(f => f.Risk).HasMaxLength(10).IsRequired();
            e.Property(f => f.Label).HasMaxLength(100).IsRequired();
            e.HasIndex(f => new { f.UserId, f.ResolvedAtUtc });
            e.HasOne<User>()
                .WithMany()
                .HasForeignKey(f => f.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Site>(e =>
        {
            e.Property(s => s.Host).HasMaxLength(253).IsRequired();
            e.Property(s => s.VerificationToken).HasMaxLength(64).IsRequired();
            e.HasIndex(s => new { s.UserId, s.Host }).IsUnique();
            e.HasOne<User>()
                .WithMany()
                .HasForeignKey(s => s.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}