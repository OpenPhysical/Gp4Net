using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Domain;

/// <summary>
/// Represents the complete content of a GlobalPlatform card.
/// Aggregates all entities retrieved from multiple GET STATUS commands.
/// </summary>
public record CardContent(
    Maybe<ApplicationInfo> IssuerSecurityDomain,
    ImmutableList<ApplicationInfo> Applications,
    ImmutableList<ApplicationInfo> SecurityDomains,
    ImmutableList<ExecutableLoadFile> ExecutableLoadFiles
)
{
    /// <summary>
    /// Gets all applications and security domains combined.
    /// </summary>
    public ImmutableList<ApplicationInfo> AllApplications => Applications.AddRange(SecurityDomains);

    /// <summary>
    /// Gets all entities (ISD, apps, SSDs, load files) as a unified collection for display.
    /// </summary>
    public ImmutableList<CardEntity> AllEntities
    {
        get
        {
            var entities = ImmutableList.CreateBuilder<CardEntity>();

            // Add ISD first
            IssuerSecurityDomain.Execute(isd =>
                entities.Add(new CardEntity.IssuerSecurityDomainEntity(isd))
            );

            // Add security domains
            foreach (var ssd in SecurityDomains)
            {
                entities.Add(new CardEntity.SecurityDomainEntity(ssd));
            }

            // Add applications
            foreach (var app in Applications)
            {
                entities.Add(new CardEntity.ApplicationEntity(app));
            }

            // Add load files
            foreach (var loadFile in ExecutableLoadFiles)
            {
                entities.Add(new CardEntity.LoadFileEntity(loadFile));
            }

            return entities.ToImmutable();
        }
    }

    /// <summary>
    /// Gets summary counts for each entity type.
    /// </summary>
    public CardContentSummary Summary =>
        new(
            HasIsd: IssuerSecurityDomain.HasValue,
            SecurityDomainCount: SecurityDomains.Count,
            ApplicationCount: Applications.Count,
            LoadFileCount: ExecutableLoadFiles.Count,
            ModuleCount: ExecutableLoadFiles.Sum(lf => lf.ModuleCount)
        );

    /// <summary>
    /// Gets applications by their type.
    /// </summary>
    public ImmutableList<ApplicationInfo> GetApplicationsByType(ApplicationType type)
    {
        return [.. AllApplications.Where(app => app.Type == type)];
    }

    /// <summary>
    /// Gets applications by their lifecycle state.
    /// </summary>
    public ImmutableList<ApplicationInfo> GetApplicationsByState(byte rawLifecycleState)
    {
        return [.. AllApplications.Where(app => app.RawLifecycleState == rawLifecycleState)];
    }

    /// <summary>
    /// Gets executable load files by their lifecycle state.
    /// </summary>
    public ImmutableList<ExecutableLoadFile> GetLoadFilesByState(
        ExecutableLoadFileLifecycleState state
    )
    {
        return [.. ExecutableLoadFiles.Where(lf => lf.LifecycleState == state)];
    }

    /// <summary>
    /// Checks if the card has any selectable applications.
    /// </summary>
    public bool HasSelectableApplications => AllApplications.Any(app => app.IsSelectable);

    /// <summary>
    /// Creates an empty CardContent instance.
    /// </summary>
    public static CardContent Empty =>
        new(
            IssuerSecurityDomain: Maybe<ApplicationInfo>.None,
            Applications: ImmutableList<ApplicationInfo>.Empty,
            SecurityDomains: ImmutableList<ApplicationInfo>.Empty,
            ExecutableLoadFiles: ImmutableList<ExecutableLoadFile>.Empty
        );
}

/// <summary>
/// Summary information about card content.
/// </summary>
public record CardContentSummary(
    bool HasIsd,
    int SecurityDomainCount,
    int ApplicationCount,
    int LoadFileCount,
    int ModuleCount
)
{
    /// <summary>
    /// Gets the total number of entities on the card.
    /// </summary>
    public int TotalEntityCount =>
        (HasIsd ? 1 : 0) + SecurityDomainCount + ApplicationCount + LoadFileCount;
}

/// <summary>
/// Discriminated union representing different types of card entities for unified processing.
/// </summary>
public abstract record CardEntity
{
    /// <summary>
    /// Represents an Issuer Security Domain entity.
    /// </summary>
    public record IssuerSecurityDomainEntity(ApplicationInfo Application) : CardEntity;

    /// <summary>
    /// Represents a Security Domain entity.
    /// </summary>
    public record SecurityDomainEntity(ApplicationInfo Application) : CardEntity;

    /// <summary>
    /// Represents an Application entity.
    /// </summary>
    public record ApplicationEntity(ApplicationInfo Application) : CardEntity;

    /// <summary>
    /// Represents an Executable Load File entity.
    /// </summary>
    public record LoadFileEntity(ExecutableLoadFile LoadFile) : CardEntity;
}
