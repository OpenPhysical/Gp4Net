using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Immutable representation of a Security Domain on a virtual card.
/// Security Domains can establish secure channels and manage applications according to GP Section 7.
/// </summary>
public record VirtualSecurityDomain(
    ImmutableArray<byte> Aid,
    string Name,
    SecurityDomainType Type,
    ApplicationState State,
    ApplicationPrivileges Privileges,
    /// <summary>
    /// AID of the associated Security Domain. Self-reference (same as Aid) indicates root of hierarchy.
    /// </summary>
    Maybe<ImmutableArray<byte>> AssociatedSecurityDomainAid,
    /// <summary>
    /// Current authentication state for this Security Domain's secure channel sessions.
    /// </summary>
    AuthenticationState CurrentAuthentication,
    /// <summary>
    /// Current cryptographic security level if a secure channel is active.
    /// </summary>
    Maybe<Gp4Net.Domain.SecurityLevel> CurrentSecurityLevel,
    /// <summary>
    /// Key sets available to this Security Domain, indexed by key version.
    /// </summary>
    ImmutableDictionary<byte, Gp4Net.Domain.Keys.IKeySet> Keys,
    /// <summary>
    /// Data objects managed by this Security Domain.
    /// </summary>
    ImmutableDictionary<string, byte[]> DataObjects
)
{
    /// <summary>
    /// Creates the Issuer Security Domain (ISD) with default configuration.
    /// </summary>
    public static VirtualSecurityDomain CreateIsd()
    {
        var emptyAid = ImmutableArray<byte>.Empty;
        return new VirtualSecurityDomain(
            emptyAid, // ISD has empty AID
            "Issuer Security Domain",
            SecurityDomainType.IssuerSecurityDomain,
            ApplicationState.Selectable,
            ApplicationPrivileges.SecurityDomain | ApplicationPrivileges.CardManager,
            Maybe<ImmutableArray<byte>>.From(emptyAid), // Self-associated
            AuthenticationState.None,
            Maybe<Gp4Net.Domain.SecurityLevel>.None,
            ImmutableDictionary<byte, Gp4Net.Domain.Keys.IKeySet>.Empty,
            ImmutableDictionary<string, byte[]>.Empty
        );
    }

    /// <summary>
    /// Creates a Supplementary Security Domain with specified configuration.
    /// </summary>
    public static VirtualSecurityDomain CreateSupplementary(
        ImmutableArray<byte> aid,
        string name,
        ImmutableArray<byte> associatedSecurityDomainAid,
        ApplicationPrivileges privileges = ApplicationPrivileges.SecurityDomain)
    {
        return new VirtualSecurityDomain(
            aid,
            name,
            SecurityDomainType.SupplementarySecurityDomain,
            ApplicationState.Installed,
            privileges,
            Maybe<ImmutableArray<byte>>.From(associatedSecurityDomainAid),
            AuthenticationState.None,
            Maybe<Gp4Net.Domain.SecurityLevel>.None,
            ImmutableDictionary<byte, Gp4Net.Domain.Keys.IKeySet>.Empty,
            ImmutableDictionary<string, byte[]>.Empty
        );
    }

    /// <summary>
    /// Updates the authentication state for this Security Domain.
    /// </summary>
    public VirtualSecurityDomain WithAuthentication(
        AuthenticationState authState,
        Maybe<Gp4Net.Domain.SecurityLevel> securityLevel = default)
    {
        return this with 
        { 
            CurrentAuthentication = authState,
            CurrentSecurityLevel = securityLevel.HasValue ? securityLevel : CurrentSecurityLevel
        };
    }

    /// <summary>
    /// Updates the lifecycle state of this Security Domain.
    /// </summary>
    public VirtualSecurityDomain WithState(ApplicationState newState)
    {
        return this with { State = newState };
    }

    /// <summary>
    /// Adds or updates a data object for this Security Domain.
    /// </summary>
    public VirtualSecurityDomain WithDataObject(string tag, byte[] data)
    {
        return this with { DataObjects = DataObjects.SetItem(tag, data) };
    }

    /// <summary>
    /// Gets a data object managed by this Security Domain.
    /// </summary>
    public Maybe<byte[]> GetDataObject(string tag)
    {
        return DataObjects.TryGetValue(tag, out var data) 
            ? Maybe<byte[]>.From(data)
            : Maybe<byte[]>.None;
    }

    /// <summary>
    /// Checks if this Security Domain is the root of its association hierarchy.
    /// </summary>
    public bool IsHierarchyRoot => 
        AssociatedSecurityDomainAid.Match(
            associated => associated.SequenceEqual(Aid),
            () => false);

    /// <summary>
    /// Checks if this Security Domain has an active secure channel session.
    /// </summary>
    public bool HasActiveSecureChannel => CurrentAuthentication != AuthenticationState.None;
}

/// <summary>
/// Immutable representation of an application installed on a virtual card.
/// </summary>
public record VirtualApplication(
    ImmutableArray<byte> Aid,
    string Name,
    ApplicationState State,
    ApplicationPrivileges Privileges,
    /// <summary>
    /// AID of the Security Domain this application is associated with.
    /// </summary>
    ImmutableArray<byte> AssociatedSecurityDomainAid,
    ImmutableDictionary<string, byte[]> DataObjects
)
{
    public static VirtualApplication Create(
        ImmutableArray<byte> aid,
        string name,
        ImmutableArray<byte> associatedSecurityDomainAid,
        ApplicationPrivileges privileges = ApplicationPrivileges.None)
    {
        return new VirtualApplication(
            aid,
            name,
            ApplicationState.Installed,
            privileges,
            associatedSecurityDomainAid,
            ImmutableDictionary<string, byte[]>.Empty
        );
    }

    public VirtualApplication WithState(ApplicationState newState)
    {
        return this with { State = newState };
    }

    public VirtualApplication WithDataObject(string tag, byte[] data)
    {
        return this with { DataObjects = DataObjects.SetItem(tag, data) };
    }

    public Maybe<byte[]> GetDataObject(string tag)
    {
        return DataObjects.TryGetValue(tag, out var data) 
            ? Maybe<byte[]>.From(data)
            : Maybe<byte[]>.None;
    }
}

/// <summary>
/// Application state according to GlobalPlatform specification.
/// </summary>
public enum ApplicationState : byte
{
    Installed = 0x03,
    Selectable = 0x07,
    Personalized = 0x0F,
    Blocked = 0x83,
    Locked = 0x87
}

/// <summary>
/// Application privileges according to GlobalPlatform specification.
/// </summary>
[Flags]
public enum ApplicationPrivileges : byte
{
    None = 0x00,
    SecurityDomain = 0x80,
    DapVerification = 0x40,
    DelegatedManagement = 0x20,
    CardLock = 0x10,
    CardTerminate = 0x08,
    CardReset = 0x04,
    CvmManagement = 0x02,
    CardManager = 0x01
}

/// <summary>
/// Entity authentication states according to GlobalPlatform Section 10.4.
/// Represents whether the off-card entity has been authenticated through secure channel establishment.
/// This is separate from SecurityLevel which tracks cryptographic capabilities.
/// </summary>
public enum AuthenticationState : byte
{
    /// <summary>
    /// No secure channel session has been established. Entity is not authenticated.
    /// </summary>
    None = 0x00,
    
    /// <summary>
    /// Entity is authenticated but may be an agent of the Application Provider.
    /// The entity knows the correct secure channel keys but the Application Provider ID
    /// doesn't match or isn't registered in the card.
    /// </summary>
    AnyAuthenticated = 0x01,
    
    /// <summary>
    /// Entity is authenticated as the actual Application Provider.
    /// The entity knows the correct secure channel keys AND the Application Provider ID
    /// matches what's registered in the card for this Security Domain.
    /// </summary>
    Authenticated = 0x02
}

/// <summary>
/// Security Domain types according to GlobalPlatform Section 7.
/// </summary>
public enum SecurityDomainType : byte
{
    /// <summary>
    /// Issuer Security Domain - the root security domain established by the card issuer.
    /// Always associated with itself and cannot be extradited.
    /// </summary>
    IssuerSecurityDomain = 0x01,
    
    /// <summary>
    /// Supplementary Security Domain - additional security domains that can be associated
    /// with other Security Domains and can be extradited between hierarchies.
    /// </summary>
    SupplementarySecurityDomain = 0x02
}

/// <summary>
/// Immutable selection context for virtual cards supporting full GlobalPlatform hierarchy.
/// Tracks Security Domains, Applications, their associations, and current selection state.
/// </summary>
public record ApplicationSelectionContext(
    /// <summary>
    /// Security Domains on the card, indexed by AID hex string.
    /// </summary>
    ImmutableDictionary<string, VirtualSecurityDomain> SecurityDomains,
    /// <summary>
    /// Applications on the card, indexed by AID hex string.
    /// </summary>
    ImmutableDictionary<string, VirtualApplication> Applications,
    /// <summary>
    /// Key of currently selected entity (Security Domain or Application AID hex string).
    /// Empty string represents ISD selection.
    /// </summary>
    Maybe<string> SelectedEntityKey,
    /// <summary>
    /// History of selected entities for next occurrence selection logic.
    /// </summary>
    ImmutableList<string> SelectionHistory
)
{
    public static ApplicationSelectionContext Empty => new(
        ImmutableDictionary<string, VirtualSecurityDomain>.Empty,
        ImmutableDictionary<string, VirtualApplication>.Empty,
        Maybe<string>.None,
        ImmutableList<string>.Empty
    );

    public static ApplicationSelectionContext WithIsd()
    {
        var isd = VirtualSecurityDomain.CreateIsd();
        const string isdKey = ""; // ISD uses empty string key (empty AID)
        
        var securityDomainsBuilder = ImmutableDictionary.CreateBuilder<string, VirtualSecurityDomain>();
        securityDomainsBuilder.Add(isdKey, isd);
        
        var historyBuilder = ImmutableList.CreateBuilder<string>();
        historyBuilder.Add(isdKey);
        
        return new ApplicationSelectionContext(
            securityDomainsBuilder.ToImmutable(),
            ImmutableDictionary<string, VirtualApplication>.Empty,
            Maybe<string>.From(isdKey),
            historyBuilder.ToImmutable()
        );
    }

    /// <summary>
    /// Gets a Security Domain by its AID.
    /// </summary>
    private Maybe<VirtualSecurityDomain> GetSecurityDomainByAid(ImmutableArray<byte> aid)
    {
        var aidString = aid.IsEmpty ? "" : Convert.ToHexString(aid.ToArray());
        return SecurityDomains.TryGetValue(aidString, out var sd)
            ? Maybe<VirtualSecurityDomain>.From(sd)
            : Maybe<VirtualSecurityDomain>.None;
    }

    /// <summary>
    /// Gets the currently selected application if an application is selected.
    /// </summary>
    public Maybe<VirtualApplication> SelectedApplication =>
        SelectedEntityKey.Bind(key => 
            Applications.TryGetValue(key, out var app) 
                ? Maybe<VirtualApplication>.From(app)
                : Maybe<VirtualApplication>.None);

    /// <summary>
    /// Installs a new application in the context.
    /// </summary>
    public Result<ApplicationSelectionContext, SmartCardError> InstallApplication(
        ImmutableArray<byte> aid, 
        string name,
        ImmutableArray<byte> associatedSecurityDomainAid,
        ApplicationPrivileges privileges = ApplicationPrivileges.None)
    {
        if (aid.IsEmpty)
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.InvalidArgument("Application AID cannot be empty"));
        }

        var aidString = Convert.ToHexString(aid.ToArray());
        
        if (Applications.ContainsKey(aidString) || SecurityDomains.ContainsKey(aidString))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.InvalidData($"Entity with AID {aidString} already exists"));
        }

        // Verify associated Security Domain exists
        if (!GetSecurityDomainByAid(associatedSecurityDomainAid).HasValue)
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.ReferencedDataNotFound());
        }

        var application = VirtualApplication.Create(aid, name, associatedSecurityDomainAid, privileges);
        var applicationsBuilder = Applications.ToBuilder();
        applicationsBuilder.Add(aidString, application);

        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with { Applications = applicationsBuilder.ToImmutable() });
    }

    /// <summary>
    /// Selects an application by AID. Returns new context with the application selected.
    /// </summary>
    public Result<ApplicationSelectionContext, SmartCardError> SelectApplication(ImmutableArray<byte> aid)
    {
        if (aid.IsEmpty)
        {
            // Empty AID selects ISD
            return SelectIsd();
        }

        var aidString = Convert.ToHexString(aid.ToArray());
        
        if (!Applications.TryGetValue(aidString, out var application))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.FileNotFound());
        }

        if (application.State != ApplicationState.Selectable && application.State != ApplicationState.Personalized)
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied());
        }

        var historyBuilder = SelectionHistory.ToBuilder();
        historyBuilder.Add(aidString);
        
        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with { 
                SelectedEntityKey = Maybe<string>.From(aidString),
                SelectionHistory = historyBuilder.ToImmutable()
            });
    }

    /// <summary>
    /// Selects the Issuer Security Domain.
    /// </summary>
    public Result<ApplicationSelectionContext, SmartCardError> SelectIsd()
    {
        const string isdKey = "ISD";
        
        if (!Applications.ContainsKey(isdKey))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.FileNotFound());
        }

        var historyBuilder = SelectionHistory.ToBuilder();
        historyBuilder.Add(isdKey);
        
        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with { 
                SelectedEntityKey = Maybe<string>.From(isdKey),
                SelectionHistory = historyBuilder.ToImmutable()
            });
    }

    /// <summary>
    /// Updates the state of an application. Returns new context with updated application.
    /// </summary>
    public Result<ApplicationSelectionContext, SmartCardError> UpdateApplicationState(
        ImmutableArray<byte> aid, 
        ApplicationState newState)
    {
        var aidString = aid.IsEmpty ? "ISD" : Convert.ToHexString(aid.ToArray());
        
        if (!Applications.TryGetValue(aidString, out var application))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.ReferencedDataNotFound());
        }

        var updatedApplication = application.WithState(newState);
        var newApplications = Applications.SetItem(aidString, updatedApplication);

        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with { Applications = newApplications });
    }

    /// <summary>
    /// Deletes an application from the context. Returns new context without the application.
    /// </summary>
    public Result<ApplicationSelectionContext, SmartCardError> DeleteApplication(ImmutableArray<byte> aid)
    {
        if (aid.IsEmpty)
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.InvalidArgument("Cannot delete ISD"));
        }

        var aidString = Convert.ToHexString(aid.ToArray());
        
        if (!Applications.ContainsKey(aidString))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.ReferencedDataNotFound());
        }

        var newApplications = Applications.Remove(aidString);
        var newSelectedKey = SelectedEntityKey.Match(
            selected => selected == aidString ? Maybe<string>.None : SelectedEntityKey,
            () => Maybe<string>.None);

        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with { 
                Applications = newApplications,
                SelectedEntityKey = newSelectedKey
            });
    }

    /// <summary>
    /// Gets all applications in a specific state.
    /// </summary>
    public ImmutableList<VirtualApplication> GetApplicationsByState(ApplicationState state)
    {
        return Applications.Values
            .Where(app => app.State == state)
            .ToImmutableList();
    }

    /// <summary>
    /// Gets all applications with specific privileges.
    /// </summary>
    public ImmutableList<VirtualApplication> GetApplicationsByPrivileges(ApplicationPrivileges privileges)
    {
        return Applications.Values
            .Where(app => app.Privileges.HasFlag(privileges))
            .ToImmutableList();
    }

    /// <summary>
    /// Checks if the currently selected application has specific privileges.
    /// </summary>
    public bool CurrentApplicationHasPrivileges(ApplicationPrivileges requiredPrivileges)
    {
        return SelectedApplication.Match(
            app => app.Privileges.HasFlag(requiredPrivileges),
            () => false);
    }

    /// <summary>
    /// Gets selection history summary for debugging.
    /// </summary>
    public string GetSelectionHistorySummary()
    {
        if (!SelectionHistory.Any())
        {
            return "No selections made";
        }

        var historyItems = SelectionHistory
            .Select((key, index) => $"  {index + 1}. {key}")
            .ToImmutableList();

        return $"Selection History ({SelectionHistory.Count} selections):\n" +
               string.Join("\n", historyItems);
    }
}