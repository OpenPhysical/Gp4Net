using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Immutable representation of a Security Domain on a virtual card.
/// Security Domains can establish secure channels and manage applications according to GP Section 7.
/// </summary>
/// <param name="Aid">The Application Identifier.</param>
/// <param name="Name">The security domain name.</param>
/// <param name="Type">The security domain type.</param>
/// <param name="State">The current application state.</param>
/// <param name="Privileges">The application privileges.</param>
/// <param name="AssociatedSecurityDomainAid">AID of the associated Security Domain. Self-reference (same as Aid) indicates root of hierarchy.</param>
/// <param name="CurrentAuthentication">Current authentication state for this Security Domain's secure channel sessions.</param>
/// <param name="CurrentSecurityLevel">Current cryptographic security level if a secure channel is active.</param>
/// <param name="Keys">Key sets available to this Security Domain, indexed by key version.</param>
/// <param name="DataObjects">Data objects managed by this Security Domain.</param>
public record VirtualSecurityDomain(
    ImmutableArray<byte> Aid,
    string Name,
    SecurityDomainType Type,
    ApplicationState State,
    ApplicationPrivileges Privileges,
    Maybe<ImmutableArray<byte>> AssociatedSecurityDomainAid,
    AuthenticationState CurrentAuthentication,
    Maybe<SecurityLevel> CurrentSecurityLevel,
    ImmutableDictionary<byte, IKeySet> Keys,
    ImmutableDictionary<string, byte[]> DataObjects
)
{
    /// <summary>
    /// Creates the Issuer Security Domain (ISD) with default configuration.
    /// </summary>
    public static VirtualSecurityDomain CreateIsd()
    {
        ImmutableArray<byte> emptyAid = ImmutableArray<byte>.Empty;
        return new VirtualSecurityDomain(
            emptyAid, // ISD has empty AID
            "Issuer Security Domain",
            SecurityDomainType.IssuerSecurityDomain,
            ApplicationState.Selectable,
            ApplicationPrivileges.SecurityDomain | ApplicationPrivileges.CardManager,
            Maybe<ImmutableArray<byte>>.From(emptyAid), // Self-associated
            AuthenticationState.None,
            Maybe<SecurityLevel>.None,
            ImmutableDictionary<byte, IKeySet>.Empty,
            ImmutableDictionary<string, byte[]>.Empty
        );
    }

    /// <summary>
    /// Creates a Supplementary Security Domain with specified configuration.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION
    public static VirtualSecurityDomain CreateSupplementary(
        ImmutableArray<byte> aid,
        string name,
        ImmutableArray<byte> associatedSecurityDomainAid,
        ApplicationPrivileges privileges = ApplicationPrivileges.SecurityDomain
    )
    {
        return new VirtualSecurityDomain(
            aid,
            name,
            SecurityDomainType.SupplementarySecurityDomain,
            ApplicationState.Installed,
            privileges,
            Maybe<ImmutableArray<byte>>.From(associatedSecurityDomainAid),
            AuthenticationState.None,
            Maybe<SecurityLevel>.None,
            ImmutableDictionary<byte, IKeySet>.Empty,
            ImmutableDictionary<string, byte[]>.Empty
        );
    }

    /// <summary>
    /// Updates the authentication state for this Security Domain.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION'
    public VirtualSecurityDomain WithAuthentication(
        AuthenticationState authState,
        Maybe<SecurityLevel> securityLevel = default
    )
    {
        return this with
        {
            CurrentAuthentication = authState,
            CurrentSecurityLevel = securityLevel.HasValue ? securityLevel : CurrentSecurityLevel,
        };
    }

    /// <summary>
    /// Updates the lifecycle state of this Security Domain.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION'
    public VirtualSecurityDomain WithState(ApplicationState newState)
    {
        return this with { State = newState };
    }

    /// <summary>
    /// Adds or updates a data object for this Security Domain.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION'
    public VirtualSecurityDomain WithDataObject(string tag, byte[] data)
    {
        return this with { DataObjects = DataObjects.SetItem(tag, data) };
    }

    /// <summary>
    /// Gets a data object managed by this Security Domain.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION'
    public Maybe<byte[]> GetDataObject(string tag)
    {
        return DataObjects.TryGetValue(tag, out byte[]? data)
            ? Maybe<byte[]>.From(data)
            : Maybe<byte[]>.None;
    }

    /// <summary>
    /// Checks if this Security Domain is the root of its association hierarchy.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION'
    public bool IsHierarchyRoot =>
        AssociatedSecurityDomainAid.Match(associated => associated.SequenceEqual(Aid), () => false);

}

/// <summary>
/// Immutable representation of an application installed on a virtual card.
/// </summary>
/// <param name="Aid">The Application Identifier.</param>
/// <param name="Name">The application name.</param>
/// <param name="State">The current application state.</param>
/// <param name="Privileges">The application privileges.</param>
/// <param name="AssociatedSecurityDomainAid">AID of the Security Domain this application is associated with.</param>
/// <param name="DataObjects">Data objects managed by this application.</param>
public record VirtualApplication(
    ImmutableArray<byte> Aid,
    string Name,
    ApplicationState State,
    ApplicationPrivileges Privileges,
    ImmutableArray<byte> AssociatedSecurityDomainAid,
    ImmutableDictionary<string, byte[]> DataObjects
)
{
    /// <summary>
    /// Creates a new instance of <see cref="VirtualApplication"/> with default configurations,
    /// setting the state to Installed and initializing data objects as empty.
    /// </summary>
    /// <param name="aid">The application identifier (AID) of the virtual application.</param>
    /// <param name="name">The name of the virtual application.</param>
    /// <param name="associatedSecurityDomainAid">The AID of the associated security domain.</param>
    /// <param name="privileges">The privileges assigned to the virtual application. Defaults to <see cref="ApplicationPrivileges.None"/>.</param>
    /// <returns>A new instance of <see cref="VirtualApplication"/> configured with the provided parameters.</returns>
    public static VirtualApplication Create(
        ImmutableArray<byte> aid,
        string name,
        ImmutableArray<byte> associatedSecurityDomainAid,
        ApplicationPrivileges privileges = ApplicationPrivileges.None
    )
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

    /// <summary>
    /// Updates the current VirtualApplication instance with a new application state.
    /// </summary>
    /// <param name="newState">The new state to be assigned to the application.</param>
    /// <returns>A new instance of VirtualApplication with the updated state.</returns>
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
        // @TODO NO NULLS!
        return DataObjects.TryGetValue(tag, out byte[]? data)
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
    Locked = 0x87,
}

/// <summary>
/// Application privileges according to GlobalPlatform specification.
/// </summary>
[Flags]
public enum ApplicationPrivileges : byte
{
    None = 0x00,
    SecurityDomain = 0x80,
    DapVerification = 0x40, // @TODO THIS NEEDS TO BE SUPPORTED
    DelegatedManagement = 0x20,
    CardLock = 0x10,
    CardTerminate = 0x08,
    CardReset = 0x04,
    CvmManagement = 0x02, // @TODO THIS NEEDS TO BE SUPPORTED
    CardManager = 0x01,
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
    // @TODO THIS MUST BE USED.  ELIMINATE ANY HACKS YOU ARE USING INSTEAD.
    AnyAuthenticated = 0x01,

    /// <summary>
    /// Entity is authenticated as the actual Application Provider.
    /// The entity knows the correct secure channel keys AND the Application Provider ID
    /// matches what's registered in the card for this Security Domain.
    /// </summary>
    // @TODO THIS MUST BE USED.  ELIMINATE ANY HACKS YOU ARE USING INSTEAD.
    Authenticated = 0x02,
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
    SupplementarySecurityDomain = 0x02,
}

/// <summary>
/// Immutable selection context for virtual cards supporting full GlobalPlatform hierarchy.
/// Tracks Security Domains, Applications, their associations, and current selection state.
/// </summary>
/// <param name="SecurityDomains">Security Domains on the card, indexed by AID hex string.</param>
/// <param name="Applications">Applications on the card, indexed by AID hex string.</param>
/// <param name="SelectedEntityKey">Key of currently selected entity (Security Domain or Application AID hex string). Empty string represents ISD selection.</param>
/// <param name="SelectionHistory">History of selected entities for next occurrence selection logic.</param>
public record ApplicationSelectionContext(
    ImmutableDictionary<string, VirtualSecurityDomain> SecurityDomains,
    ImmutableDictionary<string, VirtualApplication> Applications,
    Maybe<string> SelectedEntityKey,
    ImmutableList<string> SelectionHistory
)
{
    /// <summary>
    /// Provides an empty instance of the ApplicationSelectionContext with no predefined security domains,
    /// applications, selected entities, or selection history.
    /// </summary>
    // @TODO WHY DOES THIS EXIST?  CARDS HAVE ISDs.
    public static ApplicationSelectionContext Empty =>
        new(
            ImmutableDictionary<string, VirtualSecurityDomain>.Empty,
            ImmutableDictionary<string, VirtualApplication>.Empty,
            Maybe<string>.None,
            ImmutableList<string>.Empty
        );

    /// <summary>
    /// Initializes a new instance of <see cref="ApplicationSelectionContext"/> with a default Issuer Security Domain (ISD).
    /// </summary>
    /// <returns>
    /// An <see cref="ApplicationSelectionContext"/> with the default ISD configuration.
    /// </returns>
    public static ApplicationSelectionContext WithIsd()
    {
        VirtualSecurityDomain isd = VirtualSecurityDomain.CreateIsd();
        const string isdKey = ""; // ISD uses empty string key (empty AID) // @TODO NO IT DOESN'T.  USE THE PROPER AID.  AS A CONSTANT.  IN THE RIGHT PLACE.


        ImmutableDictionary<string, VirtualSecurityDomain>.Builder securityDomainsBuilder =
            ImmutableDictionary.CreateBuilder<string, VirtualSecurityDomain>();
        securityDomainsBuilder.Add(isdKey, isd);

        ImmutableList<string>.Builder historyBuilder = ImmutableList.CreateBuilder<string>();
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
        // @TODO THERE IS NO SUCH THING AS AN "EMPTY" AID.  THAT'S AN INVALID STATE, AND MUST BE UNREPRESENTABLE.
        string aidString = aid.IsEmpty ? "" : Convert.ToHexString(aid.ToArray());
        // @TODO NO NULLS!
        return SecurityDomains.TryGetValue(aidString, out VirtualSecurityDomain? sd)
            ? Maybe<VirtualSecurityDomain>.From(sd)
            : Maybe<VirtualSecurityDomain>.None;
    }

    /// <summary>
    /// Gets the currently selected application if an application is selected.
    /// </summary>
    public Maybe<VirtualApplication> SelectedApplication =>
        SelectedEntityKey.Bind(key =>
            // @TODO NO NULLS!
            Applications.TryGetValue(key, out VirtualApplication? app)
                ? Maybe<VirtualApplication>.From(app)
                : Maybe<VirtualApplication>.None
        );

    /// <summary>
    /// Installs a new application in the context.
    /// </summary>
    public Result<ApplicationSelectionContext, SmartCardError> InstallApplication(
        ImmutableArray<byte> aid,
        string name,
        ImmutableArray<byte> associatedSecurityDomainAid,
        ApplicationPrivileges privileges = ApplicationPrivileges.None
    )
    {
        if (aid.IsEmpty)
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.InvalidArgument("Application AID cannot be empty")
            );
        }

        string aidString = Convert.ToHexString(aid.ToArray());

        if (Applications.ContainsKey(aidString) || SecurityDomains.ContainsKey(aidString))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.InvalidData($"Entity with AID {aidString} already exists")
            );
        }

        // Verify associated Security Domain exists
        if (!GetSecurityDomainByAid(associatedSecurityDomainAid).HasValue)
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.ReferencedDataNotFound()
            );
        }

        VirtualApplication application = VirtualApplication.Create(
            aid,
            name,
            associatedSecurityDomainAid,
            privileges
        );
        ImmutableDictionary<string, VirtualApplication>.Builder applicationsBuilder =
            Applications.ToBuilder();
        applicationsBuilder.Add(aidString, application);

        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with
            {
                Applications = applicationsBuilder.ToImmutable(),
            }
        );
    }

    /// <summary>
    /// Selects an application by AID. Returns new context with the application selected.
    /// </summary>
    public Result<ApplicationSelectionContext, SmartCardError> SelectApplication(
        ImmutableArray<byte> aid
    )
    {
        if (aid.IsEmpty)
        {
            // Empty AID selects ISD
            return SelectIsd();
        }

        string aidString = Convert.ToHexString(aid.ToArray());

        // @TODO NO NULLS!
        if (!Applications.TryGetValue(aidString, out VirtualApplication? application))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.FileNotFound()
            );
        }

        if (
            application.State != ApplicationState.Selectable
            && application.State != ApplicationState.Personalized
        )
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            );
        }

        ImmutableList<string>.Builder historyBuilder = SelectionHistory.ToBuilder();
        historyBuilder.Add(aidString);

        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with
            {
                SelectedEntityKey = Maybe<string>.From(aidString),
                SelectionHistory = historyBuilder.ToImmutable(),
            }
        );
    }

    /// <summary>
    /// Selects the Issuer Security Domain.
    /// </summary>
    public Result<ApplicationSelectionContext, SmartCardError> SelectIsd()
    {
        // @TODO THIS IS INCONSISTENT WITH EARLIER CODE.  It's ALSO A HACK.
        const string isdKey = "ISD";

        if (!Applications.ContainsKey(isdKey))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.FileNotFound()
            );
        }

        ImmutableList<string>.Builder historyBuilder = SelectionHistory.ToBuilder();
        historyBuilder.Add(isdKey);

        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with
            {
                SelectedEntityKey = Maybe<string>.From(isdKey),
                SelectionHistory = historyBuilder.ToImmutable(),
            }
        );
    }

    /// <summary>
    /// Updates the state of an application. Returns new context with updated application.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION
    // @TODO CHECK GP SPEC TO SEE IF THIS IS USEFUL
    public Result<ApplicationSelectionContext, SmartCardError> UpdateApplicationState(
        ImmutableArray<byte> aid,
        ApplicationState newState
    )
    {
        string aidString = aid.IsEmpty ? "ISD" : Convert.ToHexString(aid.ToArray());

        if (!Applications.TryGetValue(aidString, out VirtualApplication? application))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.ReferencedDataNotFound()
            );
        }

        VirtualApplication updatedApplication = application.WithState(newState);
        ImmutableDictionary<string, VirtualApplication> newApplications = Applications.SetItem(
            aidString,
            updatedApplication
        );

        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with
            {
                Applications = newApplications,
            }
        );
    }

    /// <summary>
    /// Deletes an application from the context. Returns new context without the application.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION
    // @TODO CHECK GP SPEC TO SEE IF THIS IS USEFUL
    public Result<ApplicationSelectionContext, SmartCardError> DeleteApplication(
        ImmutableArray<byte> aid
    )
    {
        if (aid.IsEmpty)
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.InvalidArgument("Cannot delete ISD")
            );
        }

        string aidString = Convert.ToHexString(aid.ToArray());

        if (!Applications.ContainsKey(aidString))
        {
            return Result.Failure<ApplicationSelectionContext, SmartCardError>(
                SmartCardError.ReferencedDataNotFound()
            );
        }

        ImmutableDictionary<string, VirtualApplication> newApplications = Applications.Remove(
            aidString
        );
        Maybe<string> newSelectedKey = SelectedEntityKey.Match(
            selected => selected == aidString ? Maybe<string>.None : SelectedEntityKey,
            () => Maybe<string>.None
        );

        return Result.Success<ApplicationSelectionContext, SmartCardError>(
            this with
            {
                Applications = newApplications,
                SelectedEntityKey = newSelectedKey,
            }
        );
    }

    /// <summary>
    /// Gets all applications in a specific state.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION
    // @TODO CHECK GP SPEC TO SEE IF THIS IS USEFUL
    // @TODO SHOULDN'T THIS BE USED WITH PARTIAL SELECTION?
    public ImmutableList<VirtualApplication> GetApplicationsByState(ApplicationState state)
    {
        return Applications.Values.Where(app => app.State == state).ToImmutableList();
    }

    /// <summary>
    /// Gets all applications with specific privileges.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION
    // @TODO CHECK GP SPEC TO SEE IF THIS IS USEFUL
    public ImmutableList<VirtualApplication> GetApplicationsByPrivileges(
        ApplicationPrivileges privileges
    )
    {
        return Applications
            .Values.Where(app => app.Privileges.HasFlag(privileges))
            .ToImmutableList();
    }

    /// <summary>
    /// Checks if the currently selected application has specific privileges.
    /// </summary>
    public bool CurrentApplicationHasPrivileges(ApplicationPrivileges requiredPrivileges)
    {
        return SelectedApplication.Match(
            app => app.Privileges.HasFlag(requiredPrivileges),
            () => false
        );
    }

    /// <summary>
    /// Gets selection history summary for debugging.
    /// </summary>
    // @TODO IF THIS CODE IS USEFUL WE SHOULD USE IT.  IF THERE'S A DIFFERENT WAY TO DO THIS, ELIMINATE THE DRY VIOLATION'
    public string GetSelectionHistorySummary()
    {
        if (!SelectionHistory.Any())
        {
            return "No selections made";
        }

        ImmutableList<string> historyItems = SelectionHistory
            .Select((key, index) => $"  {index + 1}. {key}")
            .ToImmutableList();

        return $"Selection History ({SelectionHistory.Count} selections):\n"
            + string.Join("\n", historyItems);
    }
}
