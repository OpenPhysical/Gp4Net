using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Gp4Net.CardEmulator.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Immutable card state representing the current state of a virtual card.
/// All state transitions produce new instances rather than mutating existing state.
/// Uses functional programming patterns with Maybe and immutable secure channel state.
/// </summary>
[PublicAPI]
public record CardState(
    CardUuid Uuid,
    bool IsSelected,
    byte ScpVersion,
    Domain.Protocol.ScpImplementation ScpImplementation,
    Maybe<SecureChannelState> SecureChannel,
    Maybe<IKeySet> CurrentKeys,
    Maybe<byte[]> HostChallenge,
    Maybe<byte[]> CardChallenge,
    ImmutableDictionary<ushort, byte[]> DataObjects,
    ImmutableDictionary<string, InstalledApplication> Applications,
    ImmutableList<LoadFile> LoadFiles,
    ImmutableDictionary<byte, IKeySet> InstalledKeys,
    byte DefaultKeyVersion,
    ImmutableDictionary<byte, byte[]> SequenceCounters,
    ApplicationSelectionContext ApplicationContext
)
{
    /// <summary>
    /// Creates the initial state for a new card.
    /// Per GP Card Spec v2.3.1 Section 6.4.1: "The Issuer Security Domain is by default the implicitly selectable Application
    /// on all logical channels of all card I/O interfaces supported by the card"
    /// Per GP Card Spec v2.3.1 Section 6.4.2.1.1: "Once the card session has been established... the Application defined 
    /// as implicitly selectable on the Basic Logical Channel... shall become the selected Application on the Basic Logical Channel"
    /// </summary>
    public static Result<CardState, SmartCardError> Create()
    {
        return CardUuid.Generate()
            .Map(uuid => new CardState(
                Uuid: uuid,
                IsSelected: true, // ISD is implicitly selected by default per GP Card Spec v2.3.1
                ScpVersion: 0x02,
                ScpImplementation: Domain.Protocol.ScpImplementation.Scp02I15,
                SecureChannel: Maybe<SecureChannelState>.None,
                CurrentKeys: Maybe<IKeySet>.None,
                HostChallenge: Maybe<byte[]>.None,
                CardChallenge: Maybe<byte[]>.None,
                DataObjects: ImmutableDictionary<ushort, byte[]>.Empty,
                Applications: ImmutableDictionary<string, InstalledApplication>.Empty,
                LoadFiles: ImmutableList<LoadFile>.Empty,
                InstalledKeys: ImmutableDictionary<byte, IKeySet>.Empty,
                DefaultKeyVersion: 0xFF,
                SequenceCounters: ImmutableDictionary<byte, byte[]>.Empty,
                ApplicationContext: ApplicationSelectionContext.WithIsd()
            ));
    }

    /// <summary>
    /// Creates initial state with a specific UUID. Used for testing and deserialization.
    /// </summary>
    /// <param name="uuid">The UUID to use for the card.</param>
    /// <returns>Initial card state with the specified UUID.</returns>
    public static CardState CreateWithUuid(CardUuid uuid)
    {
        return new CardState(
            Uuid: uuid,
            IsSelected: true,
            ScpVersion: 0x02,
            ScpImplementation: Domain.Protocol.ScpImplementation.Scp02I15,
            SecureChannel: Maybe<SecureChannelState>.None,
            CurrentKeys: Maybe<IKeySet>.None,
            HostChallenge: Maybe<byte[]>.None,
            CardChallenge: Maybe<byte[]>.None,
            DataObjects: ImmutableDictionary<ushort, byte[]>.Empty,
            Applications: ImmutableDictionary<string, InstalledApplication>.Empty,
            LoadFiles: ImmutableList<LoadFile>.Empty,
            InstalledKeys: ImmutableDictionary<byte, IKeySet>.Empty,
            DefaultKeyVersion: 0xFF,
            SequenceCounters: ImmutableDictionary<byte, byte[]>.Empty,
            ApplicationContext: ApplicationSelectionContext.WithIsd()
        );
    }

    /// <summary>
    /// Gets whether a secure channel is established.
    /// </summary>
    public bool IsSecureChannelEstablished
    {
        get
        {
            return SecureChannel.HasValue;
        }
    }

    /// <summary>
    /// Gets the current security level.
    /// </summary>
    public byte SecurityLevel
    {
        get
        {
            return SecureChannel.HasValue ? (byte)SecureChannel.Value.SecurityLevel : (byte)0x00;
        }
    }

    /// <summary>
    /// Gets the session keys if a secure channel is established.
    /// </summary>
    public Maybe<SessionKeys> SessionKeys
    {
        get
        {
            return SecureChannel.Map(sc => sc.SessionKeys);
        }
    }

    /// <summary>
    /// Gets the MAC chaining value if a secure channel is established.
    /// </summary>
    public Maybe<ImmutableArray<byte>> MacChainingValue
    {
        get
        {
            return SecureChannel.Map(sc => sc.MacChaining.Value);
        }
    }

    /// <summary>
    /// Gets the encryption counter if a secure channel is established.
    /// </summary>
    public Maybe<uint> EncryptionCounter
    {
        get
        {
            return SecureChannel.Map(sc => sc.EncryptionCounter);
        }
    }

    /// <summary>
    /// Creates a new state with the card selected.
    /// </summary>
    public CardState WithSelected(bool selected = true) => this with { IsSelected = selected };

    /// <summary>
    /// Creates a new state with secure channel established using functional SecureChannelState.
    /// </summary>
    public CardState WithSecureChannel(SecureChannelState secureChannelState) =>
        this with { SecureChannel = Maybe<SecureChannelState>.From(secureChannelState) };

    /// <summary>
    /// Creates a new state with secure channel cleared.
    /// </summary>
    public CardState WithoutSecureChannel() =>
        this with { SecureChannel = Maybe<SecureChannelState>.None };

    /// <summary>
    /// Creates a new state with updated secure channel state.
    /// This is used when the secure channel state changes (e.g., counter increments).
    /// </summary>
    public CardState WithUpdatedSecureChannel(SecureChannelState newSecureChannelState) =>
        this with { SecureChannel = Maybe<SecureChannelState>.From(newSecureChannelState) };

    /// <summary>
    /// Creates a new state with updated challenges.
    /// </summary>
    public CardState WithChallenges(Maybe<byte[]> hostChallenge, Maybe<byte[]> cardChallenge) => this with
    {
        HostChallenge = hostChallenge,
        CardChallenge = cardChallenge
    };

    /// <summary>
    /// Creates a new state with a different UUID. Used for card reset operations.
    /// </summary>
    public CardState WithUuid(CardUuid newUuid) => this with { Uuid = newUuid };


    /// <summary>
    /// Creates a new state with updated current keys.
    /// </summary>
    public CardState WithKeys(IKeySet keys) => this with { CurrentKeys = Maybe<IKeySet>.From(keys) };

    /// <summary>
    /// Creates a new state with current keys cleared.
    /// </summary>
    public CardState WithoutKeys() => this with { CurrentKeys = Maybe<IKeySet>.None };


    /// <summary>
    /// Creates a new state with an added data object.
    /// </summary>
    public CardState WithDataObject(ushort tag, byte[] data) => this with
    {
        DataObjects = DataObjects.SetItem(tag, data)
    };

    /// <summary>
    /// Creates a new state with an installed application.
    /// </summary>
    public CardState WithApplication(string aid, InstalledApplication application) => this with
    {
        Applications = Applications.SetItem(aid, application)
    };

    /// <summary>
    /// Creates a new state with a loaded file.
    /// </summary>
    public CardState WithLoadFile(LoadFile loadFile) => this with
    {
        LoadFiles = LoadFiles.Add(loadFile)
    };

    /// <summary>
    /// Creates a new state with an installed key set.
    /// </summary>
    public CardState WithInstalledKey(byte keyVersion, IKeySet keySet) => this with
    {
        InstalledKeys = InstalledKeys.SetItem(keyVersion, keySet)
    };

    /// <summary>
    /// Creates a new state with updated default key version.
    /// </summary>
    public CardState WithDefaultKeyVersion(byte keyVersion) => this with
    {
        DefaultKeyVersion = keyVersion
    };

    /// <summary>
    /// Gets the sequence counter for a specific key version.
    /// Returns a 2-byte counter for SCP02 or 3-byte counter for SCP03.
    /// </summary>
    public byte[] GetSequenceCounter(byte keyVersion)
    {
        if (SequenceCounters.TryGetValue(keyVersion, out byte[] counter))
            return counter;
        
        // Return appropriate default counter based on SCP version
        return ScpVersion == 0x02 
            ? [0x00, 0x01] // 2-byte counter for SCP02
            : [0x00, 0x00, 0x01]; // 3-byte counter for SCP03
    }

    /// <summary>
    /// Creates a new state with an incremented sequence counter for the specified key version.
    /// </summary>
    public CardState WithIncrementedSequenceCounter(byte keyVersion)
    {
        byte[] currentCounter = GetSequenceCounter(keyVersion);
        byte[] newCounter = IncrementCounter(currentCounter);
        return this with { SequenceCounters = SequenceCounters.SetItem(keyVersion, newCounter) };
    }

    /// <summary>
    /// Creates a new state with a reset sequence counter for the specified key version.
    /// This should be called when a keyset is created or replaced.
    /// </summary>
    public CardState WithResetSequenceCounter(byte keyVersion)
    {
        // Return appropriate reset counter based on SCP version
        byte[] resetCounter = ScpVersion == 0x02 
            ? [0x00, 0x01] // 2-byte counter for SCP02
            : [0x00, 0x00, 0x01]; // 3-byte counter for SCP03
        return this with { SequenceCounters = SequenceCounters.SetItem(keyVersion, resetCounter) };
    }

    /// <summary>
    /// Increments a counter in big-endian format.
    /// Handles both 2-byte (SCP02) and 3-byte (SCP03) counters.
    /// </summary>
    private static byte[] IncrementCounter(byte[] counter)
    {
        byte[] newCounter = new byte[counter.Length];
        System.Array.Copy(counter, newCounter, counter.Length);

        switch (counter.Length)
        {
            // Increment in big-endian format
            case 2:
            {
                // 2-byte counter for SCP02
                int value = (newCounter[0] << 8) | newCounter[1];
                value++;
                newCounter[0] = (byte)(value >> 8);
                newCounter[1] = (byte)value;
                break;
            }
            case 3:
            {
                // 3-byte counter for SCP03
                int value = (newCounter[0] << 16) | (newCounter[1] << 8) | newCounter[2];
                value++;
                newCounter[0] = (byte)(value >> 16);
                newCounter[1] = (byte)(value >> 8);
                newCounter[2] = (byte)value;
                break;
            }
        }
            
        return newCounter;
    }

    /// <summary>
    /// Creates a new state with updated application selection context.
    /// </summary>
    public CardState WithApplicationContext(ApplicationSelectionContext newContext) => this with
    {
        ApplicationContext = newContext
    };

    /// <summary>
    /// Selects an application by AID and returns updated card state.
    /// </summary>
    public Result<CardState, Gp4Net.Core.SmartCardError> SelectApplication(ImmutableArray<byte> aid)
    {
        return ApplicationContext.SelectApplication(aid)
            .Map(newContext => WithApplicationContext(newContext));
    }

    /// <summary>
    /// Installs a new application and returns updated card state.
    /// </summary>
    public Result<CardState, Gp4Net.Core.SmartCardError> InstallApplication(
        ImmutableArray<byte> aid, 
        string name,
        ImmutableArray<byte> associatedSecurityDomainAid,
        ApplicationPrivileges privileges = ApplicationPrivileges.None)
    {
        return ApplicationContext.InstallApplication(aid, name, associatedSecurityDomainAid, privileges)
            .Map(newContext => WithApplicationContext(newContext));
    }

    /// <summary>
    /// Gets the currently selected application.
    /// </summary>
    public Maybe<VirtualApplication> CurrentlySelectedApplication => ApplicationContext.SelectedApplication;

    /// <summary>
    /// Checks if the current application has specific privileges.
    /// </summary>
    public bool CurrentApplicationHasPrivileges(ApplicationPrivileges requiredPrivileges)
    {
        return ApplicationContext.CurrentApplicationHasPrivileges(requiredPrivileges);
    }

    /// <summary>
    /// Resets the card state to initial conditions.
    /// Per GP Card Spec v2.3.1 Section 6.4.2.1.1: After card reset, ISD becomes implicitly selected.
    /// Preserves installed applications, keys, and sequence counters but clears secure channel state.
    /// </summary>
    public CardState Reset() => CreateWithUuid(Uuid) with
    {
        ScpVersion = ScpVersion,
        ScpImplementation = ScpImplementation,
        DataObjects = DataObjects,
        InstalledKeys = InstalledKeys,
        DefaultKeyVersion = DefaultKeyVersion,
        SequenceCounters = SequenceCounters, // Preserve sequence counters across resets
        ApplicationContext = ApplicationSelectionContext.WithIsd(), // Reset to ISD as implicitly selected
        IsSelected = true // ISD is implicitly selected after reset per GP Card Spec v2.3.1
    };
}

/// <summary>
/// Represents an installed application on the card.
/// </summary>
public record InstalledApplication(
    byte[] Aid,
    byte[] ExecutableModuleAid,
    byte LifeCycleState,
    byte Privileges,
    ImmutableDictionary<string, byte[]> ApplicationData
);

/// <summary>
/// Represents a loaded CAP file on the card.
/// </summary>
public record LoadFile(
    byte[] Aid,
    byte[] SecurityDomainAid,
    byte LifeCycleState,
    ImmutableList<ExecutableModule> Modules
);

/// <summary>
/// Represents an executable module within a load file.
/// </summary>
public record ExecutableModule(
    byte[] Aid,
    byte LifeCycleState
);