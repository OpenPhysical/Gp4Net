using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Immutable card state representing the current state of a virtual card.
/// All state transitions produce new instances rather than mutating existing state.
/// Uses functional programming patterns with Maybe and immutable secure channel state.
/// </summary>
[PublicAPI]
public record CardState(
    bool IsSelected,
    byte ScpVersion,
    Gp4Net.Domain.Protocol.ScpImplementation ScpImplementation,
    Maybe<SecureChannelState> SecureChannel,
    IKeySet? CurrentKeys,
    byte[]? HostChallenge,
    byte[]? CardChallenge,
    ImmutableDictionary<ushort, byte[]> DataObjects,
    ImmutableDictionary<string, InstalledApplication> Applications,
    ImmutableList<LoadFile> LoadFiles,
    ImmutableDictionary<byte, IKeySet> InstalledKeys,
    byte DefaultKeyVersion,
    ImmutableDictionary<byte, byte[]> SequenceCounters
)
{
    /// <summary>
    /// Creates the initial state for a new card.
    /// </summary>
    public static CardState Initial
    {
        get
        {
            return new CardState(
                IsSelected: false,
                ScpVersion: 0x02,
                ScpImplementation: Gp4Net.Domain.Protocol.ScpImplementation.Scp02StaticMac,
                SecureChannel: Maybe<SecureChannelState>.None,
                CurrentKeys: null,
                HostChallenge: null,
                CardChallenge: null,
                DataObjects: ImmutableDictionary<ushort, byte[]>.Empty,
                Applications: ImmutableDictionary<string, InstalledApplication>.Empty,
                LoadFiles: ImmutableList<LoadFile>.Empty,
                InstalledKeys: ImmutableDictionary<byte, IKeySet>.Empty,
                DefaultKeyVersion: 0xFF,
                SequenceCounters: ImmutableDictionary<byte, byte[]>.Empty
            );
        }
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
    public Maybe<Gp4Net.Domain.Keys.SessionKeys> SessionKeys
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
    public CardState WithChallenges(byte[]? hostChallenge, byte[]? cardChallenge) => this with
    {
        HostChallenge = hostChallenge,
        CardChallenge = cardChallenge
    };


    /// <summary>
    /// Creates a new state with updated current keys.
    /// </summary>
    public CardState WithKeys(IKeySet keys) => this with { CurrentKeys = keys };

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
        if (SequenceCounters.TryGetValue(keyVersion, out var counter))
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
        var currentCounter = GetSequenceCounter(keyVersion);
        var newCounter = IncrementCounter(currentCounter);
        return this with { SequenceCounters = SequenceCounters.SetItem(keyVersion, newCounter) };
    }

    /// <summary>
    /// Creates a new state with a reset sequence counter for the specified key version.
    /// This should be called when a keyset is created or replaced.
    /// </summary>
    public CardState WithResetSequenceCounter(byte keyVersion)
    {
        // Return appropriate reset counter based on SCP version
        var resetCounter = ScpVersion == 0x02 
            ? new byte[] { 0x00, 0x01 } // 2-byte counter for SCP02
            : new byte[] { 0x00, 0x00, 0x01 }; // 3-byte counter for SCP03
        return this with { SequenceCounters = SequenceCounters.SetItem(keyVersion, resetCounter) };
    }

    /// <summary>
    /// Increments a counter in big-endian format.
    /// Handles both 2-byte (SCP02) and 3-byte (SCP03) counters.
    /// </summary>
    private static byte[] IncrementCounter(byte[] counter)
    {
        var newCounter = new byte[counter.Length];
        System.Array.Copy(counter, newCounter, counter.Length);

        switch (counter.Length)
        {
            // Increment in big-endian format
            case 2:
            {
                // 2-byte counter for SCP02
                var value = (newCounter[0] << 8) | newCounter[1];
                value++;
                newCounter[0] = (byte)(value >> 8);
                newCounter[1] = (byte)value;
                break;
            }
            case 3:
            {
                // 3-byte counter for SCP03
                var value = (newCounter[0] << 16) | (newCounter[1] << 8) | newCounter[2];
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
    /// Resets the card state to initial conditions.
    /// </summary>
    public CardState Reset() => Initial with
    {
        ScpVersion = this.ScpVersion,
        ScpImplementation = this.ScpImplementation,
        DataObjects = this.DataObjects,
        InstalledKeys = this.InstalledKeys,
        DefaultKeyVersion = this.DefaultKeyVersion,
        SequenceCounters = this.SequenceCounters // Preserve sequence counters across resets
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