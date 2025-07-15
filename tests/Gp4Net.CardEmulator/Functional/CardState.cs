using System.Collections.Immutable;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional
{
    /// <summary>
    /// Immutable card state representing the current state of a virtual card.
    /// All state transitions produce new instances rather than mutating existing state.
    /// </summary>
    [PublicAPI]
    public record CardState(
        bool IsSelected,
        bool IsSecureChannelEstablished,
        byte ScpVersion,
        byte ScpImplementation,
        IKeySet? CurrentKeys,
        byte[]? HostChallenge,
        byte[]? CardChallenge,
        SessionKeys? SessionKeys,
        byte SecurityLevel,
        ImmutableDictionary<ushort, byte[]> DataObjects,
        ImmutableDictionary<string, InstalledApplication> Applications,
        ImmutableList<LoadFile> LoadFiles,
        ImmutableDictionary<byte, IKeySet> InstalledKeys,
        byte DefaultKeyVersion
    )
    {
        /// <summary>
        /// Creates the initial state for a new card.
        /// </summary>
        public static CardState Initial => new(
            IsSelected: false,
            IsSecureChannelEstablished: false,
            ScpVersion: 0x02,
            ScpImplementation: 0x15,
            CurrentKeys: null,
            HostChallenge: null,
            CardChallenge: null,
            SessionKeys: null,
            SecurityLevel: 0x00,
            DataObjects: ImmutableDictionary<ushort, byte[]>.Empty,
            Applications: ImmutableDictionary<string, InstalledApplication>.Empty,
            LoadFiles: ImmutableList<LoadFile>.Empty,
            InstalledKeys: ImmutableDictionary<byte, IKeySet>.Empty,
            DefaultKeyVersion: 0xFF
        );

        /// <summary>
        /// Creates a new state with the card selected.
        /// </summary>
        public CardState WithSelected(bool selected = true) => this with { IsSelected = selected };

        /// <summary>
        /// Creates a new state with secure channel established.
        /// </summary>
        public CardState WithSecureChannel(
            bool established, 
            SessionKeys? sessionKeys = null, 
            byte securityLevel = 0x00) => this with 
        { 
            IsSecureChannelEstablished = established,
            SessionKeys = sessionKeys,
            SecurityLevel = securityLevel
        };

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
        /// Resets the card state to initial conditions.
        /// </summary>
        public CardState Reset() => Initial with
        {
            ScpVersion = this.ScpVersion,
            ScpImplementation = this.ScpImplementation,
            DataObjects = this.DataObjects,
            InstalledKeys = this.InstalledKeys,
            DefaultKeyVersion = this.DefaultKeyVersion
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
}