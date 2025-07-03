using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Gp4Net.Domain;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline
{
    /// <summary>
    /// Mock implementation of ICommandContext for testing.
    /// </summary>
    [PublicAPI]
    public class MockCommandContext : ICommandContext
    {
        public IDisplayService Display { get; }
        public ICardService CardService { get; }
        public IGlobalPlatformService GlobalPlatformService { get; }
        public IKeysetResolver KeysetResolver { get; }

        /// <summary>
        /// Gets the list of method calls made to this mock.
        /// </summary>
        public List<string> MethodCalls { get; } = [];

        /// <summary>
        /// Gets or sets whether card connection should succeed.
        /// </summary>
        public bool ShouldConnectSucceed { get; set; } = true;

        /// <summary>
        /// Gets or sets whether secure channel establishment should succeed.
        /// </summary>
        public bool ShouldSecureChannelSucceed { get; set; } = true;

        public MockCommandContext(
            IDisplayService? display = null,
            ICardService? cardService = null,
            IGlobalPlatformService? globalPlatformService = null,
            IKeysetResolver? keysetResolver = null
        )
        {
            Display = display ?? new MockDisplayService();
            CardService = cardService ?? new MockCardService();
            GlobalPlatformService = globalPlatformService ?? new MockGlobalPlatformService();
            KeysetResolver = keysetResolver ?? new MockKeysetResolver();
        }

        public async Task<ICommandContext> RequireCardConnection(string? readerName = null)
        {
            MethodCalls.Add($"RequireCardConnection({readerName})");

            if (!ShouldConnectSucceed)
            {
                throw new InvalidOperationException("Mock card connection failed");
            }

            await Task.Delay(1); // Simulate async operation
            return this;
        }

        public async Task<ICommandContext> RequireSecureChannel(
            byte securityLevel = 1,
            string? keyset = null
        )
        {
            MethodCalls.Add($"RequireSecureChannel({securityLevel}, {keyset})");

            if (!ShouldSecureChannelSucceed)
            {
                throw new InvalidOperationException("Mock secure channel establishment failed");
            }

            await Task.Delay(1); // Simulate async operation
            return this;
        }

        public async Task<int> ExecuteAsync(Func<ICommandContext, Task<int>> commandLogic)
        {
            MethodCalls.Add("ExecuteAsync(async)");
            return await commandLogic(this);
        }

        public async Task<int> ExecuteAsync(Func<ICommandContext, int> commandLogic)
        {
            MethodCalls.Add("ExecuteAsync(sync)");
            return await Task.FromResult(commandLogic(this));
        }
    }

    /// <summary>
    /// Mock implementation of IDisplayService for testing.
    /// </summary>
    [PublicAPI]
    public class MockDisplayService : IDisplayService
    {
        public List<string> Messages { get; } = [];

        public void Success(string message) => Messages.Add($"SUCCESS: {message}");

        public void Error(string message) => Messages.Add($"ERROR: {message}");

        public void Warning(string message) => Messages.Add($"WARNING: {message}");

        public void Info(string message) => Messages.Add($"INFO: {message}");

        public void Verbose(string message) => Messages.Add($"VERBOSE: {message}");

        public void Exception(Exception exception) =>
            Messages.Add($"EXCEPTION: {exception.Message}");

        public void CardInfo(byte[] atr) => Messages.Add($"CARD_INFO: {Convert.ToHexString(atr)}");

        public void Markup(string markup) => Messages.Add($"MARKUP: {markup}");
    }

    /// <summary>
    /// Mock implementation of ICardService for testing.
    /// </summary>
    [PublicAPI]
    public class MockCardService : ICardService
    {
        public bool IsConnected { get; set; } = true;
        public bool IsSecureChannelEstablished { get; set; } = false;

        public IReadOnlyList<string> GetReaders() => new[] { "Mock Reader 1", "Mock Reader 2" };

        public bool Connect(string readerName) => true;

        public void Disconnect() { }

        public byte[]? GetAtr() => new byte[] { 0x3B, 0x00 };

        public CardResponse SendCommand(byte[] command) => new(Array.Empty<byte>(), 0x9000);

        public CardResponse SendCommand(IApduCommand command) => new(Array.Empty<byte>(), 0x9000);

        public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
        {
            IsSecureChannelEstablished = true;
            return true;
        }

        public void Dispose() { }
    }

    /// <summary>
    /// Mock implementation of IGlobalPlatformService for testing.
    /// </summary>
    [PublicAPI]
    public class MockGlobalPlatformService : IGlobalPlatformService
    {
        public Domain.Commands.SelectResponse SelectIsd() => new(Array.Empty<byte>());

        public Domain.Commands.GetStatusResponse GetStatus(
            Domain.Commands.GetStatusCommand.StatusSubset statusSubset =
                Domain.Commands.GetStatusCommand.StatusSubset.IssuerSecurityDomain
        ) => new([]);

        public System.Collections.Generic.IList<ApplicationInfo> GetApplications() => [];

        public InstallationResult InstallCapFile(
            byte[] capFileData,
            bool installApplets = true,
            bool makeSelectable = true
        ) => new(true);

        public DeletionResult DeleteApplication(byte[] aid, bool deleteRelated = true) => new(true);

        public bool SetLifecycleState(byte[] aid, LifecycleState newState) => true;

        public Domain.CardInfo.CplcData? GetCplc() => new();

        public Domain.CardInfo.CardDataInfo? GetCardData() => new();

        public Domain.CardInfo.CardCapabilities? GetCardCapabilities() => null;

        public Domain.Commands.GetDataResponse? GetData(ushort dataObjectIdentifier) =>
            new(dataObjectIdentifier, Array.Empty<byte>());

        public System.Threading.Tasks.Task<PutKeyResult> PutKeysAsync(
            Domain.Keys.IKeySet newKeySet,
            byte newKeyVersion
        ) => System.Threading.Tasks.Task.FromResult(new PutKeyResult(true));

        public (byte[] Data, ushort StatusWord) SendCommand(IApduCommand command) =>
            (Array.Empty<byte>(), 0x9000);
    }

    /// <summary>
    /// Mock implementation of IKeysetResolver for testing.
    /// </summary>
    [PublicAPI]
    public class MockKeysetResolver : IKeysetResolver
    {
        public Domain.Keys.IKeySet ResolveKeyset(
            string? keysetSpec,
            Dictionary<string, string>? keysetParams,
            byte[]? encKey,
            byte[]? macKey,
            byte[]? dekKey,
            byte keyVersion,
            Domain.Commands.InitializeUpdateResponse? cardResponse = null
        ) => new MockKeySet();
    }

    /// <summary>
    /// Mock implementation of IKeySet for testing.
    /// </summary>
    [PublicAPI]
    public class MockKeySet : Domain.Keys.IKeySet
    {
        public byte KeyVersion => 0xFF;
        public byte[] EncKey => new byte[16];
        public byte[] MacKey => new byte[16];
        public byte[] DekKey => new byte[16];

        public void Dispose() { }
    }
}
