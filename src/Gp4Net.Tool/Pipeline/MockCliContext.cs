using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Mock implementation of ICliExecutionContext for testing.
/// </summary>
[PublicAPI]
public class MockCliContext : ICliExecutionContext
{
    public IDisplayService Display { get; }
    public ICardService CardService { get; }
    private readonly Gp4Net.Services.IGlobalPlatformService _globalPlatformService;
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

    public MockCliContext(
        IDisplayService display = null,
        ICardService cardService = null,
        Gp4Net.Services.IGlobalPlatformService globalPlatformService = null,
        IKeysetResolver keysetResolver = null
    )
    {
        Display = display ?? new MockDisplayService();
        CardService = cardService ?? new MockCardService();
        _globalPlatformService = globalPlatformService ?? throw new ArgumentNullException(nameof(globalPlatformService), "Must provide functional IGlobalPlatformService");
        KeysetResolver = keysetResolver ?? new MockKeysetResolver();
    }

    public Gp4Net.Services.IGlobalPlatformService GetGlobalPlatformService()
    {
        MethodCalls.Add("GetGlobalPlatformService()");
        return _globalPlatformService;
    }

    public async Task<ICliExecutionContext> RequireCardConnection(Maybe<string> readerName = default)
    {
        var readerNameString = readerName.HasValue ? readerName.Value : "auto";
        MethodCalls.Add($"RequireCardConnection({readerNameString})");

        if (!ShouldConnectSucceed)
        {
            throw new InvalidOperationException("Mock card connection failed");
        }

        await Task.Delay(1); // Simulate async operation
        return this;
    }

    public async Task<ICliExecutionContext> RequireSecureChannel(
        byte securityLevel = 1,
        Maybe<string> keyset = default
    )
    {
        var keysetString = keyset.HasValue ? keyset.Value : "";
        MethodCalls.Add($"RequireSecureChannel({securityLevel}, {keysetString})");

        if (!ShouldSecureChannelSucceed)
        {
            throw new InvalidOperationException("Mock secure channel establishment failed");
        }

        await Task.Delay(1); // Simulate async operation
        return this;
    }

    public async Task<int> ExecuteAsync(Func<ICliExecutionContext, Task<int>> commandLogic)
    {
        MethodCalls.Add("ExecuteAsync(async)");
        return await commandLogic(this);
    }

    public async Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic)
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

    public IReadOnlyList<string> GetReaders() => ["Mock Reader 1", "Mock Reader 2"];

    public bool Connect(string readerName) => true;

    public void Disconnect() { }

    public byte[] GetAtr() => [0x3B, 0x00];

    public CardResponse SendCommand(byte[] command) => new([], 0x9000);

    public CardResponse SendCommand(IApduCommand command) => new([], 0x9000);

    public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
    {
        IsSecureChannelEstablished = true;
        return true;
    }

    public void Dispose() { }
}

// MockGlobalPlatformService removed - use functional services with DI in tests

/// <summary>
/// Mock implementation of IKeysetResolver for testing.
/// </summary>
[PublicAPI]
public class MockKeysetResolver : IKeysetResolver
{
    public Domain.Keys.IKeySet ResolveKeyset(
        string keysetSpec,
        Dictionary<string, string> keysetParams,
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion,
        Domain.Commands.InitializeUpdateResponse cardResponse = null
    ) => new MockKeySet();
}

/// <summary>
/// Mock implementation of IKeySet for testing.
/// </summary>
[PublicAPI]
public class MockKeySet : Domain.Keys.IKeySet
{
    public byte KeyVersion
    {
        get
        {
            return 0xFF;
        }
    }
    public byte KeyId
    {
        get
        {
            return 0x00;
        }
    }
    public byte[] EncKey
    {
        get
        {
            return new byte[16];
        }
    }
    public byte[] MacKey
    {
        get
        {
            return new byte[16];
        }
    }
    public byte[] DekKey
    {
        get
        {
            return new byte[16];
        }
    }

    public void Dispose() { }
}