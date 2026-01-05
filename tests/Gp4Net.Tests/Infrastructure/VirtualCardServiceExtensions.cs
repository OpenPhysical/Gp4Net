using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using JetBrains.Annotations;

namespace Gp4Net.Tests.Infrastructure;

/// <summary>
/// Extension methods for VirtualCardService to support legacy test methods.
/// Provides compatibility layer for existing test infrastructure.
/// </summary>
[PublicAPI]
public static class VirtualCardServiceExtensions
{
    /// <summary>
    /// Sets up a test environment with multiple virtual readers.
    /// Creates test readers for use in test scenarios.
    /// </summary>
    /// <param name="service">The virtual card service to configure.</param>
    /// <returns>The configured service for method chaining.</returns>
    public static VirtualCardService SetupTestEnvironment(this VirtualCardService service)
    {
        var manager = new VirtualReaderManagerBuilder()
            .WithP71Reader("Virtual P71 Reader 00 00")
            .Value.WithP71Reader("Virtual Test Reader 01 00")
            .Value.WithP71Reader("Virtual Debug Reader 02 00")
            .Value.Build();

        return new VirtualCardService(manager, Maybe<VirtualCardReader>.None, false);
    }

    /// <summary>
    /// Gets all available readers as a collection.
    /// Provides compatibility with tests that expect reader enumeration.
    /// </summary>
    /// <param name="service">The virtual card service.</param>
    /// <returns>Collection of available reader names.</returns>
    public static IReadOnlyList<string> GetReadersLegacy(this VirtualCardService service)
    {
        return service.GetReaderManager().GetReaderNames();
    }

    /// <summary>
    /// Asynchronously gets all available readers.
    /// Provides async compatibility for reader discovery operations.
    /// </summary>
    /// <param name="service">The virtual card service.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Task containing result with collection of available reader names.</returns>
    public static Task<Result<string[], SmartCardError>> GetReadersAsync(
        this VirtualCardService service,
        CancellationToken cancellationToken = default
    )
    {
        return service
            .ConnectAsync(string.Empty)
            .ContinueWith(_ => service.GetReaders(), cancellationToken);
    }

    /// <summary>
    /// Transmits an APDU command asynchronously to the connected card.
    /// Provides compatibility layer for tests expecting TransmitAsync method.
    /// Uses functional approach - failures are returned as exceptions in Task to match existing test expectations.
    /// </summary>
    /// <param name="service">The virtual card service.</param>
    /// <param name="command">The APDU command bytes to transmit.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Task containing response bytes including status word.</returns>
    public static Task<byte[]> TransmitAsync(
        this VirtualCardService service,
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        var response = service.SendCommand(command);

        return response.Error.Match(
            error => Task.FromException<byte[]>(new InvalidOperationException(error.ToString())),
            () =>
            {
                // Combine data and status word as tests expect
                byte[] responseBytes = new byte[response.Data.Length + 2];
                response.Data.CopyTo(responseBytes, 0);

                // Add status word (big-endian)
                responseBytes[^2] = (byte)(response.StatusWord >> 8);
                responseBytes[^1] = (byte)(response.StatusWord & 0xFF);

                return Task.FromResult(responseBytes);
            }
        );
    }

    /// <summary>
    /// Creates a test keyset resolver for unit tests.
    /// Provides standard test key sets that tests can use.
    /// </summary>
    /// <returns>A keyset resolver populated with test keys.</returns>
    public static TestKeysetResolver CreateTestKeysetResolver()
    {
        var resolver = new TestKeysetResolver();

        // Add default GlobalPlatform test keys
        var defaultScp02Keys = Scp02KeySet.Create(
            encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            keyVersion: 1
        );

        return defaultScp02Keys.Match(
            keys =>
            {
                var resolverWithTestKeys = resolver.AddKeyset("GP_TEST_KEYS", keys);
                return resolverWithTestKeys.AddKeyset("DEFAULT", keys);
            },
            error => resolver // Return empty resolver on key creation failure
        );
    }
}

/// <summary>
/// Test implementation of IKeysetResolver for unit testing.
/// Provides minimal implementation that returns test keys for all methods.
/// </summary>
[PublicAPI]
public class TestKeysetResolver : IKeysetResolver
{
    private readonly IReadOnlyDictionary<string, IKeySet> _keysets;

    /// <summary>
    /// Initializes a new instance with empty keysets.
    /// </summary>
    public TestKeysetResolver()
        : this(new Dictionary<string, IKeySet>()) { }

    /// <summary>
    /// Initializes a new instance with provided keysets.
    /// </summary>
    private TestKeysetResolver(IReadOnlyDictionary<string, IKeySet> keysets)
    {
        _keysets = keysets;
    }

    public Result<IKeySet, SmartCardError> ResolveFromHexKeys(
        string hexEncKey,
        string hexMacKey,
        string hexDekKey,
        byte keyVersion
    )
    {
        return CreateDefaultScp02KeySet();
    }

    public Result<Scp02KeySet, SmartCardError> ResolveScp02KeySet(string keyId, byte keyVersion)
    {
        return CreateDefaultScp02KeySet()
            .Bind(keyset =>
                keyset is Scp02KeySet scp02Keys
                    ? Result.Success<Scp02KeySet, SmartCardError>(scp02Keys)
                    : Result.Failure<Scp02KeySet, SmartCardError>(
                        SmartCardError.InvalidArgument("Failed to create SCP02 keys")
                    )
            );
    }

    public Result<Scp03KeySet, SmartCardError> ResolveScp03KeySet(string keyId, byte keyVersion)
    {
        return CreateDefaultScp03KeySet();
    }

    public Result<IKeySet, SmartCardError> GetTestKeys(byte protocolVersion, byte keyVersion)
    {
        return protocolVersion == 0x03
            ? CreateDefaultScp03KeySet().Map(keyset => (IKeySet)keyset)
            : CreateDefaultScp02KeySet();
    }

    public Result<IKeySet, SmartCardError> ResolveKeyset(
        string keysetName,
        Dictionary<string, string> parameters,
        Maybe<byte[]> encKey,
        Maybe<byte[]> macKey,
        Maybe<byte[]> dekKey,
        byte keyVersion,
        Maybe<InitializeUpdateResponse> cardResponse
    )
    {
        return Maybe<string>
            .From(keysetName)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .ToResult(SmartCardError.InvalidArgument("Keyset identifier cannot be null or empty"))
            .Bind(id =>
                Maybe<IKeySet>
                    .From(_keysets.TryGetValue(id, out var keyset) ? keyset : default)
                    .ToResult(SmartCardError.InvalidArgument($"Keyset '{id}' not found"))
            );
    }

    /// <summary>
    /// Adds a keyset to the resolver for testing.
    /// Returns a new resolver instance with the added keyset.
    /// </summary>
    /// <param name="identifier">The identifier for the keyset.</param>
    /// <param name="keyset">The keyset to add.</param>
    /// <returns>New resolver instance with the keyset added.</returns>
    public TestKeysetResolver AddKeyset(string identifier, IKeySet keyset)
    {
        return Maybe<string>
            .From(identifier)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Match(
                id =>
                {
                    var newKeysets = new Dictionary<string, IKeySet>(_keysets) { [id] = keyset };
                    return new TestKeysetResolver(newKeysets);
                },
                () => this // Return unchanged if invalid identifier
            );
    }

    /// <summary>
    /// Creates a new empty resolver.
    /// </summary>
    /// <returns>Empty keyset resolver.</returns>
    public TestKeysetResolver Clear()
    {
        return new TestKeysetResolver();
    }

    /// <summary>
    /// Gets the number of keysets currently stored.
    /// </summary>
    public int Count => _keysets.Count;

    private static Result<IKeySet, SmartCardError> CreateDefaultScp02KeySet()
    {
        return Scp02KeySet
            .Create(
                encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
                macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
                dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
                keyVersion: 1
            )
            .Map(keyset => (IKeySet)keyset);
    }

    private static Result<Scp03KeySet, SmartCardError> CreateDefaultScp03KeySet()
    {
        return Scp03KeySet.Create(
            encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            keyVersion: 1
        );
    }
}

/// <summary>
/// Test context helper for creating pipeline contexts in tests.
/// Provides factory methods for common test context scenarios.
/// </summary>
[PublicAPI]
public static class TestContextHelper
{
    /// <summary>
    /// Gets the project root directory for test resource access.
    /// Returns the directory containing the solution file.
    /// </summary>
    /// <returns>The path to the project root directory.</returns>
    public static string GetProjectRootDirectory()
    {
        var current = Directory.GetCurrentDirectory();
        return FindRoot(current).GetValueOrDefault(current);

        static Maybe<string> FindRoot(string start)
        {
            var candidate = new DirectoryInfo(start);

            while (candidate is not null)
            {
                if (
                    Directory.Exists(Path.Combine(candidate.FullName, "src"))
                    && File.Exists(Path.Combine(candidate.FullName, "Gp4Net.sln"))
                )
                {
                    return candidate.FullName;
                }

                candidate = candidate.Parent;
            }

            return Maybe<string>.None;
        }
    }

    /// <summary>
    /// Creates an empty test context for basic test scenarios.
    /// </summary>
    /// <returns>An empty immutable pipeline context.</returns>
    public static IPipelineContext Empty() => ImmutablePipelineContext.Empty;

    /// <summary>
    /// Creates a test context with a specific keyset.
    /// </summary>
    /// <param name="keyset">The keyset to include in the context.</param>
    /// <returns>Pipeline context containing the keyset.</returns>
    public static IPipelineContext WithKeyset(KeySet keyset)
    {
        return ImmutablePipelineContext.Empty.With("Keyset", keyset);
    }

    /// <summary>
    /// Creates a test context with secure channel state.
    /// </summary>
    /// <param name="channelState">The secure channel state.</param>
    /// <returns>Pipeline context containing the channel state.</returns>
    public static IPipelineContext WithSecureChannel(SecureChannelState channelState)
    {
        return ImmutablePipelineContext.Empty.With("SecureChannelState", channelState);
    }

    /// <summary>
    /// Creates a test context with both keyset and secure channel state.
    /// </summary>
    /// <param name="keyset">The keyset to include.</param>
    /// <param name="channelState">The secure channel state.</param>
    /// <returns>Fully configured pipeline context for secure channel tests.</returns>
    public static IPipelineContext WithKeysetAndChannel(
        KeySet keyset,
        SecureChannelState channelState
    )
    {
        return ImmutablePipelineContext
            .Empty.With("Keyset", keyset)
            .With("SecureChannelState", channelState);
    }
}
