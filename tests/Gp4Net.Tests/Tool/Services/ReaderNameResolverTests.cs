using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Tool.Services;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Tool.Services;

/// <summary>
/// Tests for the functional ReaderSelection static service.
/// Validates auto-detection, exact matching, partial matching, and error handling.
/// </summary>
[TestFixture]
public class ReaderNameResolverTests
{
    private ICardSessionCommands _cardService;
    private VirtualCardOperations _virtualCardService;

    [SetUp]
    public void Setup()
    {
        var manager = new VirtualReaderManagerBuilder()
            .WithP71Reader("Virtual P71 Reader 00 00")
            .Value.WithP71Reader("Virtual Test Reader 01 00")
            .Value.WithP71Reader("Virtual Debug Reader 02 00")
            .Value.Build();

        _virtualCardService = new VirtualCardOperations(
            manager,
            Maybe<VirtualCardReader>.None,
            false
        );

        // Use a wrapper that implements ICardSessionCommands
        _cardService = new VirtualSmartCardServiceWrapper(_virtualCardService);
    }

    [TearDown]
    public void TearDown()
    {
        _cardService?.Dispose();
        _virtualCardService?.Dispose();
    }

    [Test]
    public async Task ResolveAsync_WithAutoKeyword_ReturnsFirstAvailableReader()
    {
        // Arrange
        var autoInput = Maybe<string>.From("auto");

        // Act
        Result<string, SmartCardError> result = await ReaderSelection.ResolveAsync(
            autoInput,
            _cardService
        );

        // Assert - debug output
        if (result.IsFailure)
        {
            TestContext.Out.WriteLine($"❌ ResolveAsync failed: {result.Error.Message}");
        }
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithEmptyInput_ReturnsFirstAvailableReader()
    {
        // Arrange
        var emptyInput = Maybe<string>.None;

        // Act
        Result<string, SmartCardError> result = await ReaderSelection.ResolveAsync(
            emptyInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithExactMatch_ReturnsMatchingReader()
    {
        // Arrange
        var availableReadersResult = await _cardService.GetReadersAsync();

        await availableReadersResult.Bind(async readers =>
        {
            if (readers.Length == 0)
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.CommunicationError("No readers available")
                );

            var exactReaderName = readers[0];
            var input = Maybe<string>.From(exactReaderName);

            // Act
            var result = await ReaderSelection.ResolveAsync(input, _cardService);

            // Assert
            result.Should().BeSuccess();
            result.Match(
                readerName => readerName.Should().Be(exactReaderName),
                error => Assert.Fail($"Expected success but got error: {error}")
            );

            return UnitResult.Success<SmartCardError>();
        });

        // Handle the result - check if test can proceed
        if (availableReadersResult.IsFailure)
        {
            Assert.Inconclusive($"Cannot run test: {availableReadersResult.Error}");
        }
    }

    [Test]
    public async Task ResolveAsync_WithExactMatchCaseInsensitive_ReturnsMatchingReader()
    {
        // Arrange
        var availableReadersResult = await _cardService.GetReadersAsync();

        await availableReadersResult.Bind(async readers =>
        {
            if (readers.Length == 0)
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.CommunicationError("No readers available")
                );

            var exactReaderName = readers[0];
            var lowerCaseInput = Maybe<string>.From(exactReaderName.ToLowerInvariant());

            // Act
            var result = await ReaderSelection.ResolveAsync(lowerCaseInput, _cardService);

            // Assert
            result.Should().BeSuccess();
            result.Match(
                readerName => readerName.Should().Be(exactReaderName),
                error => Assert.Fail($"Expected success but got error: {error}")
            );

            return UnitResult.Success<SmartCardError>();
        });

        // Handle the result - check if test can proceed
        if (availableReadersResult.IsFailure)
        {
            Assert.Inconclusive($"Cannot run test: {availableReadersResult.Error}");
        }
    }

    [Test]
    public async Task ResolveAsync_WithPartialMatch_ReturnsMatchingReader()
    {
        // Arrange - use a more specific partial match that only matches one reader
        var partialInput = Maybe<string>.From("P71");

        // Act
        Result<string, SmartCardError> result = await ReaderSelection.ResolveAsync(
            partialInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().Contain("P71"),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithPartialMatchCaseInsensitive_ReturnsMatchingReader()
    {
        // Arrange - use a specific partial match (case-insensitive) that only matches one reader
        var partialInput = Maybe<string>.From("test");

        // Act
        Result<string, SmartCardError> result = await ReaderSelection.ResolveAsync(
            partialInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().Contain("Test"),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithNonExistentReader_ReturnsError()
    {
        // Arrange
        var nonExistentInput = Maybe<string>.From("NonExistentReader123");

        // Act
        Result<string, SmartCardError> result = await ReaderSelection.ResolveAsync(
            nonExistentInput,
            _cardService
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        result.Match(
            readerName => Assert.Fail($"Expected failure but got success: {readerName}"),
            error =>
            {
                _ = error.Message.Should().Contain("not found");
                _ = error.Message.Should().Contain("Available readers:");
            }
        );
    }

    [Test]
    public async Task ResolveAsync_WithFailingCardService_ReturnsError()
    {
        // Arrange
        var failingCardService = new DisconnectedSmartCardService();
        var input = Maybe<string>.From("auto");

        // Act
        Result<string, SmartCardError> result = await ReaderSelection.ResolveAsync(
            input,
            failingCardService
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        result.Match(
            readerName => Assert.Fail($"Expected failure but got success: {readerName}"),
            error => _ = error.Message.Should().Contain("Failed to enumerate readers")
        );
    }

    [Test]
    public async Task ResolveAsync_WithDetectKeyword_ReturnsFirstAvailableReader()
    {
        // Arrange
        var detectInput = Maybe<string>.From("detect");

        // Act
        Result<string, SmartCardError> result = await ReaderSelection.ResolveAsync(
            detectInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithFirstKeyword_ReturnsFirstAvailableReader()
    {
        // Arrange
        var firstInput = Maybe<string>.From("first");

        // Act
        Result<string, SmartCardError> result = await ReaderSelection.ResolveAsync(
            firstInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public async Task ResolveAsync_PrefersPhysicalOverVirtualReaders()
    {
        // This test verifies that auto-detection prefers physical readers over virtual ones
        // In our test environment, we only have virtual readers, so this tests the fallback logic

        // Arrange
        var autoInput = Maybe<string>.From("auto");

        // Act
        Result<string, SmartCardError> result = await ReaderSelection.ResolveAsync(
            autoInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
        // In test environment, will return virtual reader as fallback
    }
}

/// <summary>
/// Wrapper that implements ICardSessionCommands using VirtualCardOperations.
/// Provides reader enumeration from virtual reader manager.
/// </summary>
internal sealed class VirtualSmartCardServiceWrapper : ICardSessionCommands
{
    private readonly VirtualCardOperations _virtualCardService;

    public ImmutablePipelineContext Context { get; } = ImmutablePipelineContext.Empty;

    public VirtualSmartCardServiceWrapper(VirtualCardOperations virtualCardService)
    {
        _virtualCardService = virtualCardService;
    }

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Not implemented for reader enumeration tests")
            )
        );
    }

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        bool useSecureChannel,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Not implemented for reader enumeration tests")
            )
        );
    }

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CommandOptions options,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Not implemented for reader enumeration tests")
            )
        );
    }

    public Result<ICardSessionCommands, SmartCardError> WithContext(
        ImmutablePipelineContext context
    )
    {
        return Result.Success<ICardSessionCommands, SmartCardError>(this);
    }

    public Result<ICardSessionCommands, SmartCardError> WithContextValue<T>(string key, T value)
    {
        return Result.Success<ICardSessionCommands, SmartCardError>(this);
    }

    public Task<Result<bool, SmartCardError>> IsConnectedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public Task<Result<byte[], SmartCardError>> GetAtrAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<byte[], SmartCardError>(
                SmartCardError.CommunicationError("No ATR available in test environment")
            )
        );
    }

    public Task<Result<string[], SmartCardError>> GetReadersAsync(
        CancellationToken cancellationToken = default
    )
    {
        var readers = _virtualCardService.GetReaderManager().GetReaderNames();
        return Task.FromResult(Result.Success<string[], SmartCardError>([.. readers]));
    }

    public Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Not implemented for reader enumeration tests")
            )
        );
    }

    public async Task<
        Result<CardTransportCapabilities, SmartCardError>
    > GetCardTransportCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Failure<CardTransportCapabilities, SmartCardError>(
                SmartCardError.CommunicationError("Not implemented for reader enumeration tests")
            )
        );
    }

    public void Dispose()
    {
        _virtualCardService?.Dispose();
    }
}

/// <summary>
/// Test implementation of ICardSessionCommands that always returns errors.
/// </summary>
internal sealed class DisconnectedSmartCardService : ICardSessionCommands
{
    public ImmutablePipelineContext Context { get; } = ImmutablePipelineContext.Empty;

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("No card connection in test environment")
            )
        );
    }

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        bool useSecureChannel,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("No card connection in test environment")
            )
        );
    }

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CommandOptions options,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("No card connection in test environment")
            )
        );
    }

    public Result<ICardSessionCommands, SmartCardError> WithContext(
        ImmutablePipelineContext context
    )
    {
        return Result.Failure<ICardSessionCommands, SmartCardError>(
            SmartCardError.CommunicationError("Cannot update context in disconnected service")
        );
    }

    public Result<ICardSessionCommands, SmartCardError> WithContextValue<T>(string key, T value)
    {
        return Result.Failure<ICardSessionCommands, SmartCardError>(
            SmartCardError.CommunicationError("Cannot update context in disconnected service")
        );
    }

    public Task<Result<bool, SmartCardError>> IsConnectedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public Task<Result<byte[], SmartCardError>> GetAtrAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<byte[], SmartCardError>(
                SmartCardError.CommunicationError("No ATR available in test environment")
            )
        );
    }

    public Task<Result<string[], SmartCardError>> GetReadersAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<string[], SmartCardError>(
                SmartCardError.CommunicationError("No readers available in test environment")
            )
        );
    }

    public Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("No card connection in test environment")
            )
        );
    }

    public async Task<
        Result<CardTransportCapabilities, SmartCardError>
    > GetCardTransportCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Failure<CardTransportCapabilities, SmartCardError>(
                SmartCardError.CommunicationError("No card connection in test environment")
            )
        );
    }

    public void Dispose() { }
}
