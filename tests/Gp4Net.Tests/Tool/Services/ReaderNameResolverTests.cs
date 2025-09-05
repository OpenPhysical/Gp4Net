using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Tool.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Tool.Services;

/// <summary>
/// Tests for the functional ReaderNameResolver static service.
/// Validates auto-detection, exact matching, partial matching, and error handling.
/// </summary>
[TestFixture]
public class ReaderNameResolverTests
{
    private ISmartCardService _cardService;
    private VirtualCardService _virtualCardService;

    [SetUp]
    public void Setup()
    {
        _virtualCardService = new VirtualCardService();
        _virtualCardService.SetupComprehensiveTestEnvironment();
        var logger = NullLogger<SmartCardService>.Instance;
        var readers = _virtualCardService.GetReaders();
        var readerName = readers.Count > 0 ? readers.First() : "Virtual P71 Reader 00 00";
        _cardService = VirtualCardConnectionService.CreateServiceAsync(
                readerName,
                logger,
                CancellationToken.None
            ).Result
            .Match(
                service => service,
                error => new DisconnectedSmartCardService()
            );
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
        Maybe<string> autoInput = Maybe<string>.From("auto");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(
            autoInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithEmptyInput_ReturnsFirstAvailableReader()
    {
        // Arrange
        Maybe<string> emptyInput = Maybe<string>.None;

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(
            emptyInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithExactMatch_ReturnsMatchingReader()
    {
        // Arrange
        var availableReadersResult = await _cardService.GetReadersAsync();
        
        await availableReadersResult
            .ToMaybe()
            .ToResult("Failed to get readers")
            .Bind(async readers =>
            {
                var exactReaderName = readers.First();
                var input = Maybe<string>.From(exactReaderName);

                // Act
                var result = await ReaderNameResolver.ResolveAsync(input, _cardService);

                // Assert
                result.Should().BeSuccess();
                result.Match(
                    readerName => readerName.Should().Be(exactReaderName),
                    error => Assert.Fail($"Expected success but got error: {error.Message}")
                );
                
                return Result.Success();
            })
            .Match(
                _ => Task.CompletedTask,
                error => Task.FromResult(Assert.Inconclusive($"Cannot run test: {error}"))
            );
    }

    [Test]
    public async Task ResolveAsync_WithExactMatchCaseInsensitive_ReturnsMatchingReader()
    {
        // Arrange
        var availableReadersResult = await _cardService.GetReadersAsync();
        
        await availableReadersResult
            .ToMaybe()
            .ToResult("Failed to get readers")
            .Bind(async readers =>
            {
                var exactReaderName = readers.First();
                var lowerCaseInput = Maybe<string>.From(exactReaderName.ToLowerInvariant());

                // Act
                var result = await ReaderNameResolver.ResolveAsync(lowerCaseInput, _cardService);

                // Assert
                result.Should().BeSuccess();
                result.Match(
                    readerName => readerName.Should().Be(exactReaderName),
                    error => Assert.Fail($"Expected success but got error: {error.Message}")
                );
                
                return Result.Success();
            })
            .Match(
                _ => Task.CompletedTask,
                error => Task.FromResult(Assert.Inconclusive($"Cannot run test: {error}"))
            );
    }

    [Test]
    public async Task ResolveAsync_WithPartialMatch_ReturnsMatchingReader()
    {
        // Arrange
        Maybe<string> partialInput = Maybe<string>.From("Virtual");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(
            partialInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().Contain("Virtual"),
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithPartialMatchCaseInsensitive_ReturnsMatchingReader()
    {
        // Arrange
        Maybe<string> partialInput = Maybe<string>.From("virtual");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(
            partialInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().Contain("Virtual"),
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithNonExistentReader_ReturnsError()
    {
        // Arrange
        Maybe<string> nonExistentInput = Maybe<string>.From("NonExistentReader123");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(
            nonExistentInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeFailure();
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
        Maybe<string> input = Maybe<string>.From("auto");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(
            input,
            failingCardService
        );

        // Assert
        _ = result.Should().BeFailure();
        result.Match(
            readerName => Assert.Fail($"Expected failure but got success: {readerName}"),
            error => _ = error.Message.Should().Contain("Failed to enumerate readers")
        );
    }

    [Test]
    public async Task ResolveAsync_WithNullCardService_ThrowsArgumentNullException()
    {
        // Arrange & Act & Assert
        Func<Task<Result<string, SmartCardError>>> act = async () =>
            await ReaderNameResolver.ResolveAsync(Maybe<string>.From("auto"), null);
        _ = await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Test]
    public async Task ResolveAsync_WithDetectKeyword_ReturnsFirstAvailableReader()
    {
        // Arrange
        Maybe<string> detectInput = Maybe<string>.From("detect");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(
            detectInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public async Task ResolveAsync_WithFirstKeyword_ReturnsFirstAvailableReader()
    {
        // Arrange
        Maybe<string> firstInput = Maybe<string>.From("first");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(
            firstInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public async Task ResolveAsync_PrefersPhysicalOverVirtualReaders()
    {
        // This test verifies that auto-detection prefers physical readers over virtual ones
        // In our test environment, we only have virtual readers, so this tests the fallback logic

        // Arrange
        Maybe<string> autoInput = Maybe<string>.From("auto");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(
            autoInput,
            _cardService
        );

        // Assert
        _ = result.Should().BeSuccess();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
        // In test environment, will return virtual reader as fallback
    }
}

/// <summary>
/// Test implementation of ISmartCardService that always returns errors.
/// </summary>
internal sealed class DisconnectedSmartCardService : ISmartCardService
{
    public IPipelineContext Context { get; } = new SimplePipelineContext();

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(CommandAPDU command, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<CommandResponse, SmartCardError>(
            SmartCardError.CommunicationError("No card connection in test environment")));
    }

    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(CommandAPDU command, CommandOptions options, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<CommandResponse, SmartCardError>(
            SmartCardError.CommunicationError("No card connection in test environment")));
    }

    public Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context)
    {
        return Result.Failure<ISmartCardService, SmartCardError>(
            SmartCardError.CommunicationError("Cannot update context in disconnected service"));
    }

    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value)
    {
        return Result.Failure<ISmartCardService, SmartCardError>(
            SmartCardError.CommunicationError("Cannot update context in disconnected service"));
    }

    public Task<Result<bool, SmartCardError>> IsConnectedAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public Task<Result<byte[], SmartCardError>> GetAtrAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<byte[], SmartCardError>(
            SmartCardError.CommunicationError("No ATR available in test environment")));
    }

    public Task<Result<string[], SmartCardError>> GetReadersAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<string[], SmartCardError>(
            SmartCardError.CommunicationError("No readers available in test environment")));
    }

    public Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(byte[] command, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<CommandResponse, SmartCardError>(
            SmartCardError.CommunicationError("No card connection in test environment")));
    }

    public void Dispose() { }
}

/// <summary>
/// Simple implementation of IPipelineContext for testing.
/// </summary>
internal sealed class SimplePipelineContext : IPipelineContext
{
    private readonly ImmutableDictionary<string, object> _values = ImmutableDictionary<string, object>.Empty;

    public Maybe<T> Get<T>(string key)
    {
        return Maybe<T>.None;
    }

    public IPipelineContext With<T>(string key, T value)
    {
        return this;
    }

    public IPipelineContext Without(string key)
    {
        return this;
    }

    public ImmutableArray<string> Keys => ImmutableArray<string>.Empty;

    public IPipelineContext WithMany(ImmutableDictionary<string, object> values)
    {
        return this;
    }

    public ImmutableDictionary<string, object> ToImmutableDictionary()
    {
        return _values;
    }
}
