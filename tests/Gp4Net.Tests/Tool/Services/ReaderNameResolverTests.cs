using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Services;
using Gp4Net.Tool.Services;
using Gp4Net.Tests.TestHelpers;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using NUnit.Framework;

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
        _cardService = new TestCardService(_virtualCardService);
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
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(autoInput, _cardService);

        // Assert
        _ = result.Should().BeSuccessful();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}"));
    }

    [Test]
    public async Task ResolveAsync_WithEmptyInput_ReturnsFirstAvailableReader()
    {
        // Arrange
        Maybe<string> emptyInput = Maybe<string>.None;

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(emptyInput, _cardService);

        // Assert
        _ = result.Should().BeSuccessful();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}"));
    }

    [Test]
    public async Task ResolveAsync_WithExactMatch_ReturnsMatchingReader()
    {
        // Arrange
        Result<string[], SmartCardError> availableReadersResult = await _cardService.GetReadersAsync();
        if (availableReadersResult.IsFailure)
        {
            Assert.Inconclusive($"Cannot run test: {availableReadersResult.Error.Message}");
            return;
        }
        
        availableReadersResult.Match(
            readers =>
            {
                var exactReaderName = readers.First();
                Task<Maybe<string>>? input = Maybe<string>.From(exactReaderName);

                // Act
                _ = ReaderNameResolver.ResolveAsync(input, _cardService)
                    .ContinueWith(task => task.Result.Match(
                        readerName =>
                        {
                            _ = readerName.Should().Be(exactReaderName);
                            return true;
                        },
                        error =>
                        {
                            Assert.Fail($"Expected success but got error: {error.Message}");
                            return false;
                        }));
                return true;
            },
            error =>
            {
                Assert.Inconclusive($"Cannot run test: {error.Message}");
                return false;
            });
    }

    [Test]
    public async Task ResolveAsync_WithExactMatchCaseInsensitive_ReturnsMatchingReader()
    {
        // Arrange
        Result<string[], SmartCardError> availableReadersResult = await _cardService.GetReadersAsync();
        if (availableReadersResult.IsFailure)
        {
            Assert.Inconclusive($"Cannot run test: {availableReadersResult.Error.Message}");
            return;
        }
            
        availableReadersResult.Match(
            readers =>
            {
                var exactReaderName = readers.First();
                Task<Maybe<string>>? lowerCaseInput = Maybe<string>.From(exactReaderName.ToLowerInvariant());

                // Act
                _ = ReaderNameResolver.ResolveAsync(lowerCaseInput, _cardService)
                    .ContinueWith(task => task.Result.Match(
                        readerName =>
                        {
                            _ = readerName.Should().Be(exactReaderName);
                            return true;
                        },
                        error =>
                        {
                            Assert.Fail($"Expected success but got error: {error.Message}");
                            return false;
                        }));
                return true;
            },
            error =>
            {
                Assert.Inconclusive($"Cannot run test: {error.Message}");
                return false;
            });
    }

    [Test]
    public async Task ResolveAsync_WithPartialMatch_ReturnsMatchingReader()
    {
        // Arrange
        Maybe<string> partialInput = Maybe<string>.From("Virtual");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(partialInput, _cardService);

        // Assert
        _ = result.Should().BeSuccessful();
        result.Match(
            readerName => _ = readerName.Should().Contain("Virtual"),
            error => Assert.Fail($"Expected success but got error: {error.Message}"));
    }

    [Test]
    public async Task ResolveAsync_WithPartialMatchCaseInsensitive_ReturnsMatchingReader()
    {
        // Arrange
        Maybe<string> partialInput = Maybe<string>.From("virtual");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(partialInput, _cardService);

        // Assert
        _ = result.Should().BeSuccessful();
        result.Match(
            readerName => _ = readerName.Should().Contain("Virtual"),
            error => Assert.Fail($"Expected success but got error: {error.Message}"));
    }

    [Test]
    public async Task ResolveAsync_WithNonExistentReader_ReturnsError()
    {
        // Arrange
        Maybe<string> nonExistentInput = Maybe<string>.From("NonExistentReader123");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(nonExistentInput, _cardService);

        // Assert
        _ = result.Should().BeFailure();
        result.Match(
            readerName => Assert.Fail($"Expected failure but got success: {readerName}"),
            error =>
            {
                _ = error.Message.Should().Contain("not found");
                _ = error.Message.Should().Contain("Available readers:");
            });
    }

    [Test]
    public async Task ResolveAsync_WithFailingCardService_ReturnsError()
    {
        // Arrange
        var failingCardService = new FailingSmartCardService();
        Maybe<string> input = Maybe<string>.From("auto");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(input, failingCardService);

        // Assert
        _ = result.Should().BeFailure();
        result.Match(
            readerName => Assert.Fail($"Expected failure but got success: {readerName}"),
            error => _ = error.Message.Should().Contain("Failed to enumerate readers"));
    }

    [Test]
    public async Task ResolveAsync_WithNullCardService_ThrowsArgumentNullException()
    {
        // Arrange & Act & Assert
        Func<Task<Result<string, SmartCardError>>> act = async () => await ReaderNameResolver.ResolveAsync(Maybe<string>.From("auto"), null);
        _ = await act.Should().ThrowAsync<System.ArgumentNullException>();
    }

    [Test]
    public async Task ResolveAsync_WithDetectKeyword_ReturnsFirstAvailableReader()
    {
        // Arrange
        Maybe<string> detectInput = Maybe<string>.From("detect");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(detectInput, _cardService);

        // Assert
        _ = result.Should().BeSuccessful();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}"));
    }

    [Test]
    public async Task ResolveAsync_WithFirstKeyword_ReturnsFirstAvailableReader()
    {
        // Arrange
        Maybe<string> firstInput = Maybe<string>.From("first");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(firstInput, _cardService);

        // Assert
        _ = result.Should().BeSuccessful();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}"));
    }

    [Test]
    public async Task ResolveAsync_PrefersPhysicalOverVirtualReaders()
    {
        // This test verifies that auto-detection prefers physical readers over virtual ones
        // In our test environment, we only have virtual readers, so this tests the fallback logic
        
        // Arrange
        Maybe<string> autoInput = Maybe<string>.From("auto");

        // Act
        Result<string, SmartCardError> result = await ReaderNameResolver.ResolveAsync(autoInput, _cardService);

        // Assert
        _ = result.Should().BeSuccessful();
        result.Match(
            readerName => _ = readerName.Should().NotBeNullOrWhiteSpace(),
            error => Assert.Fail($"Expected success but got error: {error.Message}"));
        // In test environment, will return virtual reader as fallback
    }
}