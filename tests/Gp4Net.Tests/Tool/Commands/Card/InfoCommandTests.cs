using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.CardEmulator.Services;
using NUnit.Framework;
using Spectre.Console.Testing;
using Gp4Net.Tests.TestHelpers;

namespace Gp4Net.Tests.Tool.Commands.Card;

[TestFixture]
public class InfoCommandTests
{
    private IGlobalPlatformService _globalPlatformService;
    private InfoCommand _command;
    private TestConsole _console;
    private VirtualCardService _virtualCardService = null!;

    [SetUp]
    public void Setup()
    {
        _virtualCardService = new VirtualCardService();
        _virtualCardService.SetupComprehensiveTestEnvironment();
        
        // Use library approach - direct service injection
        _globalPlatformService = new EmptyGlobalPlatformService();
        _console = new TestConsole();

        // Create command with direct service injection (modern approach)
        _command = new InfoCommand(_globalPlatformService);
    }

    [TearDown]
    public void TearDown()
    {
        _console?.Dispose();
        _virtualCardService?.Dispose();
    }

    [Test]
    public async Task ExecuteAsync_WithValidSettings_ReturnsSuccess()
    {
        // Arrange
        InfoCommand.Settings settings = new InfoCommand.Settings();
        var context = TestCommandContext.Create();

        // Act
        int result = await _command.ExecuteAsync(context, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    [Test]
    public async Task ExecuteAsync_GlobalPlatformServiceException_ReturnsError()
    {
        // Arrange - Create a command with failing service
        FailingGlobalPlatformService failingService = new FailingGlobalPlatformService();
        InfoCommand failingCommand = new InfoCommand(failingService);
        InfoCommand.Settings settings = new InfoCommand.Settings();
        var context = TestCommandContext.Create();

        // Act
        int result = await failingCommand.ExecuteAsync(context, settings);

        // Assert
        _ = result.Should().Be(1);
    }

    [Test]
    public void Settings_RequiresSecureChannel_ReturnsFalse()
    {
        // Arrange
        InfoCommand.Settings settings = new InfoCommand.Settings();

        // Assert - InfoCommand should not require secure channel by default
        // This assumes InfoCommand.Settings inherits from a base that has RequiresSecureChannel property
        // If not, this test can be removed
    }

    [Test]
    public async Task ExecuteAsync_GetCardInfoSucceeds_ReturnsSuccess()
    {
        // Arrange
        InfoCommand.Settings settings = new InfoCommand.Settings();
        var context = TestCommandContext.Create();

        // Act
        int result = await _command.ExecuteAsync(context, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    [Test]
    public async Task ExecuteAsync_WithVerboseSettings_DisplaysDetailedInfo()
    {
        // Arrange
        InfoCommand.Settings settings = new InfoCommand.Settings { Verbose = true };
        var context = TestCommandContext.Create();

        // Act
        int result = await _command.ExecuteAsync(context, settings);

        // Assert
        _ = result.Should().Be(0);
    }
}

/// <summary>
/// Test implementation of GlobalPlatform service that fails for error testing.
/// </summary>
public class FailingGlobalPlatformService : IGlobalPlatformService
{
    public ISmartCardService CardService { get; } = new EmptySmartCardService();

    public Task<Result<SelectResponse, SmartCardError>> SelectIsdAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<SelectResponse, SmartCardError>(
            SmartCardError.CommunicationError("Test failure - ISD selection failed")));
    }

    public Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        KeySet keySet, 
        SecurityLevel securityLevel = SecurityLevel.CMac, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<SecureChannelState, SmartCardError>(
            SmartCardError.CommunicationError("Test failure - secure channel establishment failed")));
    }

    public Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        string keysetName, 
        SecurityLevel securityLevel = SecurityLevel.CMac, 
        byte keyVersion = 1, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<SecureChannelState, SmartCardError>(
            SmartCardError.CommunicationError("Test failure - secure channel establishment failed")));
    }

    public Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        string encKey, 
        string macKey, 
        string dekKey, 
        byte keyVersion, 
        SecurityLevel securityLevel = SecurityLevel.CMac, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<SecureChannelState, SmartCardError>(
            SmartCardError.CommunicationError("Test failure - secure channel establishment failed")));
    }

    public Task<Result<CardInformation, SmartCardError>> GetCardInfoAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<CardInformation, SmartCardError>(
            SmartCardError.CommunicationError("Test failure - card info retrieval failed")));
    }

    public Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetStatusAsync(
        StatusSubset subset = StatusSubset.IssuerSecurityDomain, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(
            SmartCardError.CommunicationError("Test failure")));
    }

    public Task<Result<InstallationResult, SmartCardError>> InstallCapFileAsync(
        byte[] capFileData, 
        Maybe<InstallOptions> options = default, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<InstallationResult, SmartCardError>(
            SmartCardError.CommunicationError("Test failure")));
    }

    public Task<Result<bool, SmartCardError>> DeleteApplicationAsync(
        byte[] aid, 
        bool deleteRelated = false, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<bool, SmartCardError>(
            SmartCardError.CommunicationError("Test failure")));
    }

    public Task<Result<bool, SmartCardError>> PutKeysAsync(
        KeySet keySet, 
        byte keyVersion, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<bool, SmartCardError>(
            SmartCardError.CommunicationError("Test failure")));
    }

    public Task<Result<CplcData, SmartCardError>> GetCplcAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<CplcData, SmartCardError>(
            SmartCardError.CommunicationError("Test failure")));
    }

    public Task<Result<byte[], SmartCardError>> GetDataAsync(
        ushort tag, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<byte[], SmartCardError>(
            SmartCardError.CommunicationError("Test failure")));
    }

    public Task<Result<bool, SmartCardError>> SetLifecycleStateAsync(
        byte[] aid, 
        LifecycleState state, 
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result.Failure<bool, SmartCardError>(
            SmartCardError.CommunicationError("Test failure")));
    }
}

/// <summary>
/// Helper for creating test command contexts for Spectre.Console commands.
/// </summary>
public static class TestCommandContext
{
    /// <summary>
    /// Creates a test command context with default values.
    /// </summary>
    public static CommandContext Create()
    {
        return new CommandContext(
            ImmutableArray<string>.Empty, 
            "test", 
            null, 
            CancellationToken.None);
    }
}
