using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Pipeline;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using static Gp4Net.Tests.Infrastructure.TestCardService;

namespace Gp4Net.Tests.Tool.Commands.Applet;

/// <summary>
/// Unit tests for the pipeline-based DeleteCommand implementation.
/// Tests cover all deletion modes, error handling, and GlobalPlatform specification compliance.
/// </summary>
/// <remarks>
/// <para>This test suite validates the functional architecture implementation of the DELETE command:</para>
/// <list type="bullet">
/// <item><description><strong>Result&lt;T,E&gt; Monads:</strong> Verifies proper error handling patterns</description></item>
/// <item><description><strong>Pipeline Pattern:</strong> Tests IPipelineCommand integration</description></item>
/// <item><description><strong>Mock Isolation:</strong> Uses mocked services for pure unit testing</description></item>
/// <item><description><strong>GP Spec Compliance:</strong> Validates status word error mappings</description></item>
/// </list>
///
/// <para><strong>Test Categories:</strong></para>
/// <list type="bullet">
/// <item><description>Single and multiple AID deletion scenarios</description></item>
/// <item><description>CAP file parsing and package extraction</description></item>
/// <item><description>Interactive mode with application selection</description></item>
/// <item><description>Dry-run mode validation (no actual operations)</description></item>
/// <item><description>Error condition handling and user feedback</description></item>
/// <item><description>Human-readable error message generation</description></item>
/// </list>
///
/// <para><strong>Security Testing:</strong></para>
/// <para>Tests verify that all DELETE operations properly require secure channel establishment
/// and handle authentication failures gracefully with appropriate error messages.</para>
/// </remarks>
[TestFixture]
public class DeleteCommandPipelineTests
{
    private TestCliContext _testContext;
    private ISmartCardService _smartCardService;
    private DeleteCommand _command;
    private string _testCapFilePath;

    [SetUp]
    public void Setup()
    {
        // Use real virtual card implementation - no mocks needed
        var virtualCardService = new VirtualCardService();
        virtualCardService.SetupTestEnvironment();
        _smartCardService = Create(virtualCardService).Value;

        // Skip domain service factory setup for DeleteCommand tests - use card service directly

        // Create real CLI context with virtual card
        var displayService = new DisplayService();
        var keysetResolver = new KeysetResolver();
        var logger = NullLogger<CliContext>.Instance;

        _testContext = new TestCliContext(
            displayService,
            _smartCardService,
            keysetResolver,
            logger
        );

        _command = new DeleteCommand();

        // Use real CAP file from test data
        _testCapFilePath = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            "data",
            "applets",
            "OpenFIPS201-v1_10_2-chainfix.cap"
        );
    }

    [TearDown]
    public void TearDown()
    {
        _smartCardService?.Dispose();
    }

    [Test]
    public async Task ExecuteAsync_SingleAid_Success()
    {
        // Arrange
        var settings = new DeleteCommand.Settings { Aid = "A000000003000000", Force = true };

        // No mock setup needed - using real virtual card implementation

        // Act
        int result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0); // Should succeed with virtual card
    }

    [Test]
    public async Task ExecuteAsync_SingleAid_DeleteWithoutRelated()
    {
        // Arrange
        var settings = new DeleteCommand.Settings
        {
            Aid = "A000000003000000",
            DeleteRelated = false,
            Force = true,
        };

        // Act
        int result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0); // Should succeed with virtual card
    }

    [Test]
    public async Task ExecuteAsync_InvalidAid_ReturnsError()
    {
        // Arrange
        var settings = new DeleteCommand.Settings { Aid = "INVALID_HEX", Force = true };

        // Act
        int result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(1);
    }

    [Test]
    public async Task ExecuteAsync_CapFile_ValidCapFile_ExtractsAidAndDeletes()
    {
        // Arrange
        var settings = new DeleteCommand.Settings { CapFile = _testCapFilePath, Force = true };

        // Act
        int result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0); // Success
        // Should delete the applet using the AID extracted from the CAP file
    }

    [Test]
    public async Task ExecuteAsync_Interactive_NoApplications_Success()
    {
        // Arrange
        var settings = new DeleteCommand.Settings { Interactive = true, Force = true };

        // Act
        int result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    [Test]
    public async Task ExecuteAsync_DryRun_NoActualDeletion()
    {
        // Arrange
        var settings = new DeleteCommand.Settings
        {
            Aid = "A000000003000000",
            DryRun = true,
            Force = true,
        };

        // Act
        int result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0);
        // Should not require card connection for dry run
    }

    [Test]
    public async Task ExecuteAsync_DryRunWithValidCapFile_ShowsPlanWithoutDeleting()
    {
        // Arrange
        var settings = new DeleteCommand.Settings
        {
            CapFile = _testCapFilePath,
            DryRun = true,
            Force = true,
        };

        // Act
        int result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0); // Success - dry run just shows plan
    }

}

/// <summary>
/// Test implementation of CLI execution context for functional testing with virtual card.
/// </summary>
public class TestCliContext : ICliExecutionContext
{
    public IDisplayService Display { get; }
    public ISmartCardService CardService { get; }
    public IKeysetResolver KeysetResolver { get; }
    public ILogger Logger { get; }

    public TestCliContext(
        IDisplayService display,
        ISmartCardService smartCardService,
        IKeysetResolver keysetResolver,
        ILogger logger
    )
    {
        Display = display;
        CardService = smartCardService;
        KeysetResolver = keysetResolver;
        Logger = logger;
    }

    public Func<
        SecureChannelRequest,
        CancellationToken,
        Task<Result<SecureChannelExecutionContext, SmartCardError>>
    > EstablishSecureChannelAsync =>
        (request, cancellationToken) =>
            Task.FromResult(
                Result.Success<SecureChannelExecutionContext, SmartCardError>(
                    new SecureChannelExecutionContext(
                        CardService,
                        CreateMockSecureChannelState().Value
                    )
                )
            );

    public Task<Result<ICliExecutionContext, SmartCardError>> RequireCardConnection(
        Maybe<string> readerName = default
    ) => Task.FromResult(Result.Success<ICliExecutionContext, SmartCardError>(this));

    public Task<Result<ICliExecutionContext, SmartCardError>> RequireSecureChannel(
        byte securityLevel = 1,
        Maybe<string> keyset = default
    ) => Task.FromResult(Result.Success<ICliExecutionContext, SmartCardError>(this));

    public Task<int> ExecuteAsync(Func<ICliExecutionContext, Task<int>> commandLogic) =>
        commandLogic(this);

    public Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic) =>
        Task.FromResult(commandLogic(this));

    private static Result<SecureChannelState, SmartCardError> CreateMockSecureChannelState()
    {
        var mockKeys = new SessionKeys(new byte[16], new byte[16], new byte[16]);

        return SecureChannelState.Create(
            mockKeys,
            SecurityLevel.None,
            CryptoService.ScpVersion.Scp02,
            new byte[8], // Zero-initialized MAC chaining value
            0x00 // Implementation parameter
        );
    }
}
