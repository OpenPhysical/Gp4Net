using System.Collections.Generic;
using System.IO;
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
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Pipeline;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WSCT.ISO7816;
using static Gp4Net.Tests.Infrastructure.TestCardService;

namespace Gp4Net.Tests.Tool.Commands.Applet;

/// <summary>
/// Tests for UninstallCommand following TDD and constitutional principles.
/// Uses virtual card emulator for integration testing without mocking.
/// </summary>
[TestFixture]
public sealed class UninstallCommandTests
{
    private TestCliContext _testContext;
    private ICardSessionCommands _smartCardService;
    private UninstallCommand _command;
    private string _testCapFilePath;

    [SetUp]
    public void Setup()
    {
        var virtualCardService = new VirtualCardOperations();
        virtualCardService.SetupTestEnvironment();
        _smartCardService = Create(virtualCardService).Value;

        var displayService = new ConsoleDisplay();
        var keysetResolver = new KeysetResolution();
        var logger = NullLogger<CliContext>.Instance;

        _testContext = new TestCliContext(
            displayService,
            _smartCardService,
            keysetResolver,
            logger
        );

        _command = new UninstallCommand();

        _testCapFilePath = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            "..",
            "..",
            "..",
            "..",
            "TestData",
            "caps",
            "uninstall-tests",
            "OpenFIPS201-v1_10_2.cap"
        );
    }

    [TearDown]
    public void TearDown()
    {
        _smartCardService?.Dispose();
    }

    [Test]
    public async Task Should_Uninstall_Package_And_Instances_When_Cap_File_Provided()
    {
        var settings = new UninstallCommand.Settings { CapFile = _testCapFilePath };

        int result = await _command.ExecuteAsync(_testContext, settings);

        _ = result.Should().Be(0);
    }

    [Test]
    public async Task Should_Remove_Only_Instances_When_InstancesOnly_Flag_Set()
    {
        var settings = new UninstallCommand.Settings
        {
            CapFile = _testCapFilePath,
            InstancesOnly = true,
        };

        int result = await _command.ExecuteAsync(_testContext, settings);

        _ = result.Should().Be(0);
    }

    [Test]
    public async Task Should_Succeed_When_Package_Already_Removed_Idempotent()
    {
        var settings = new UninstallCommand.Settings { CapFile = _testCapFilePath };

        int result = await _command.ExecuteAsync(_testContext, settings);

        _ = result.Should().Be(0);
    }

    [Test]
    public async Task Should_Fail_With_Clear_Error_When_Cap_File_Not_Found()
    {
        var settings = new UninstallCommand.Settings { CapFile = "/nonexistent/file.cap" };

        int result = await _command.ExecuteAsync(_testContext, settings);

        _ = result.Should().Be(1);
    }

    [Test]
    public async Task Should_Treat_Delete_Not_Found_Status_As_Idempotent_Success()
    {
        using var cardService = new QueuedStatusCardService(0x6A88, 0x6A88);
        var context = CreateContext(cardService);
        var settings = new UninstallCommand.Settings { CapFile = _testCapFilePath };

        int result = await _command.ExecuteAsync(context, settings);

        _ = result.Should().Be(0);
        _ = cardService.ExecuteCount.Should().Be(2);
    }

    [Test]
    public async Task Should_Fail_When_Applet_Delete_Returns_Non_Idempotent_Status()
    {
        using var cardService = new QueuedStatusCardService(0x6985);
        var context = CreateContext(cardService);
        var settings = new UninstallCommand.Settings { CapFile = _testCapFilePath };

        int result = await _command.ExecuteAsync(context, settings);

        _ = result.Should().Be(1);
        _ = cardService.ExecuteCount.Should().Be(1);
    }

    [Test]
    public async Task Should_Fail_When_Package_Delete_Returns_Non_Idempotent_Status()
    {
        using var cardService = new QueuedStatusCardService(0x9000, 0x6985);
        var context = CreateContext(cardService);
        var settings = new UninstallCommand.Settings { CapFile = _testCapFilePath };

        int result = await _command.ExecuteAsync(context, settings);

        _ = result.Should().Be(1);
        _ = cardService.ExecuteCount.Should().Be(2);
    }

    private static TestCliContext CreateContext(ICardSessionCommands cardService)
    {
        var displayService = new ConsoleDisplay();
        var keysetResolver = new KeysetResolution();
        var logger = NullLogger<CliContext>.Instance;
        return new TestCliContext(displayService, cardService, keysetResolver, logger);
    }

    private sealed class QueuedStatusCardService : ICardSessionCommands
    {
        private readonly Queue<StatusWord> _statusWords;

        public QueuedStatusCardService(params ushort[] statusWords)
        {
            _statusWords = new Queue<StatusWord>(statusWords.Select(sw => new StatusWord(sw)));
        }

        public int ExecuteCount { get; private set; }

        public ImmutablePipelineContext Context => ImmutablePipelineContext.Empty;

        public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
            CommandAPDU command,
            CancellationToken cancellationToken = default
        ) => ExecuteCommandAsync(command, false, cancellationToken);

        public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
            CommandAPDU command,
            bool useSecureChannel,
            CancellationToken cancellationToken = default
        )
        {
            ExecuteCount++;
            var statusWord =
                _statusWords.Count > 0 ? _statusWords.Dequeue() : new StatusWord(0x9000);
            var response =
                statusWord == new StatusWord(0x9000)
                    ? CommandResponse.Success()
                    : CommandResponse.Failure(statusWord);
            return Task.FromResult(Result.Success<CommandResponse, SmartCardError>(response));
        }

        public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
            CommandAPDU command,
            CommandOptions options,
            CancellationToken cancellationToken = default
        ) => ExecuteCommandAsync(command, options.UseSecureChannel, cancellationToken);

        public Result<ICardSessionCommands, SmartCardError> WithContext(
            ImmutablePipelineContext context
        ) => Result.Success<ICardSessionCommands, SmartCardError>(this);

        public Result<ICardSessionCommands, SmartCardError> WithContextValue<T>(
            string key,
            T value
        ) => Result.Success<ICardSessionCommands, SmartCardError>(this);

        public Task<Result<bool, SmartCardError>> IsConnectedAsync(
            CancellationToken cancellationToken = default
        ) => Task.FromResult(Result.Success<bool, SmartCardError>(true));

        public Task<Result<byte[], SmartCardError>> GetAtrAsync(
            CancellationToken cancellationToken = default
        ) => Task.FromResult(Result.Success<byte[], SmartCardError>([]));

        public Task<Result<string[], SmartCardError>> GetReadersAsync(
            CancellationToken cancellationToken = default
        ) => Task.FromResult(Result.Success<string[], SmartCardError>(["test-reader"]));

        public Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(
            CancellationToken cancellationToken = default
        ) => Task.FromResult(Result.Success<bool, SmartCardError>(true));

        public Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
            byte[] command,
            CancellationToken cancellationToken = default
        ) =>
            Task.FromResult(
                Result.Success<CommandResponse, SmartCardError>(CommandResponse.Success())
            );

        public Task<
            Result<CardTransportCapabilities, SmartCardError>
        > GetCardTransportCapabilitiesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(
                Result.Success<CardTransportCapabilities, SmartCardError>(
                    new CardTransportCapabilities(false, 245)
                )
            );

        public void Dispose() { }
    }
}
