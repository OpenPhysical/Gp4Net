using System.IO;
using FsCheck;
using FsCheck.NUnit;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Pipeline;
using Microsoft.Extensions.Logging.Abstractions;
using static Gp4Net.Tests.Infrastructure.TestCardService;

namespace Gp4Net.Tests.Tool.Commands.Applet;

/// <summary>
/// Property-based tests for UninstallCommand using FsCheck.
/// Tests invariants that should hold for ALL inputs (idempotency, consistency).
/// </summary>
[NUnit.Framework.TestFixture]
public sealed class UninstallCommandPropertyTests
{
    private TestCliContext _testContext;
    private ICardSessionCommands _smartCardService;
    private UninstallCommand _command;
    private string _testCapFilePath;

    [NUnit.Framework.SetUp]
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
            NUnit.Framework.TestContext.CurrentContext.TestDirectory,
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

    [NUnit.Framework.TearDown]
    public void TearDown()
    {
        _smartCardService?.Dispose();
    }

    [Property(MaxTest = 5, QuietOnSuccess = true)]
    public bool Uninstall_Is_Idempotent_Returns_Success_On_Subsequent_Calls()
    {
        var settings = new UninstallCommand.Settings { CapFile = _testCapFilePath };

        var firstResult = _command.ExecuteAsync(_testContext, settings).GetAwaiter().GetResult();
        var secondResult = _command.ExecuteAsync(_testContext, settings).GetAwaiter().GetResult();

        return firstResult == 0 && secondResult == 0;
    }
}
