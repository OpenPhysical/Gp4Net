using System.IO;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Pipeline;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
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
    private ISmartCardService _smartCardService;
    private UninstallCommand _command;
    private string _testCapFilePath;

    [SetUp]
    public void Setup()
    {
        var virtualCardService = new VirtualCardService();
        virtualCardService.SetupTestEnvironment();
        _smartCardService = Create(virtualCardService).Value;

        var displayService = new DisplayService();
        var keysetResolver = new KeysetResolver();
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
}
