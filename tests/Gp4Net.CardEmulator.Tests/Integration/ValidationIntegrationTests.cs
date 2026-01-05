using System.IO;
using System.Linq;
using AwesomeAssertions;
using Gp4Net.Domain.CapFile;
using Gp4Net.Tool.Commands.Applet;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Integration;

/// <summary>
/// Integration tests for CAP file validation workflows using real implementations.
/// Tests CapValidationResult creation and validation message generation.
/// </summary>
[TestFixture]
[Category("Integration")]
public sealed class ValidationIntegrationTests
{
    private string _testCapFilePath = string.Empty;

    [SetUp]
    public void Setup()
    {
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

    [Test]
    public void Should_Build_CapValidationResult_From_Real_Cap_File()
    {
        if (!File.Exists(_testCapFilePath))
        {
            Assert.Ignore($"Test CAP file not found: {_testCapFilePath}");
        }

        byte[] capFileData = File.ReadAllBytes(_testCapFilePath);
        var capFileResult = CapFileStructure.Parse(capFileData);

        _ = capFileResult.IsSuccess.Should().BeTrue();

        var capFile = capFileResult.Value;
        var components = capFile.Components.Select(c => ComponentSummary.FromComponent(c)).ToList();

        var validationResult = CapValidationResult.FromCapFile(
            _testCapFilePath,
            capFile,
            components,
            System.Array.Empty<ValidationMessage>(),
            System.Array.Empty<ValidationMessage>(),
            System.Array.Empty<ValidationMessage>()
        );

        _ = validationResult.IsValid.Should().BeTrue();
        _ = validationResult.PackageAid.Should().NotBeEmpty();
        _ = validationResult.Components.Count.Should().BeGreaterThan(0);
    }

    [Test]
    public void Should_Create_Validation_Messages_With_Severity()
    {
        var error = ValidationMessage.Error(
            "TEST-001",
            "Test error message",
            CSharpFunctionalExtensions.Maybe<string>.From("context"),
            CSharpFunctionalExtensions.Maybe<string>.From("suggestion")
        );

        _ = error.Severity.Should().Be(ValidationSeverity.Error);
        _ = error.Code.Should().Be("TEST-001");
        _ = error.Message.Should().Be("Test error message");
    }

    [Test]
    public void Should_Extract_Component_Summaries_From_Cap_File()
    {
        if (!File.Exists(_testCapFilePath))
        {
            Assert.Ignore($"Test CAP file not found: {_testCapFilePath}");
        }

        byte[] capFileData = File.ReadAllBytes(_testCapFilePath);
        var capFileResult = CapFileStructure.Parse(capFileData);

        _ = capFileResult.IsSuccess.Should().BeTrue();

        var capFile = capFileResult.Value;
        var components = capFile.Components.Select(c => ComponentSummary.FromComponent(c)).ToList();

        _ = components.Count.Should().BeGreaterThan(0);
        _ = components.Should().Contain(c => c.Name == "Header");
        _ = components.Should().Contain(c => c.Name == "Directory");
    }
}
