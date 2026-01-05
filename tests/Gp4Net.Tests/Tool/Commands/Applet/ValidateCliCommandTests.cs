using System.IO;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Commands.Common;
using NUnit.Framework;

namespace Gp4Net.Tests.Tool.Commands.Applet;

/// <summary>
/// Tests for ValidateCommand enhanced output features (User Story 2).
/// Tests JSON output format option.
/// Note: ValidateCommand is a simple AsyncCommand without complex dependencies,
/// so we test it directly via Spectre.Console.Cli framework.
/// </summary>
[TestFixture]
public sealed class ValidateCliCommandTests
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
    public void Should_Have_Format_Option_Default_To_Table()
    {
        var settings = new ValidateCommand.Settings();

        _ = settings.Format.Should().Be(OutputFormat.Table);
    }

    [Test]
    public void Should_Allow_Format_Json_Option()
    {
        var settings = new ValidateCommand.Settings { Format = OutputFormat.Json };

        _ = settings.Format.Should().Be(OutputFormat.Json);
    }

    [Test]
    public void Should_Have_Detailed_Flag_Default_To_False()
    {
        var settings = new ValidateCommand.Settings();

        _ = settings.Detailed.Should().BeFalse();
    }

    [Test]
    public void Should_Allow_Detailed_Flag_To_Be_Set()
    {
        var settings = new ValidateCommand.Settings { Detailed = true };

        _ = settings.Detailed.Should().BeTrue();
    }
}
