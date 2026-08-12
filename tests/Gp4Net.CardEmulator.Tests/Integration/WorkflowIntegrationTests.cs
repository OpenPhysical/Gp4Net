using System.IO;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Domain.CapFile;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Integration;

/// <summary>
/// End-to-end integration tests verifying complete workflows with real implementations.
/// Tests actual CAP file operations using VirtualCardOperations (no mocks).
/// </summary>
[TestFixture]
[Category("Integration")]
public sealed class WorkflowIntegrationTests
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
    public async Task Should_Parse_Real_Cap_File_Successfully()
    {
        if (!File.Exists(_testCapFilePath))
        {
            Assert.Ignore($"Test CAP file not found: {_testCapFilePath}");
        }

        byte[] capFileData = await File.ReadAllBytesAsync(_testCapFilePath);
        var result = CapFileStructure.Parse(capFileData);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.PackageAid.Length.Should().BeGreaterThan(0);
        _ = result.Value.Applets.Count.Should().BeGreaterThan(0);
    }

    [Test]
    public void Should_Initialize_Virtual_Card_Service()
    {
        using var virtualCardService = new VirtualCardOperations();
        var readerManager = virtualCardService.GetReaderManager();

        var readers = virtualCardService.GetReaders();
        _ = readers.IsSuccess.Should().BeTrue();
    }

    [Test]
    public async Task Should_List_Virtual_Card_Readers()
    {
        using var virtualCardService = new VirtualCardOperations();

        await Task.CompletedTask;

        var readers = virtualCardService.GetReaders();
        _ = readers.IsSuccess.Should().BeTrue();
    }

    [Test]
    public void Should_Extract_Package_Aid_From_Cap_File()
    {
        if (!File.Exists(_testCapFilePath))
        {
            Assert.Ignore($"Test CAP file not found: {_testCapFilePath}");
        }

        byte[] capFileData = File.ReadAllBytes(_testCapFilePath);
        var capResult = CapFileStructure.Parse(capFileData);

        _ = capResult.IsSuccess.Should().BeTrue();

        var capFile = capResult.Value;
        _ = capFile.PackageAid.Should().NotBeEmpty();
        _ = capFile.PackageVersion.Major.Should().BeGreaterThanOrEqualTo(0);
    }

    [Test]
    public void Should_Extract_Applet_Aids_From_Cap_File()
    {
        if (!File.Exists(_testCapFilePath))
        {
            Assert.Ignore($"Test CAP file not found: {_testCapFilePath}");
        }

        byte[] capFileData = File.ReadAllBytes(_testCapFilePath);
        var capResult = CapFileStructure.Parse(capFileData);

        _ = capResult.IsSuccess.Should().BeTrue();

        var capFile = capResult.Value;
        _ = capFile.Applets.Count.Should().BeGreaterThan(0);

        foreach (var applet in capFile.Applets)
        {
            _ = applet.Aid.Length.Should().BeGreaterThan(0);
        }
    }
}
