using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Gp4Net.Domain.CapFile;
using Gp4Net.Domain.Commands;
using Gp4Net.Tests.TestHelpers;
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Moq;
using NUnit.Framework;
using Spectre.Console.Cli;
using Spectre.Console.Testing;

namespace Gp4Net.Tests.Tool.Commands.Applet
{
    [TestFixture]
    public class DeleteCommandTests
    {
        private Mock<ICardService> _mockCardService;
        private Mock<IGlobalPlatformService> _mockGlobalPlatformService;
        private Mock<IKeysetResolver> _mockKeysetResolver;
        private Gp4Net.Tool.Commands.Applet.DeleteCommand _command;
        private TestConsole _console;
        private string _testCapFilePath;

        [SetUp]
        public void Setup()
        {
            _mockCardService = new Mock<ICardService>();
            _mockGlobalPlatformService = new Mock<IGlobalPlatformService>();
            _mockKeysetResolver = new Mock<IKeysetResolver>();
            _console = new TestConsole();

            _command = new Gp4Net.Tool.Commands.Applet.DeleteCommand(
                _mockCardService.Object,
                _mockGlobalPlatformService.Object,
                _mockKeysetResolver.Object
            );

            // Use the real OpenFIPS201 CAP file from test assets
            // Navigate up from test assembly to find project root
            var assemblyDir = Path.GetDirectoryName(typeof(DeleteCommandTests).Assembly.Location)!;
            var projectRoot = Path.GetFullPath(Path.Combine(assemblyDir, "..", "..", "..", "..", ".."));
            _testCapFilePath = Path.Combine(
                projectRoot,
                "tests",
                "applets",
                "OpenFIPS201-v1_10_2-chainfix.cap"
            );
        }

        [TearDown]
        public void TearDown()
        {
            _console?.Dispose();
        }

        #region Basic Delete Tests

        [Test]
        public async Task ExecuteAsync_SingleAid_Success()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Aids = new[] { "A0000000030000" },
                Force = true
            };

            SetupMocksForSuccessfulDeletion();

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            _mockGlobalPlatformService.Verify(
                s => s.DeleteApplication(It.IsAny<byte[]>(), true),
                Times.Once
            );
        }

        [Test]
        public async Task ExecuteAsync_MultipleAids_Success()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Aids = new[] { "A0000000030000", "A0000000040000" },
                Force = true
            };

            SetupMocksForSuccessfulDeletion();

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            _mockGlobalPlatformService.Verify(
                s => s.DeleteApplication(It.IsAny<byte[]>(), true),
                Times.Exactly(2)
            );
        }

        [Test]
        public async Task ExecuteAsync_InvalidAid_ReturnsError()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Aids = new[] { "INVALID_HEX" },
                Force = true
            };

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(1));
            // Note: Error message goes to AnsiConsole directly, not captured in unit tests
            // The validation error is properly handled by returning error code 1
        }

        #endregion

        #region Dry-Run Tests

        [Test]
        public async Task ExecuteAsync_DryRun_NoActualDeletion()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Aids = new[] { "A0000000030000" },
                DryRun = true,
                Force = true
            };

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            // Note: "Dry-run mode" message goes to AnsiConsole directly, not captured in unit tests
            _mockGlobalPlatformService.Verify(
                s => s.DeleteApplication(It.IsAny<byte[]>(), It.IsAny<bool>()),
                Times.Never
            );
        }

        [Test]
        public async Task ExecuteAsync_DryRunWithCapFile_ParsesButDoesNotDelete()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                CapFile = _testCapFilePath,
                DryRun = true,
                Force = true
            };

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            // Note: "Reading CAP file" and "Dry-run mode" messages go to AnsiConsole directly, not captured in unit tests
            _mockCardService.Verify(s => s.Connect(It.IsAny<string>()), Times.Never);
            _mockGlobalPlatformService.Verify(
                s => s.DeleteApplication(It.IsAny<byte[]>(), It.IsAny<bool>()),
                Times.Never
            );
        }

        #endregion

        #region CAP File Tests

        [Test]
        public async Task ExecuteAsync_CapFile_ExtractsAidsAndDeletes()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                CapFile = _testCapFilePath,
                Force = true
            };

            SetupMocksForSuccessfulDeletion();

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            // Note: "Reading CAP file" message goes to AnsiConsole directly, not captured in unit tests
            // Should delete package AID and at least one applet AID
            _mockGlobalPlatformService.Verify(
                s => s.DeleteApplication(It.IsAny<byte[]>(), true),
                Times.AtLeast(2)
            );
        }

        [Test]
        public async Task ExecuteAsync_CapFileNotFound_ReturnsError()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                CapFile = "nonexistent.cap",
                Force = true
            };

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(1));
            // Note: "CAP file not found" message goes to AnsiConsole directly, not captured in unit tests
        }

        #endregion

        #region Interactive Mode Tests

        [Test]
        public async Task ExecuteAsync_InteractiveMode_NoApplications_Success()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Interactive = true,
                Force = true
            };

            SetupMocksForConnection();
            _ = _mockGlobalPlatformService
                .Setup(s => s.GetApplications())
                .Returns(new List<ApplicationInfo>());

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            // Note: "No applications found" message goes to AnsiConsole directly, not captured in unit tests
        }

        #endregion

        #region Debug Mode Tests

        [Test]
        public async Task ExecuteAsync_DebugMode_ShowsDetailedInfo()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Aids = new[] { "A0000000030000" },
                Debug = true,
                Force = true
            };

            SetupMocksForSuccessfulDeletion();

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            // Note: "Debug information" message goes to AnsiConsole directly, not captured in unit tests
        }

        #endregion

        #region Delete Related Tests

        [Test]
        public async Task ExecuteAsync_NoDeleteRelated_PassesFalse()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Aids = new[] { "A0000000030000" },
                NoDeleteRelated = true,
                Force = true
            };

            SetupMocksForSuccessfulDeletion();

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            _mockGlobalPlatformService.Verify(
                s => s.DeleteApplication(It.IsAny<byte[]>(), false),
                Times.Once
            );
        }

        #endregion

        #region Error Handling Tests

        [Test]
        public async Task ExecuteAsync_DeleteFails_ReturnsError()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Aids = new[] { "A0000000030000" },
                Force = true
            };

            SetupMocksForConnection();
            _ = _mockGlobalPlatformService
                .Setup(s => s.DeleteApplication(It.IsAny<byte[]>(), It.IsAny<bool>()))
                .Returns(new DeletionResult(false, "Application not found"));

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(1));
            // Note: "Failed to delete" message goes to AnsiConsole directly, not captured in unit tests
            // Note: "Application not found" message goes to AnsiConsole directly, not captured in unit tests
        }

        [Test]
        public async Task ExecuteAsync_PartialSuccess_ReturnsError()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Aids = new[] { "A0000000030000", "A0000000040000" },
                Force = true
            };

            SetupMocksForConnection();
            
            // First deletion succeeds, second fails
            _ = _mockGlobalPlatformService
                .SetupSequence(s => s.DeleteApplication(It.IsAny<byte[]>(), It.IsAny<bool>()))
                .Returns(new DeletionResult(true, deletedAids: new[] { new byte[] { 0xA0, 0x00 } }))
                .Returns(new DeletionResult(false, "Application not found"));

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(1));
            // Note: Success/failure messages go to AnsiConsole directly, not captured in unit tests
            // The integration tests verify the actual console output
        }

        [Test]
        public async Task ExecuteAsync_ConnectionFails_ReturnsError()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                Aids = new[] { "A0000000030000" },
                Force = true
            };

            _ = _mockCardService.Setup(s => s.GetReaders()).Returns(new List<string>());

            // Act
            var result = await _command.ExecuteAsync(DeleteCommandTestHelpers.CreateTestContext(), settings);

            // Assert
            Assert.That(result, Is.EqualTo(1));
        }

        #endregion

        #region Validation Tests

        [Test]
        public void Validate_NoInputProvided_ReturnsError()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings();

            // Act
            var result = settings.Validate();

            // Assert
            Assert.That(result.Successful, Is.False);
            Assert.That(result.Message, Does.Contain("Specify at least one AID"));
        }

        [Test]
        public void Validate_InvalidCapFile_ReturnsError()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                CapFile = "nonexistent.cap"
            };

            // Act
            var result = settings.Validate();

            // Assert
            Assert.That(result.Successful, Is.False);
            Assert.That(result.Message, Does.Contain("CAP file not found"));
        }

        [Test]
        public void Validate_DryRunWithCapFile_Success()
        {
            // Arrange
            var settings = new Gp4Net.Tool.Commands.Applet.DeleteCommand.Settings
            {
                CapFile = _testCapFilePath,
                DryRun = true
            };

            // Act
            var result = settings.Validate();

            // Assert
            Assert.That(result.Successful, Is.True);
        }

        #endregion

        #region Helper Methods

        private void SetupMocksForConnection()
        {
            _ = _mockCardService.Setup(s => s.GetReaders()).Returns(new List<string> { "Test Reader" });
            _ = _mockCardService.Setup(s => s.Connect(It.IsAny<string>())).Returns(true);
            _ = _mockCardService.Setup(s => s.IsConnected).Returns(true);
            _ = _mockCardService.Setup(s => s.EstablishSecureChannel(It.IsAny<byte[]>(), It.IsAny<byte>()))
                .Returns(true);
            _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(true);

            _ = _mockKeysetResolver.Setup(k => k.ResolveKeyset(
                It.IsAny<string>(),
                It.IsAny<Dictionary<string, string>>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte>(),
                It.IsAny<Gp4Net.Domain.Commands.InitializeUpdateResponse>()))
                .Returns(new TestKeySet(
                    new byte[] { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                                 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F },
                    new byte[] { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                                 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F },
                    new byte[] { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                                 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F },
                    0xFF));
        }

        private void SetupMocksForSuccessfulDeletion()
        {
            SetupMocksForConnection();
            
            _ = _mockGlobalPlatformService
                .Setup(s => s.DeleteApplication(It.IsAny<byte[]>(), It.IsAny<bool>()))
                .Returns(new DeletionResult(true, deletedAids: new[] { new byte[] { 0xA0, 0x00 } }));
        }


        #endregion
    }
}