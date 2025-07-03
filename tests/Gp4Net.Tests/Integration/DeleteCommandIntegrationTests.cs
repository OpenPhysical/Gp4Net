using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Domain.Commands;
using Gp4Net.Tests.TestHelpers;
using Gp4Net.Tool.Commands.Applet;
using DeleteCommand = Gp4Net.Tool.Commands.Applet.DeleteCommand;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Services.CardCommunication;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using NUnit.Framework;
using Spectre.Console.Cli;
using Spectre.Console.Testing;

namespace Gp4Net.Tests.Integration
{
    [TestFixture]
    public class DeleteCommandIntegrationTests
    {
        private ServiceProvider _serviceProvider;
        private TestConsole _console;
        private Mock<ICardService> _mockCardService;
        private string _testCapFilePath;
        private Dictionary<string, byte[]> _simulatedCardApplications;

        [SetUp]
        public void Setup()
        {
            _console = new TestConsole();
            _testCapFilePath = Path.Combine(Path.GetTempPath(), "test_delete.cap");
            CreateTestCapFile();

            // Initialize simulated card with some applications
            _simulatedCardApplications = new Dictionary<string, byte[]>
            {
                { "A0000000030000", new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00 } },
                { "A0000000030001", new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01 } },
                { "A0000000040000", new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00 } },
                { "A000000151000000", new byte[] { 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00 } }
            };

            SetupDependencyInjection();
        }

        [TearDown]
        public void TearDown()
        {
            _console?.Dispose();
            _serviceProvider?.Dispose();
            if (File.Exists(_testCapFilePath))
            {
                File.Delete(_testCapFilePath);
            }
        }

        #region Simulated Card Tests

        [Test]
        public async Task Delete_SingleApplet_SimulatedCard_Success()
        {
            // Arrange
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--aid", "A0000000030001",
                "--force",
                "--reader", "Simulated Reader",
                "--keyset", "test"
            });

            // Assert
            Assert.That(result, Is.EqualTo(0));
            Assert.That(_simulatedCardApplications.ContainsKey("A0000000030001"), Is.False);
            Assert.That(_console.Output, Does.Contain("Successfully deleted 1 object(s)"));
        }

        [Test]
        public async Task Delete_MultipleApplets_SimulatedCard_Success()
        {
            // Arrange
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--aid", "A0000000030001",
                "--aid", "A0000000040000",
                "--force",
                "--reader", "Simulated Reader",
                "--keyset", "test"
            });

            // Assert
            Assert.That(result, Is.EqualTo(0));
            Assert.That(_simulatedCardApplications.ContainsKey("A0000000030001"), Is.False);
            Assert.That(_simulatedCardApplications.ContainsKey("A0000000040000"), Is.False);
            Assert.That(_console.Output, Does.Contain("Successfully deleted 2 object(s)"));
        }

        [Test]
        public async Task Delete_WithRelatedObjects_SimulatedCard_Success()
        {
            // Arrange
            // Add a related applet instance
            _simulatedCardApplications["A0000000030002"] = new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02 };

            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--aid", "A0000000030000", // Package AID
                "--force",
                "--reader", "Simulated Reader",
                "--keyset", "test"
                // Default is to delete related objects
            });

            // Assert
            Assert.That(result, Is.EqualTo(0));
            // Package and all related applets should be deleted
            Assert.That(_simulatedCardApplications.Any(kvp => kvp.Key.StartsWith("A000000003")), Is.False);
        }

        [Test]
        public async Task Delete_NoDeleteRelated_SimulatedCard_Success()
        {
            // Arrange
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--aid", "A0000000030000",
                "--no-delete-related",
                "--force",
                "--reader", "Simulated Reader",
                "--keyset", "test"
            });

            // Assert
            Assert.That(result, Is.EqualTo(0));
            // Only the specific AID should be deleted
            Assert.That(_simulatedCardApplications.ContainsKey("A0000000030000"), Is.False);
            Assert.That(_simulatedCardApplications.ContainsKey("A0000000030001"), Is.True); // Related applet remains
        }

        #endregion

        #region Dry-Run Tests

        [Test]
        public async Task Delete_DryRun_NoChangesToCard()
        {
            // Arrange
            var initialCount = _simulatedCardApplications.Count;
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--aid", "A0000000030001",
                "--dry-run",
                "--reader", "Simulated Reader",
                "--keyset", "test"
            });

            // Assert
            Assert.That(result, Is.EqualTo(0));
            Assert.That(_simulatedCardApplications.Count, Is.EqualTo(initialCount));
            Assert.That(_simulatedCardApplications.ContainsKey("A0000000030001"), Is.True);
            Assert.That(_console.Output, Does.Contain("Dry-run mode"));
            Assert.That(_console.Output, Does.Contain("Deletion Plan"));
        }

        [Test]
        public async Task Delete_DryRunWithDebug_ShowsDetailedPlan()
        {
            // Arrange
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--aid", "A0000000030001",
                "--dry-run",
                "--debug",
                "--reader", "Simulated Reader",
                "--keyset", "test"
            });

            // Assert
            Assert.That(result, Is.EqualTo(0));
            Assert.That(_console.Output, Does.Contain("Debug information"));
            Assert.That(_console.Output, Does.Contain("Delete related objects"));
        }

        #endregion

        #region CAP File Tests

        [Test]
        public async Task Delete_FromCapFile_ExtractsAndDeletes()
        {
            // Arrange
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--cap", _testCapFilePath,
                "--force",
                "--reader", "Simulated Reader",
                "--keyset", "test"
            });

            // Assert
            Assert.That(result, Is.EqualTo(0));
            // Both package and applet from CAP file should be deleted
            Assert.That(_simulatedCardApplications.ContainsKey("A0000000030000"), Is.False);
            Assert.That(_simulatedCardApplications.ContainsKey("A0000000030001"), Is.False);
            Assert.That(_console.Output, Does.Contain("Reading CAP file"));
        }

        [Test]
        public async Task Delete_CapFileDryRun_ParsesWithoutConnection()
        {
            // Arrange
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Mock card service to verify no connection is made
            var connectCalled = false;
            _ = _mockCardService.Setup(s => s.Connect(It.IsAny<string>()))
                .Callback(() => connectCalled = true)
                .Returns(true);

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--cap", _testCapFilePath,
                "--dry-run"
            });

            // Assert
            Assert.That(result, Is.EqualTo(0));
            Assert.That(connectCalled, Is.False);
            Assert.That(_console.Output, Does.Contain("Package A0000000030000"));
            Assert.That(_console.Output, Does.Contain("Applet A0000000030001"));
        }

        #endregion

        #region Error Handling Tests

        [Test]
        public async Task Delete_NonExistentApplet_ShowsError()
        {
            // Arrange
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--aid", "AABBCCDDEEFF", // Non-existent AID
                "--force",
                "--reader", "Simulated Reader",
                "--keyset", "test"
            });

            // Assert
            Assert.That(result, Is.EqualTo(1));
            Assert.That(_console.Output, Does.Contain("Failed to delete"));
            Assert.That(_console.Output, Does.Contain("not found"));
        }

        [Test]
        public async Task Delete_PartialFailure_ShowsPartialSuccess()
        {
            // Arrange
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.AddCommand<DeleteCommand>("delete");
            });

            // Act
            var result = await app.RunAsync(new[] { 
                "delete", 
                "--aid", "A0000000030001", // Exists
                "--aid", "AABBCCDDEEFF",   // Does not exist
                "--force",
                "--reader", "Simulated Reader",
                "--keyset", "test"
            });

            // Assert
            Assert.That(result, Is.EqualTo(1));
            Assert.That(_simulatedCardApplications.ContainsKey("A0000000030001"), Is.False); // Was deleted
            Assert.That(_console.Output, Does.Contain("Partially successful"));
        }

        #endregion

        #region Helper Methods

        private void SetupDependencyInjection()
        {
            var services = new ServiceCollection();

            // Mock card service with simulated card behavior
            _mockCardService = new Mock<ICardService>();
            SetupSimulatedCardService();
            _ = services.AddSingleton(_mockCardService.Object);

            // Mock GlobalPlatform service with simulated operations
            var mockGpService = new Mock<IGlobalPlatformService>();
            SetupSimulatedGlobalPlatformService(mockGpService);
            _ = services.AddSingleton(mockGpService.Object);

            // Mock keyset resolver
            var mockKeysetResolver = new Mock<IKeysetResolver>();
            _ = mockKeysetResolver.Setup(k => k.ResolveKeyset(
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
            _ = services.AddSingleton(mockKeysetResolver.Object);

            // Add other required services
            _ = services.AddSingleton<IDisplayService>(new DisplayService(false));
            _ = services.AddSingleton<ICommandContext, Gp4Net.Tool.Pipeline.CommandContext>();
            _ = services.AddTransient<DeleteCommand>();

            _serviceProvider = services.BuildServiceProvider();
        }

        private void SetupSimulatedCardService()
        {
            _ = _mockCardService.Setup(s => s.GetReaders())
                .Returns(new List<string> { "Simulated Reader" });
            
            _ = _mockCardService.Setup(s => s.Connect(It.IsAny<string>()))
                .Returns(true);
            
            _ = _mockCardService.Setup(s => s.IsConnected)
                .Returns(true);
            
            _ = _mockCardService.Setup(s => s.EstablishSecureChannel(It.IsAny<byte[]>(), It.IsAny<byte>()))
                .Returns(true);
            
            _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished)
                .Returns(true);

            _ = _mockCardService.Setup(s => s.GetAtr())
                .Returns(new byte[] { 0x3B, 0x65, 0x00, 0x00, 0x20, 0x56, 0x00, 0x01 });
        }

        private void SetupSimulatedGlobalPlatformService(Mock<IGlobalPlatformService> mockGpService)
        {
            // Simulate SELECT ISD
            _ = mockGpService.Setup(s => s.SelectIsd())
                .Returns(new SelectResponse(new byte[] { 0x6F, 0x00 }));

            // Simulate GET STATUS (list applications)
            _ = mockGpService.Setup(s => s.GetApplications())
                .Returns(() => _simulatedCardApplications.Select(kvp => 
                    new ApplicationInfo(
                        kvp.Value,
                        "SELECTABLE",
                        new List<string>(),
                        kvp.Key.StartsWith("A000000003") ? "Applet" : "Package"
                    )).ToList());

            // Simulate DELETE command
            _ = mockGpService.Setup(s => s.DeleteApplication(It.IsAny<byte[]>(), It.IsAny<bool>()))
                .Returns<byte[], bool>((aid, deleteRelated) => SimulateDelete(aid, deleteRelated));
        }

        private DeletionResult SimulateDelete(byte[] aid, bool deleteRelated)
        {
            var aidHex = Convert.ToHexString(aid);
            var deletedAids = new List<byte[]>();

            if (_simulatedCardApplications.ContainsKey(aidHex))
            {
                // Remove the specified AID
                _simulatedCardApplications.Remove(aidHex);
                deletedAids.Add(aid);

                // If deleteRelated is true and this is a package AID, delete related applets
                if (deleteRelated && aidHex.Length == 14) // Package AIDs are typically shorter
                {
                    var relatedKeys = _simulatedCardApplications
                        .Where(kvp => kvp.Key.StartsWith(aidHex))
                        .Select(kvp => kvp.Key)
                        .ToList();

                    foreach (var key in relatedKeys)
                    {
                        deletedAids.Add(_simulatedCardApplications[key]);
                        _simulatedCardApplications.Remove(key);
                    }
                }

                return new DeletionResult(true, deletedAids: deletedAids);
            }
            else
            {
                return new DeletionResult(false, $"AID {aidHex} not found on card");
            }
        }

        private void CreateTestCapFile()
        {
            // Create a simple test CAP file as a ZIP
            using (var stream = File.Create(_testCapFilePath))
            using (var archive = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Create))
            {
                // Add Header component
                var headerEntry = archive.CreateEntry("Header.cap");
                using (var headerStream = headerEntry.Open())
                {
                    var headerData = new byte[] { 
                        0x01, 0x00, 0x15, // tag, size
                        0xDE, 0xCA, 0xF0, // magic (DECAF0)
                        0x02, 0x01, // minor, major version
                        0x00, // flags
                        0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, // package AID
                        0x01, 0x00 // package version
                    };
                    headerStream.Write(headerData, 0, headerData.Length);
                }

                // Add Applet component
                var appletEntry = archive.CreateEntry("Applet.cap");
                using (var appletStream = appletEntry.Open())
                {
                    var appletData = new byte[] { 
                        0x03, 0x00, 0x0B, // tag, size
                        0x01, // count
                        0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, // applet AID
                        0x00, 0x00 // install method offset
                    };
                    appletStream.Write(appletData, 0, appletData.Length);
                }

                // Add Directory component
                var directoryEntry = archive.CreateEntry("Directory.cap");
                using (var directoryStream = directoryEntry.Open())
                {
                    var directoryData = new byte[] { 
                        0x02, 0x00, 0x02, // tag, size
                        0x00, 0x02 // component sizes
                    };
                    directoryStream.Write(directoryData, 0, directoryData.Length);
                }
            }
        }

        #endregion
    }
}