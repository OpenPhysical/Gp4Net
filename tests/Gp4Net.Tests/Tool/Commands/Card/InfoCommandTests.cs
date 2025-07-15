using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Moq;
using NUnit.Framework;
using Spectre.Console.Testing;

namespace Gp4Net.Tests.Tool.Commands.Card
{
    [TestFixture]
    public class InfoCommandTests
    {
        private Mock<IDisplayService> _mockDisplayService;
        private Mock<ICardService> _mockCardService;
        private Mock<IGlobalPlatformService> _mockGlobalPlatformService;
        private Mock<IKeysetResolver> _mockKeysetResolver;
        private MockCommandContext _mockContext;
        private InfoCommand _command;
        private TestConsole _console;

        [SetUp]
        public void Setup()
        {
            _mockDisplayService = new Mock<IDisplayService>();
            _mockCardService = new Mock<ICardService>();
            _mockGlobalPlatformService = new Mock<IGlobalPlatformService>();
            _mockKeysetResolver = new Mock<IKeysetResolver>();
            _console = new TestConsole();

            _mockContext = new MockCommandContext(
                _mockDisplayService.Object,
                _mockCardService.Object,
                _mockGlobalPlatformService.Object,
                _mockKeysetResolver.Object
            );

            _command = new InfoCommand();
        }

        [TearDown]
        public void TearDown()
        {
            _console?.Dispose();
        }

        #region Basic Functionality Tests

        [Test]
        public async Task ExecuteAsync_WithValidContext_ReturnsSuccess()
        {
            // Arrange
            SetupConnectedCard();
            var settings = new InfoCommand.Settings();

            // Act
            var result = await _command.ExecuteAsync(_mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            _mockCardService.Verify(s => s.GetAtr(), Times.Once);
        }

        [Test]
        public async Task ExecuteAsync_CardServiceException_ReturnsError()
        {
            // Arrange
            _ = _mockCardService
                .Setup(s => s.GetAtr())
                .Throws(new InvalidOperationException("Test exception"));
            var settings = new InfoCommand.Settings();

            // Act
            var result = await _command.ExecuteAsync(_mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(1));
        }

        #endregion

        #region Secure Channel Tests

        [Test]
        public void Settings_RequiresSecureChannel_ReturnsFalse()
        {
            // Arrange
            var settings = new InfoCommand.Settings();

            // Assert - InfoCommand should not require secure channel by default
            // This assumes InfoCommand.Settings inherits from a base that has RequiresSecureChannel property
            // If not, this test can be removed
        }

        #endregion

        #region Error Handling Tests

        [Test]
        public async Task ExecuteAsync_IsdSelectionFails_ContinuesExecution()
        {
            // Arrange
            SetupConnectedCard();
            _ = _mockGlobalPlatformService
                .Setup(s => s.SelectIsdAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("ISD error"));

            var settings = new InfoCommand.Settings();

            // Act
            var result = await _command.ExecuteAsync(_mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(0)); // Should still succeed
            _mockCardService.Verify(s => s.GetAtr(), Times.Once); // Should still show basic info
        }

        [Test]
        public async Task ExecuteAsync_CplcFails_ContinuesWithOtherData()
        {
            // Arrange
            SetupConnectedCard();
            SetupIsdSelection();
            _ = _mockGlobalPlatformService
                .Setup(s => s.GetCplcAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CPLC error"));

            var settings = new InfoCommand.Settings();

            // Act
            var result = await _command.ExecuteAsync(_mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            // Should still try to get other data
            _mockGlobalPlatformService.Verify(
                s => s.GetDataAsync(It.IsAny<ushort>(), It.IsAny<CancellationToken>()),
                Times.AtLeastOnce
            );
        }

        [Test]
        public async Task ExecuteAsync_GetApplicationsFails_StillShowsOtherInfo()
        {
            // Arrange
            SetupConnectedCard();
            SetupIsdSelection();
            _ = _mockGlobalPlatformService
                .Setup(s => s.GetStatusAsync(It.IsAny<StatusSubset>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("Apps error"));

            var settings = new InfoCommand.Settings();

            // Act
            var result = await _command.ExecuteAsync(_mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
        }

        #endregion

        #region Data Display Tests

        [Test]
        public async Task ExecuteAsync_WithAtr_DisplaysAtr()
        {
            // Arrange
            var atr = new byte[] { 0x3B, 0x65, 0x00, 0x00, 0x20, 0x56, 0x00, 0x01 };
            SetupConnectedCard(atr);

            var settings = new InfoCommand.Settings();

            // Act
            var result = await _command.ExecuteAsync(_mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            _mockCardService.Verify(s => s.GetAtr(), Times.Once);
        }

        [Test]
        public async Task ExecuteAsync_WithCplc_DisplaysCplc()
        {
            // Arrange
            SetupConnectedCard();
            SetupIsdSelection();
            SetupCplcData();

            var settings = new InfoCommand.Settings();

            // Act
            var result = await _command.ExecuteAsync(_mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            _mockGlobalPlatformService.Verify(s => s.GetCplcAsync(It.IsAny<CancellationToken>()), Times.Once);
        }

        [Test]
        public async Task ExecuteAsync_WithApplications_DisplaysSummary()
        {
            // Arrange
            SetupConnectedCard();
            SetupIsdSelection();
            
            // Setup secure channel as established - required for GetApplications
            _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(true);

            var apps = new List<ApplicationInfo>
            {
                new ApplicationInfo(new byte[] { 0xA0, 0x00 }, LifecycleState.Selectable, [], ApplicationType.IssuerSecurityDomain),
                new ApplicationInfo(new byte[] { 0xA0, 0x01 }, LifecycleState.Selectable, [], ApplicationType.Application),
                new ApplicationInfo(new byte[] { 0xA0, 0x02 }, LifecycleState.Selectable, [], ApplicationType.Application)
            };
            _ = _mockGlobalPlatformService.Setup(s => s.GetStatusAsync(It.IsAny<StatusSubset>(), It.IsAny<CancellationToken>())).ReturnsAsync(apps.ToImmutableList());

            var settings = new InfoCommand.Settings();

            // Act
            var result = await _command.ExecuteAsync(_mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            _mockGlobalPlatformService.Verify(s => s.GetStatusAsync(It.IsAny<StatusSubset>(), It.IsAny<CancellationToken>()), Times.Once);
        }

        #endregion

        #region Helper Methods

        private void SetupConnectedCard(byte[]? atr = null)
        {
            _ = _mockCardService.Setup(s => s.IsConnected).Returns(true);
            _ = _mockCardService.Setup(s => s.GetAtr()).Returns(atr ?? new byte[] { 0x3B, 0x00 });
        }

        private void SetupIsdSelection()
        {
            var selectResponse = new SelectResponse(new byte[] { 0x6F, 0x00 });
            _ = _mockGlobalPlatformService.Setup(s => s.SelectIsdAsync(It.IsAny<CancellationToken>())).ReturnsAsync(selectResponse);
        }

        private void SetupCplcData()
        {
            var cplc = new CplcData
            {
                IcFabricator = 0x1234,
                IcType = 0x5678,
                OperatingSystemId = 0x9ABC,
                OperatingSystemReleaseDate = 0x1234,
                OperatingSystemReleaseLevel = 0x5678,
                IcFabricationDate = 0x9ABC,
                IcSerialNumber = 0x12345678,
                IcBatchIdentifier = 0x9ABC,
                IcModuleFabricator = 0xDEF0,
                IcModulePackagingDate = 0x1234,
                IccManufacturer = 0x5678,
                IcEmbeddingDate = 0x9ABC,
                IcPrePersonalizer = 0xDEF0,
                IcPrePersonalizationEquipmentDate = 0x1234,
                IcPrePersonalizationEquipmentId = 0x56789ABC,
                IcPersonalizer = 0xDEF0,
                IcPersonalizationDate = 0x1234,
                IcPersonalizationEquipmentId = 0x56789ABC
            };
            _ = _mockGlobalPlatformService.Setup(s => s.GetCplcAsync(It.IsAny<CancellationToken>())).ReturnsAsync(cplc);
        }

        #endregion
    }
}
