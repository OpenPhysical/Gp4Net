using System;
using System.Linq;
using Gp4Net.Tests.Emulator.Cards;
using Gp4Net.Tests.Emulator.Core;
using Gp4Net.Tests.Emulator.Services;
using Gp4Net.Utils;
using NUnit.Framework;

namespace Gp4Net.Tests.Emulator
{
    /// <summary>
    /// Tests for the virtual card service.
    /// </summary>
    [TestFixture]
    public class VirtualCardServiceTests
    {
        private VirtualCardService _service = null!;

        [SetUp]
        public void SetUp()
        {
            _service = new VirtualCardService();
            _service.SetupTestEnvironment();
        }

        [TearDown]
        public void TearDown()
        {
            _service.Dispose();
        }

        [Test]
        public void GetReaders_ReturnsAvailableReaders()
        {
            // Act
            var readers = _service.GetReaders();

            // Assert
            Assert.That(readers, Is.Not.Null);
            Assert.That(readers.Count, Is.GreaterThan(0));
            Assert.That(readers, Does.Contain("Virtual ACOS Reader 00 00"));
        }

        [Test]
        public void Connect_ValidReader_ReturnsTrue()
        {
            // Arrange
            var readerName = "Virtual ACOS Reader 00 00";

            // Act
            var result = _service.Connect(readerName);

            // Assert
            Assert.That(result, Is.True);
            Assert.That(_service.IsConnected, Is.True);
        }

        [Test]
        public void Connect_InvalidReader_ReturnsFalse()
        {
            // Arrange
            var readerName = "Non-existent Reader";

            // Act
            var result = _service.Connect(readerName);

            // Assert
            Assert.That(result, Is.False);
            Assert.That(_service.IsConnected, Is.False);
        }

        [Test]
        public void Connect_NullReaderName_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => _service.Connect(null!));
            Assert.Throws<ArgumentException>(() => _service.Connect(""));
        }

        [Test]
        public void GetAtr_WhenConnected_ReturnsAtr()
        {
            // Arrange
            _service.Connect("Virtual ACOS Reader 00 00");

            // Act
            var atr = _service.GetAtr();

            // Assert
            Assert.That(atr, Is.Not.Null);
            Assert.That(atr.Length, Is.GreaterThan(0));
            Assert.That(Convert.ToHexString(atr), Is.EqualTo("3B68000030659000AF"));
        }

        [Test]
        public void GetAtr_WhenNotConnected_ReturnsNull()
        {
            // Act
            var atr = _service.GetAtr();

            // Assert
            Assert.That(atr, Is.Null);
        }

        [Test]
        public void SendCommand_WhenNotConnected_ThrowsInvalidOperationException()
        {
            // Arrange
            var command = ConvertCompat.FromHexString("00A4040008A000000151000000");

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => _service.SendCommand(command));
        }

        [Test]
        public void SendCommand_NullCommand_ThrowsArgumentNullException()
        {
            // Arrange
            _service.Connect("Virtual ACOS Reader 00 00");

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => _service.SendCommand(null!));
        }

        [Test]
        public void SendCommand_ValidCommand_ReturnsResponse()
        {
            // Arrange
            _service.Connect("Virtual ACOS Reader 00 00");
            var selectIsdCommand = ConvertCompat.FromHexString("00A4040008A000000151000000");

            // Act
            var response = _service.SendCommand(selectIsdCommand);

            // Assert
            Assert.That(response, Is.Not.Null);
            Assert.That(response.IsSuccessful, Is.True);
            Assert.That(response.StatusWord, Is.EqualTo(0x9000));
            Assert.That(response.Data.Length, Is.GreaterThan(0));
        }

        [Test]
        public void SendCommand_FullAuthenticationSequence_EstablishesSecureChannel()
        {
            // Arrange
            _service.Connect("Virtual ACOS Reader 00 00");

            // Act - Select ISD
            var selectResponse = _service.SendCommand(ConvertCompat.FromHexString("00A4040008A000000151000000"));
            Assert.That(selectResponse.IsSuccessful, Is.True);

            // Initialize Update
            var initResponse = _service.SendCommand(ConvertCompat.FromHexString("80500000081122334455667788"));
            Assert.That(initResponse.IsSuccessful, Is.True);

            // External Authenticate
            var authResponse = _service.SendCommand(ConvertCompat.FromHexString("84820000103CA4BC00FAD9D1434F4086C4959E26B5"));
            Assert.That(authResponse.IsSuccessful, Is.True);

            // Assert
            Assert.That(_service.IsSecureChannelEstablished, Is.True);
        }

        [Test]
        public void SendCommand_InstallCapFile_WorksCorrectly()
        {
            // Arrange
            _service.Connect("Virtual ACOS Reader 00 00");
            EstablishSecureChannel(_service);

            // Act - Install for load
            var installForLoadResponse = _service.SendCommand(ConvertCompat.FromHexString("80E602000A05A01122334400000000"));
            Assert.That(installForLoadResponse.IsSuccessful, Is.True);

            // Load first block
            var loadResponse1 = _service.SendCommand(ConvertCompat.FromHexString("80E80000FF" + "C482011D010014DECAFFED020204"));
            Assert.That(loadResponse1.IsSuccessful, Is.True);

            // Load final block
            var loadResponse2 = _service.SendCommand(ConvertCompat.FromHexString("80E8800122" + "800A0103810E0103800A08068007"));
            Assert.That(loadResponse2.IsSuccessful, Is.True);

            // Install for install
            var installForInstallResponse = _service.SendCommand(ConvertCompat.FromHexString("80E60C001A05A01122334406A0112233440106A01122334401010002C90000"));
            Assert.That(installForInstallResponse.IsSuccessful, Is.True);

            // Verify application is installed by selecting it
            var selectAppResponse = _service.SendCommand(ConvertCompat.FromHexString("00A4040006A01122334401"));
            Assert.That(selectAppResponse.IsSuccessful, Is.True);
        }

        [Test]
        public void SendCommand_GetStatus_ReturnsApplicationInformation()
        {
            // Arrange
            _service.Connect("Virtual ACOS Reader 00 00");
            EstablishSecureChannel(_service);

            // Act
            var getStatusResponse = _service.SendCommand(ConvertCompat.FromHexString("80F28000024F0000"));

            // Assert
            Assert.That(getStatusResponse.IsSuccessful, Is.True);
            Assert.That(getStatusResponse.Data.Length, Is.GreaterThan(0));
        }

        [Test]
        public void SendCommand_DeleteApplication_RemovesApplication()
        {
            // Arrange
            _service.Connect("Virtual ACOS Reader 00 00");
            InstallTestApplication(_service);

            // Act - Delete the application
            var deleteResponse = _service.SendCommand(ConvertCompat.FromHexString("80E400000A4F06A01122334401"));
            Assert.That(deleteResponse.IsSuccessful, Is.True);

            // Verify application is no longer selectable
            var selectResponse = _service.SendCommand(ConvertCompat.FromHexString("00A4040006A01122334401"));
            Assert.That(selectResponse.IsSuccessful, Is.False);
        }

        [Test]
        public void Disconnect_WhenConnected_DisconnectsSuccessfully()
        {
            // Arrange
            _service.Connect("Virtual ACOS Reader 00 00");
            Assert.That(_service.IsConnected, Is.True);

            // Act
            _service.Disconnect();

            // Assert
            Assert.That(_service.IsConnected, Is.False);
        }

        [Test]
        public void Disconnect_WhenNotConnected_DoesNotThrow()
        {
            // Act & Assert
            Assert.DoesNotThrow(() => _service.Disconnect());
        }

        [Test]
        public void AddVirtualAcosReader_CreatesNewReader()
        {
            // Arrange
            var service = new VirtualCardService();
            var readerName = "Test ACOS Reader";

            // Act
            var reader = service.AddVirtualAcosReader(readerName);

            // Assert
            Assert.That(reader, Is.Not.Null);
            Assert.That(reader.ReaderName, Is.EqualTo(readerName));
            Assert.That(reader.IsCardPresent, Is.True);
            Assert.That(service.GetReaders(), Does.Contain(readerName));
        }

        [Test]
        public void SetupTestEnvironment_CreatesMultipleReaders()
        {
            // Arrange
            var service = new VirtualCardService();

            // Act
            service.SetupTestEnvironment();

            // Assert
            var readers = service.GetReaders();
            Assert.That(readers.Count, Is.GreaterThanOrEqualTo(2));
            Assert.That(readers, Does.Contain("Virtual ACOS Reader 00 00"));
            Assert.That(readers, Does.Contain("Virtual Test Reader 01 00"));
        }

        [Test]
        public void GetReaderManager_ReturnsReaderManager()
        {
            // Act
            var readerManager = _service.GetReaderManager();

            // Assert
            Assert.That(readerManager, Is.Not.Null);
            Assert.That(readerManager.GetReaderNames().Count, Is.GreaterThan(0));
        }

        [Test]
        public void Dispose_CleansUpResources()
        {
            // Arrange
            _service.Connect("Virtual ACOS Reader 00 00");

            // Act
            _service.Dispose();

            // Assert
            Assert.That(_service.IsConnected, Is.False);
        }

        private static void EstablishSecureChannel(VirtualCardService service)
        {
            // Select ISD
            service.SendCommand(ConvertCompat.FromHexString("00A4040008A000000151000000"));
            
            // Initialize Update
            service.SendCommand(ConvertCompat.FromHexString("80500000081122334455667788"));
            
            // External Authenticate
            service.SendCommand(ConvertCompat.FromHexString("84820000103CA4BC00FAD9D1434F4086C4959E26B5"));
        }

        private static void InstallTestApplication(VirtualCardService service)
        {
            EstablishSecureChannel(service);
            
            // Install for load
            service.SendCommand(ConvertCompat.FromHexString("80E602000A05A01122334400000000"));
            
            // Load (simplified)
            service.SendCommand(ConvertCompat.FromHexString("80E8800122800A0103810E0103800A08068007"));
            
            // Install for install
            service.SendCommand(ConvertCompat.FromHexString("80E60C001A05A01122334406A0112233440106A01122334401010002C90000"));
        }
    }
}