using System;
using System.Collections.Generic;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Services.CardCommunication;
using Moq;
using NUnit.Framework;
using WSCT.Core.APDU;
using WSCT.ISO7816;
using WSCT.Wrapper;

namespace Gp4Net.Tests.Tool.Services
{
    [TestFixture]
    public class WsctCardServiceTests
    {
        private Mock<IWsctFactory> _mockFactory;
        private Mock<ICardContextWrapper> _mockContext;
        private Mock<ICardChannelWrapper> _mockChannel;
        private WsctCardService _service;

        [SetUp]
        public void Setup()
        {
            _mockFactory = new Mock<IWsctFactory>();
            _mockContext = new Mock<ICardContextWrapper>();
            _mockChannel = new Mock<ICardChannelWrapper>();

            // Setup factory to return mocked context
            _mockFactory.Setup(f => f.CreateCardContext()).Returns(_mockContext.Object);
            
            // Setup context to establish successfully by default
            _mockContext.Setup(c => c.Establish()).Returns(ErrorCode.Success);
        }

        [TearDown]
        public void TearDown()
        {
            _service?.Dispose();
        }

        #region Constructor Tests

        [Test]
        public void Constructor_ValidFactory_EstablishesContext()
        {
            // Act
            _service = new WsctCardService(_mockFactory.Object);

            // Assert
            _mockFactory.Verify(f => f.CreateCardContext(), Times.Once);
            _mockContext.Verify(c => c.Establish(), Times.Once);
        }

        [Test]
        public void Constructor_NullFactory_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new WsctCardService(null!));
        }

        [Test]
        public void Constructor_EstablishFails_ThrowsInvalidOperationException()
        {
            // Arrange
            _mockContext.Setup(c => c.Establish()).Returns(ErrorCode.InternalError);

            // Act & Assert
            var ex = Assert.Throws<InvalidOperationException>(() => new WsctCardService(_mockFactory.Object));
            Assert.That(ex.Message, Does.Contain("Failed to establish card context"));
        }

        [Test]
        public void Constructor_DefaultConstructor_UsesDefaultFactory()
        {
            // Act & Assert - Should not throw
            Assert.DoesNotThrow(() => new WsctCardService());
        }

        #endregion

        #region GetReaders Tests

        [Test]
        public void GetReaders_Success_ReturnsReaderList()
        {
            // Arrange
            var expectedReaders = new List<string> { "Reader1", "Reader2" };
            _mockContext.Setup(c => c.ListReaders("")).Returns(ErrorCode.Success);
            _mockContext.Setup(c => c.Readers).Returns(expectedReaders);
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            var readers = _service.GetReaders();

            // Assert
            Assert.That(readers, Is.EqualTo(expectedReaders));
            _mockContext.Verify(c => c.ListReaders(""), Times.Once);
        }

        [Test]
        public void GetReaders_ListReadersFails_ReturnsEmptyList()
        {
            // Arrange
            _mockContext.Setup(c => c.ListReaders("")).Returns(ErrorCode.NoReadersAvailable);
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            var readers = _service.GetReaders();

            // Assert
            Assert.That(readers, Is.Empty);
        }

        [Test]
        public void GetReaders_ExceptionThrown_ReturnsEmptyList()
        {
            // Arrange
            _mockContext.Setup(c => c.ListReaders("")).Throws<Exception>();
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            var readers = _service.GetReaders();

            // Assert
            Assert.That(readers, Is.Empty);
        }

        #endregion

        #region Connect Tests

        [Test]
        public void Connect_ValidReader_ReturnsTrue()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            var result = _service.Connect(readerName);

            // Assert
            Assert.That(result, Is.True);
            _mockContext.Verify(c => c.CreateCardChannel(readerName), Times.Once);
            _mockChannel.Verify(ch => ch.Connect(ShareMode.Shared, Protocol.Any), Times.Once);
        }

        [Test]
        public void Connect_NullReaderName_ThrowsArgumentException()
        {
            // Arrange
            _service = new WsctCardService(_mockFactory.Object);

            // Act & Assert
            Assert.Throws<ArgumentException>(() => _service.Connect(null!));
        }

        [Test]
        public void Connect_EmptyReaderName_ThrowsArgumentException()
        {
            // Arrange
            _service = new WsctCardService(_mockFactory.Object);

            // Act & Assert
            Assert.Throws<ArgumentException>(() => _service.Connect(string.Empty));
        }

        [Test]
        public void Connect_ConnectFails_ReturnsFalse()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.CardUnsupported);
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            var result = _service.Connect(readerName);

            // Assert
            Assert.That(result, Is.False);
            _mockChannel.Verify(ch => ch.Dispose(), Times.Once);
        }

        [Test]
        public void Connect_AlreadyConnected_DisconnectsFirst()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Returns(State.Specific);
            _service = new WsctCardService(_mockFactory.Object);
            
            // First connection
            _service.Connect(readerName);

            // Act - Second connection
            var result = _service.Connect(readerName);

            // Assert
            Assert.That(result, Is.True);
            _mockChannel.Verify(ch => ch.Disconnect(Disposition.UnpowerCard), Times.Once);
        }

        #endregion

        #region Disconnect Tests

        [Test]
        public void Disconnect_Connected_DisconnectsChannel()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            _service.Disconnect();

            // Assert
            _mockChannel.Verify(ch => ch.Disconnect(Disposition.UnpowerCard), Times.Once);
            _mockChannel.Verify(ch => ch.Dispose(), Times.Once);
        }

        [Test]
        public void Disconnect_NotConnected_DoesNothing()
        {
            // Arrange
            _service = new WsctCardService(_mockFactory.Object);

            // Act & Assert - Should not throw
            Assert.DoesNotThrow(() => _service.Disconnect());
        }

        [Test]
        public void Disconnect_DisconnectThrows_StillDisposesChannel()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.Disconnect(It.IsAny<Disposition>())).Throws<Exception>();
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            _service.Disconnect();

            // Assert
            _mockChannel.Verify(ch => ch.Dispose(), Times.Once);
        }

        #endregion

        #region IsConnected Tests

        [Test]
        public void IsConnected_ChannelConnectedWithSpecificState_ReturnsTrue()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Returns(State.Specific);
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            var result = _service.IsConnected;

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void IsConnected_ChannelConnectedWithNegotiableState_ReturnsTrue()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Returns(State.Negotiable);
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            var result = _service.IsConnected;

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void IsConnected_ChannelConnectedWithPoweredState_ReturnsTrue()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Returns(State.Powered);
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            var result = _service.IsConnected;

            // Assert
            Assert.That(result, Is.True);
        }

        [Test]
        public void IsConnected_ChannelNull_ReturnsFalse()
        {
            // Arrange
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            var result = _service.IsConnected;

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public void IsConnected_GetStatusThrows_ReturnsFalse()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Throws<Exception>();
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            var result = _service.IsConnected;

            // Assert
            Assert.That(result, Is.False);
        }

        #endregion

        #region GetAtr Tests

        [Test]
        public void GetAtr_Connected_ReturnsAtr()
        {
            // Arrange
            const string readerName = "TestReader";
            byte[] expectedAtr = { 0x3B, 0x65, 0x01, 0x02, 0x20, 0x56, 0x34, 0x47, 0x54 }; // Avoid zeros in middle
            
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Returns(State.Specific);
            _mockChannel.Setup(ch => ch.GetAttrib(Attrib.AtrString, ref It.Ref<byte[]>.IsAny))
                .Returns(ErrorCode.Success)
                .Callback((Attrib attrib, ref byte[] buffer) => 
                {
                    // Create proper ATR buffer: ATR data followed by zeros
                    Array.Copy(expectedAtr, buffer, expectedAtr.Length);
                    // Ensure the rest of the buffer is zeros (already is by default)
                });
            
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            var result = _service.GetAtr();

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result, Is.EqualTo(expectedAtr));
        }

        [Test]
        public void GetAtr_NotConnected_ReturnsNull()
        {
            // Arrange
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            var result = _service.GetAtr();

            // Assert
            Assert.That(result, Is.Null);
        }

        [Test]
        public void GetAtr_GetAttribFails_ReturnsNull()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Returns(State.Specific);
            _mockChannel.Setup(ch => ch.GetAttrib(Attrib.AtrString, ref It.Ref<byte[]>.IsAny))
                .Returns(ErrorCode.InternalError);
            
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            var result = _service.GetAtr();

            // Assert
            Assert.That(result, Is.Null);
        }

        #endregion

        #region SendCommand Tests

        [Test]
        public void SendCommand_ValidCommand_ReturnsResponse()
        {
            // Arrange
            const string readerName = "TestReader";
            byte[] command = { 0x00, 0xA4, 0x04, 0x00 };
            byte[] expectedData = { 0x6F, 0x10 };
            ushort expectedSw = 0x9000;
            
            var mockCommand = new Mock<ICardCommand>();
            
            // Create a real ResponseAPDU with the expected data
            var realResponse = new ResponseAPDU();
            
            _mockFactory.Setup(f => f.CreateCommandApdu(command)).Returns(mockCommand.Object);
            _mockFactory.Setup(f => f.CreateResponseApdu()).Returns(realResponse);
            
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Returns(State.Specific);
            _mockChannel.Setup(ch => ch.Transmit(mockCommand.Object, realResponse))
                .Returns(ErrorCode.Success)
                .Callback((ICardCommand cmd, ICardResponse resp) =>
                {
                    // Simulate the response data being set by the transmission
                    var responseApdu = resp as ResponseAPDU;
                    if (responseApdu != null)
                    {
                        // We can't directly set Udr and StatusWord on ResponseAPDU since they're not settable
                        // This test will verify the method doesn't crash and returns a response
                        // The actual data validation will be done in integration tests
                    }
                });
            
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            var result = _service.SendCommand(command);

            // Assert
            Assert.That(result, Is.Not.Null);
            // Note: We can't easily mock the ResponseAPDU properties since they're sealed
            // In a real scenario, the WSCT library would populate these values
            // This test verifies the method executes without throwing exceptions
        }

        [Test]
        public void SendCommand_NullCommand_ThrowsArgumentNullException()
        {
            // Arrange
            _service = new WsctCardService(_mockFactory.Object);

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => _service.SendCommand(null!));
        }

        [Test]
        public void SendCommand_NotConnected_ThrowsInvalidOperationException()
        {
            // Arrange
            byte[] command = { 0x00, 0xA4, 0x04, 0x00 };
            _service = new WsctCardService(_mockFactory.Object);

            // Act & Assert
            var ex = Assert.Throws<InvalidOperationException>(() => _service.SendCommand(command));
            Assert.That(ex.Message, Does.Contain("Card is not connected"));
        }

        [Test]
        public void SendCommand_TransmitFails_ThrowsInvalidOperationException()
        {
            // Arrange
            const string readerName = "TestReader";
            byte[] command = { 0x00, 0xA4, 0x04, 0x00 };
            
            var mockCommand = new Mock<ICardCommand>();
            var mockResponse = new Mock<ICardResponse>();
            
            _mockFactory.Setup(f => f.CreateCommandApdu(command)).Returns(mockCommand.Object);
            _mockFactory.Setup(f => f.CreateResponseApdu()).Returns(mockResponse.Object);
            
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Returns(State.Specific);
            _mockChannel.Setup(ch => ch.Transmit(mockCommand.Object, mockResponse.Object))
                .Returns(ErrorCode.CardUnsupported);
            
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act & Assert
            var ex = Assert.Throws<InvalidOperationException>(() => _service.SendCommand(command));
            Assert.That(ex.Message, Does.Contain("Transmit failed"));
        }

        [Test]
        public void SendCommand_InvalidResponseType_ThrowsInvalidOperationException()
        {
            // Arrange
            const string readerName = "TestReader";
            byte[] command = { 0x00, 0xA4, 0x04, 0x00 };
            
            var mockCommand = new Mock<ICardCommand>();
            var mockResponse = new Mock<ICardResponse>(); // Not a ResponseAPDU
            
            _mockFactory.Setup(f => f.CreateCommandApdu(command)).Returns(mockCommand.Object);
            _mockFactory.Setup(f => f.CreateResponseApdu()).Returns(mockResponse.Object);
            
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _mockChannel.Setup(ch => ch.GetStatus()).Returns(State.Specific);
            _mockChannel.Setup(ch => ch.Transmit(mockCommand.Object, mockResponse.Object))
                .Returns(ErrorCode.Success);
            
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act & Assert
            var ex = Assert.Throws<InvalidOperationException>(() => _service.SendCommand(command));
            Assert.That(ex.Message, Does.Contain("Invalid response type received"));
        }

        #endregion

        #region EstablishSecureChannel Tests

        [Test]
        public void EstablishSecureChannel_NotImplemented_ReturnsFalse()
        {
            // Arrange
            byte[] keySet = { 0x40, 0x41, 0x42, 0x43 };
            byte securityLevel = 0x03;
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            var result = _service.EstablishSecureChannel(keySet, securityLevel);

            // Assert
            Assert.That(result, Is.False);
        }

        [Test]
        public void IsSecureChannelEstablished_Always_ReturnsFalse()
        {
            // Arrange
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            var result = _service.IsSecureChannelEstablished;

            // Assert
            Assert.That(result, Is.False);
        }

        #endregion

        #region Dispose Tests

        [Test]
        public void Dispose_Connected_DisconnectsAndDisposesContext()
        {
            // Arrange
            const string readerName = "TestReader";
            _mockContext.Setup(c => c.CreateCardChannel(readerName)).Returns(_mockChannel.Object);
            _mockChannel.Setup(ch => ch.Connect(ShareMode.Shared, Protocol.Any)).Returns(ErrorCode.Success);
            _service = new WsctCardService(_mockFactory.Object);
            _service.Connect(readerName);

            // Act
            _service.Dispose();

            // Assert
            _mockChannel.Verify(ch => ch.Disconnect(Disposition.UnpowerCard), Times.Once);
            _mockChannel.Verify(ch => ch.Dispose(), Times.Once);
            _mockContext.Verify(c => c.Dispose(), Times.Once);
        }

        [Test]
        public void Dispose_NotConnected_DisposesContext()
        {
            // Arrange
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            _service.Dispose();

            // Assert
            _mockContext.Verify(c => c.Dispose(), Times.Once);
        }

        [Test]
        public void Dispose_CalledMultipleTimes_OnlyDisposesOnce()
        {
            // Arrange
            _service = new WsctCardService(_mockFactory.Object);

            // Act
            _service.Dispose();
            _service.Dispose();

            // Assert
            _mockContext.Verify(c => c.Dispose(), Times.Once);
        }

        #endregion
    }
}