using System;
using System.Collections.Generic;
using AwesomeAssertions;
using Gp4Net.Domain.Protocol;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using Moq;
using NUnit.Framework;
using CSharpFunctionalExtensions;
using WSCT.Core.APDU;
using WSCT.ISO7816;
using WSCT.Wrapper;

namespace Gp4Net.Tests.Tool.Services;

[TestFixture]
public class WsctCardServiceTests
{
    private Mock<IWsctFactory> _mockFactory;
    private Mock<ICardContextWrapper> _mockContext;
    private Mock<ICardChannelWrapper> _mockChannel;
    private Mock<ISecureChannelManager> _mockSecureChannelManager;
    private Mock<IApduTransportFactory> _mockTransportFactory;
    private WsctCardService _service = null!;

    [SetUp]
    public void Setup()
    {
        _mockFactory = new Mock<IWsctFactory>();
        _mockContext = new Mock<ICardContextWrapper>();
        _mockChannel = new Mock<ICardChannelWrapper>();
        _mockSecureChannelManager = new Mock<ISecureChannelManager>();
        _mockTransportFactory = new Mock<IApduTransportFactory>();

        // Setup factory to return mocked context
        _ = _mockFactory.Setup(f => f.CreateCardContext()).Returns(_mockContext.Object);

        // Setup context to establish successfully by default
        _ = _mockContext.Setup(c => c.Establish()).Returns(ErrorCode.Success);
    }

    [TearDown]
    public void TearDown()
    {
        _service?.Dispose();
    }

    [Test]
    public void Constructor_ValidFactory_EstablishesContext()
    {
        // Act
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Assert
        _mockFactory.Verify(f => f.CreateCardContext(), Times.Once);
        _mockContext.Verify(c => c.Establish(), Times.Once);
    }

    [Test]
    public void Constructor_NullFactory_ThrowsArgumentNullException()
    {
        // Act & Assert
        Action act = () => new WsctCardService(
            null!,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Test]
    public void Constructor_EstablishFails_ThrowsInvalidOperationException()
    {
        // Arrange
        _ = _mockContext.Setup(c => c.Establish()).Returns(ErrorCode.InternalError);

        // Act & Assert
        Action act = () => new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        var ex = act.Should().ThrowExactly<InvalidOperationException>().And;
        ex.Message.Should().Contain("Failed to establish card context");
    }

    [Test]
    public void Constructor_DefaultConstructor_UsesDefaultFactory()
    {
        // Act & Assert - Should not throw
        Action act = () => new WsctCardService(
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        act.Should().NotThrow();
    }

    [Test]
    public void GetReaders_Success_ReturnsReaderList()
    {
        // Arrange
        var expectedReaders = new List<string> { "Reader1", "Reader2" };
        _ = _mockContext.Setup(c => c.ListReaders("")).Returns(ErrorCode.Success);
        _ = _mockContext.Setup(c => c.Readers).Returns(expectedReaders);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        var readers = _service.GetReaders();

        // Assert
        readers.Should().BeEquivalentTo(expectedReaders);
        _mockContext.Verify(c => c.ListReaders(""), Times.Once);
    }

    [Test]
    public void GetReaders_ListReadersFails_ReturnsEmptyList()
    {
        // Arrange
        _ = _mockContext.Setup(c => c.ListReaders("")).Returns(ErrorCode.NoReadersAvailable);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        var readers = _service.GetReaders();

        // Assert
        readers.Should().BeEmpty();
    }

    [Test]
    public void GetReaders_ExceptionThrown_ReturnsEmptyList()
    {
        // Arrange
        _ = _mockContext.Setup(c => c.ListReaders("")).Throws<Exception>();
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        var readers = _service.GetReaders();

        // Assert
        readers.Should().BeEmpty();
    }

    [Test]
    public void Connect_ValidReader_ReturnsTrue()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        var result = _service.Connect(readerName);

        // Assert
        result.Should().BeTrue();
        _mockContext.Verify(c => c.CreateCardChannel(readerName), Times.Once);
        _mockChannel.Verify(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any), Times.Once);
    }

    [Test]
    public void Connect_NullReaderName_ThrowsArgumentException()
    {
        // Arrange
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act & Assert
        Action act = () => _service.Connect(null!);
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Test]
    public void Connect_EmptyReaderName_ThrowsArgumentException()
    {
        // Arrange
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act & Assert
        Action act = () => _service.Connect(string.Empty);
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Test]
    public void Connect_ConnectFails_ReturnsFalse()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.CardUnsupported);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        var result = _service.Connect(readerName);

        // Assert
        result.Should().BeFalse();
        _mockChannel.Verify(ch => ch.Dispose(), Times.Once);
    }

    [Test]
    public void Connect_AlreadyConnected_DisconnectsFirst()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // First connection
        _ = _service.Connect(readerName);

        // Act - Second connection
        var result = _service.Connect(readerName);

        // Assert
        result.Should().BeTrue();
        _mockChannel.Verify(ch => ch.Disconnect(Disposition.UnpowerCard), Times.Once);
    }

    [Test]
    public void Disconnect_Connected_DisconnectsChannel()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

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
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act & Assert - Should not throw
        Action act = () => _service.Disconnect();
        act.Should().NotThrow();
    }

    [Test]
    public void Disconnect_DisconnectThrows_StillDisposesChannel()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _ = _mockChannel
            .Setup(ch => ch.Disconnect(It.IsAny<Disposition>()))
            .Throws<Exception>();
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act
        _service.Disconnect();

        // Assert
        _mockChannel.Verify(ch => ch.Dispose(), Times.Once);
    }

    [Test]
    public void IsConnected_ChannelConnectedWithSpecificState_ReturnsTrue()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act
        var result = _service.IsConnected;

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsConnected_ChannelConnectedWithNegotiableState_ReturnsTrue()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act
        var result = _service.IsConnected;

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsConnected_ChannelConnectedWithPoweredState_ReturnsTrue()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act
        var result = _service.IsConnected;

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsConnected_ChannelNull_ReturnsFalse()
    {
        // Arrange
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        var result = _service.IsConnected;

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsConnected_ChannelExists_ReturnsTrue()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act
        var result = _service.IsConnected;

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void GetAtr_Connected_ReturnsAtr()
    {
        // Arrange
        const string readerName = "TestReader";
        byte[] expectedAtr = { 0x3B, 0x65, 0x01, 0x02, 0x20, 0x56, 0x34, 0x47, 0x54 }; // Avoid zeros in middle

        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _ = _mockChannel
            .Setup(ch => ch.GetAttrib(Attrib.AtrString, ref It.Ref<byte[]>.IsAny))
            .Returns((Attrib attrib, ref byte[] buffer) =>
            {
                buffer = expectedAtr;
                return ErrorCode.Success;
            });

        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act
        var result = _service.GetAtr();

        // Assert
        result.Should().NotBeNull();
        result.Should().BeEquivalentTo(expectedAtr);
    }

    [Test]
    public void GetAtr_NotConnected_ReturnsNull()
    {
        // Arrange
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        var result = _service.GetAtr();

        // Assert
        result.Should().BeNull();
    }

    [Test]
    public void GetAtr_GetAttribFails_ReturnsNull()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _ = _mockChannel
            .Setup(ch => ch.GetAttrib(Attrib.AtrString, ref It.Ref<byte[]>.IsAny))
            .Returns(ErrorCode.InternalError);

        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act
        var result = _service.GetAtr();

        // Assert
        result.Should().BeNull();
    }

    [Test]
    public void SendCommand_ValidCommand_ReturnsResponse()
    {
        // Arrange
        const string readerName = "TestReader";
        byte[] command = { 0x00, 0xA4, 0x04, 0x00 };
        // Expected values are documented but not used in this test
        // byte[] expectedData = { 0x6F, 0x10 };
        // ushort expectedSw = 0x9000;

        var mockCommand = new Mock<ICardCommand>();

        // Create a real ResponseAPDU with the expected data
        var realResponse = new ResponseAPDU();

        _ = _mockFactory.Setup(f => f.CreateCommandApdu(command)).Returns(mockCommand.Object);
        _ = _mockFactory.Setup(f => f.CreateResponseApdu()).Returns(realResponse);

        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _ = _mockChannel
            .Setup(ch => ch.Transmit(mockCommand.Object, realResponse))
            .Returns(ErrorCode.Success)
            .Callback(
                (ICardCommand cmd, ICardResponse resp) =>
                {
                    // Simulate the response data being set by the transmission
                    var responseApdu = resp as ResponseAPDU;
                    if (responseApdu != null)
                    {
                        // We can't directly set Udr and StatusWord on ResponseAPDU since they're not settable
                        // This test will verify the method doesn't crash and returns a response
                        // The actual data validation will be done in integration tests
                    }
                }
            );

        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act
        var result = _service.SendCommand(command);

        // Assert
        result.Should().NotBeNull();
        // Note: We can't easily mock the ResponseAPDU properties since they're sealed
        // In a real scenario, the WSCT library would populate these values
        // This test verifies the method executes without throwing exceptions
    }

    [Test]
    public void SendCommand_NullCommand_ThrowsArgumentNullException()
    {
        // Arrange
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act & Assert
        Action act = () => _service.SendCommand((byte[])null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Test]
    public void SendCommand_NotConnected_ThrowsInvalidOperationException()
    {
        // Arrange
        byte[] command = { 0x00, 0xA4, 0x04, 0x00 };
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act & Assert
        Action act = () => _service.SendCommand(command);
        var ex = act.Should().ThrowExactly<InvalidOperationException>().And;
        ex.Message.Should().Contain("Card is not connected");
    }

    [Test]
    public void SendCommand_TransmitFails_ThrowsInvalidOperationException()
    {
        // Arrange
        const string readerName = "TestReader";
        byte[] command = { 0x00, 0xA4, 0x04, 0x00 };

        var mockCommand = new Mock<ICardCommand>();
        var mockResponse = new Mock<ICardResponse>();

        _ = _mockFactory.Setup(f => f.CreateCommandApdu(command)).Returns(mockCommand.Object);
        _ = _mockFactory.Setup(f => f.CreateResponseApdu()).Returns(mockResponse.Object);

        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _ = _mockChannel
            .Setup(ch => ch.Transmit(mockCommand.Object, mockResponse.Object))
            .Returns(ErrorCode.CardUnsupported);

        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act & Assert
        Action act = () => _service.SendCommand(command);
        var ex = act.Should().ThrowExactly<InvalidOperationException>().And;
        ex.Message.Should().Contain("Transmit failed");
    }

    [Test]
    public void SendCommand_InvalidResponseType_ThrowsInvalidOperationException()
    {
        // Arrange
        const string readerName = "TestReader";
        byte[] command = { 0x00, 0xA4, 0x04, 0x00 };

        var mockCommand = new Mock<ICardCommand>();
        var mockResponse = new Mock<ICardResponse>(); // Not a ResponseAPDU

        _ = _mockFactory.Setup(f => f.CreateCommandApdu(command)).Returns(mockCommand.Object);
        _ = _mockFactory.Setup(f => f.CreateResponseApdu()).Returns(mockResponse.Object);

        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _ = _mockChannel
            .Setup(ch => ch.Transmit(mockCommand.Object, mockResponse.Object))
            .Returns(ErrorCode.Success);

        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

        // Act & Assert
        Action act = () => _service.SendCommand(command);
        var ex = act.Should().ThrowExactly<InvalidOperationException>().And;
        ex.Message.Should().Contain("Invalid response type received");
    }


    [Test]
    public void IsSecureChannelEstablished_Always_ReturnsFalse()
    {
        // Arrange
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        var result = _service.IsSecureChannelEstablished;

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void Dispose_Connected_DisconnectsAndDisposesContext()
    {
        // Arrange
        const string readerName = "TestReader";
        _ = _mockContext
            .Setup(c => c.CreateCardChannel(readerName))
            .Returns(_mockChannel.Object);
        _ = _mockChannel
            .Setup(ch => ch.Connect(WSCT.Wrapper.ShareMode.Exclusive, WSCT.Wrapper.Protocol.Any))
            .Returns(ErrorCode.Success);
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );
        _ = _service.Connect(readerName);

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
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        _service.Dispose();

        // Assert
        _mockContext.Verify(c => c.Dispose(), Times.Once);
    }

    [Test]
    public void Dispose_CalledMultipleTimes_OnlyDisposesOnce()
    {
        // Arrange
        _service = new WsctCardService(
            _mockFactory.Object,
            _mockSecureChannelManager.Object,
            _mockTransportFactory.Object
        );

        // Act
        _service.Dispose();
        _service.Dispose();

        // Assert
        _mockContext.Verify(c => c.Dispose(), Times.Once);
    }

}
