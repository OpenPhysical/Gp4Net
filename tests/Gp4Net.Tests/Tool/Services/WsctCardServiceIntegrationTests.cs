using System;
using System.Linq;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Services.CardCommunication;
using NUnit.Framework;

namespace Gp4Net.Tests.Tool.Services
{
    /// <summary>
    /// Integration tests for WsctCardService that require real hardware.
    /// These tests are marked with [Explicit] and must be run manually with a card reader connected.
    /// </summary>
    [TestFixture]
    [Category("Integration")]
    [Explicit("Requires physical smart card reader and card")]
    public class WsctCardServiceIntegrationTests
    {
        private WsctCardService _service;

        [SetUp]
        public void Setup()
        {
            _service = new WsctCardService();
        }

        [TearDown]
        public void TearDown()
        {
            _service?.Dispose();
        }

        [Test]
        public void GetReaders_WithPhysicalReaders_ReturnsAtLeastOneReader()
        {
            // Act
            var readers = _service.GetReaders();

            // Assert
            Assert.That(readers, Is.Not.Null);
            Assert.That(readers.Count, Is.GreaterThan(0), "No card readers found. Please connect a card reader.");
            
            // Log the readers found
            foreach (var reader in readers)
            {
                TestContext.WriteLine($"Found reader: {reader}");
            }
        }

        [Test]
        public void ConnectToCard_WithCardPresent_Succeeds()
        {
            // Arrange
            var readers = _service.GetReaders();
            Assert.That(readers.Count, Is.GreaterThan(0), "No card readers found");
            
            var readerName = readers.First();
            TestContext.WriteLine($"Attempting to connect to reader: {readerName}");

            // Act
            var connected = _service.Connect(readerName);

            // Assert
            Assert.That(connected, Is.True, $"Failed to connect to card in reader: {readerName}. Please ensure a card is inserted.");
            Assert.That(_service.IsConnected, Is.True);
        }

        [Test]
        public void GetAtr_WithConnectedCard_ReturnsValidAtr()
        {
            // Arrange
            ConnectToFirstAvailableCard();

            // Act
            var atr = _service.GetAtr();

            // Assert
            Assert.That(atr, Is.Not.Null);
            Assert.That(atr.Length, Is.GreaterThan(0));
            
            TestContext.WriteLine($"Card ATR: {Convert.ToHexString(atr)}");
            
            // Basic ATR validation - should start with TS byte (3B or 3F)
            Assert.That(atr[0], Is.EqualTo(0x3B).Or.EqualTo(0x3F), "Invalid TS byte in ATR");
        }

        [Test]
        public void SendSelectCommand_ToMasterFile_ReturnsSuccess()
        {
            // Arrange
            ConnectToFirstAvailableCard();
            
            // SELECT MF (Master File) command
            byte[] selectMfCommand = { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00 };

            // Act
            var response = _service.SendCommand(selectMfCommand);

            // Assert
            Assert.That(response, Is.Not.Null);
            TestContext.WriteLine($"Response SW: {response.StatusWord:X4}");
            TestContext.WriteLine($"Response Data: {Convert.ToHexString(response.Data)}");
            
            // Check for success status words (90 00 or 61 XX)
            Assert.That(response.StatusWord, Is.EqualTo(0x9000).Or.InRange(0x6100, 0x61FF), 
                $"Unexpected status word: {response.StatusWord:X4}");
        }

        [Test]
        public void SendGetDataCommand_ForCardData_ReturnsData()
        {
            // Arrange
            ConnectToFirstAvailableCard();
            
            // GET DATA command for Card Production Life Cycle Data (CPLC)
            byte[] getDataCommand = { 0x80, 0xCA, 0x9F, 0x7F, 0x00 };

            // Act
            var response = _service.SendCommand(getDataCommand);

            // Assert
            Assert.That(response, Is.Not.Null);
            TestContext.WriteLine($"Response SW: {response.StatusWord:X4}");
            
            if (response.StatusWord == 0x9000)
            {
                TestContext.WriteLine($"CPLC Data: {Convert.ToHexString(response.Data)}");
                Assert.That(response.Data.Length, Is.GreaterThan(0));
            }
            else if (response.StatusWord == 0x6A88)
            {
                TestContext.WriteLine("Card does not support CPLC data (6A88 - Referenced data not found)");
            }
            else
            {
                Assert.Fail($"Unexpected status word: {response.StatusWord:X4}");
            }
        }

        [Test]
        public void DisconnectAndReconnect_MultipleOperations_Succeeds()
        {
            // Arrange
            var readers = _service.GetReaders();
            Assert.That(readers.Count, Is.GreaterThan(0), "No card readers found");
            var readerName = readers.First();

            // Act & Assert - First connection
            Assert.That(_service.Connect(readerName), Is.True);
            Assert.That(_service.IsConnected, Is.True);
            
            var atr1 = _service.GetAtr();
            Assert.That(atr1, Is.Not.Null);

            // Disconnect
            _service.Disconnect();
            Assert.That(_service.IsConnected, Is.False);

            // Reconnect
            Assert.That(_service.Connect(readerName), Is.True);
            Assert.That(_service.IsConnected, Is.True);
            
            var atr2 = _service.GetAtr();
            Assert.That(atr2, Is.Not.Null);
            
            // ATR should be the same
            Assert.That(atr2, Is.EqualTo(atr1));
        }

        [Test]
        [TestCase(new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x08 })] // READ BINARY
        [TestCase(new byte[] { 0x00, 0xC0, 0x00, 0x00, 0x00 })] // GET RESPONSE
        public void SendVariousCommands_ToCard_HandlesResponsesCorrectly(byte[] command)
        {
            // Arrange
            ConnectToFirstAvailableCard();

            // Act
            var response = _service.SendCommand(command);

            // Assert
            Assert.That(response, Is.Not.Null);
            TestContext.WriteLine($"Command: {Convert.ToHexString(command)}");
            TestContext.WriteLine($"Response SW: {response.StatusWord:X4}");
            TestContext.WriteLine($"Response Data: {Convert.ToHexString(response.Data)}");
            
            // We expect some kind of response, even if it's an error
            Assert.That(response.StatusWord, Is.Not.Zero);
        }

        #region Helper Methods

        private void ConnectToFirstAvailableCard()
        {
            var readers = _service.GetReaders();
            Assert.That(readers.Count, Is.GreaterThan(0), "No card readers found");
            
            bool connected = false;
            foreach (var reader in readers)
            {
                TestContext.WriteLine($"Trying to connect to reader: {reader}");
                if (_service.Connect(reader))
                {
                    connected = true;
                    TestContext.WriteLine($"Successfully connected to: {reader}");
                    break;
                }
            }
            
            Assert.That(connected, Is.True, "Failed to connect to any card reader. Please ensure a card is inserted.");
        }

        #endregion
    }
}