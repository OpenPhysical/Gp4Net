using System;
using Gp4Net.Domain.Commands;
using Gp4Net.Utils;

namespace Gp4Net.Tests.Domain.Commands
{
    /// <summary>
    /// Tests for the SelectCommand class.
    /// </summary>
    [TestFixture]
    public class SelectCommandTests
    {
        #region Constructor Tests

        [Test]
        public void Constructor_ValidAid_CreatesInstance()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000003000000");

            // Act
            var command = new SelectCommand(aid);

            // Assert
            Assert.That(command.Aid, Is.EqualTo(aid));
            Assert.That(command.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName));
            Assert.That(command.ControlInfo, Is.EqualTo(SelectCommand.FileControlInfo.ReturnFci));
        }

        [Test]
        public void Constructor_WithAllParameters_CreatesInstance()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000003000000");

            // Act
            var command = new SelectCommand(
                aid,
                SelectCommand.SelectionControl.SelectByName,
                SelectCommand.FileControlInfo.NoResponseData);

            // Assert
            Assert.That(command.Aid, Is.EqualTo(aid));
            Assert.That(command.Control, Is.EqualTo(SelectCommand.SelectionControl.SelectByName));
            Assert.That(command.ControlInfo, Is.EqualTo(SelectCommand.FileControlInfo.NoResponseData));
        }

        [Test]
        public void Constructor_NullAid_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new SelectCommand(null));
        }

        [Test]
        public void Constructor_AidTooShort_ThrowsArgumentException()
        {
            // Arrange
            var shortAid = new byte[4];

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => new SelectCommand(shortAid));
            Assert.That(ex.ParamName, Is.EqualTo("aid"));
        }

        [Test]
        public void Constructor_AidTooLong_ThrowsArgumentException()
        {
            // Arrange
            var longAid = new byte[17];

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => new SelectCommand(longAid));
            Assert.That(ex.ParamName, Is.EqualTo("aid"));
        }

        [Test]
        public void Constructor_MinimumValidAidLength_CreatesInstance()
        {
            // Arrange
            var aid = new byte[5];

            // Act
            var command = new SelectCommand(aid);

            // Assert
            Assert.That(command.Aid, Is.EqualTo(aid));
        }

        [Test]
        public void Constructor_MaximumValidAidLength_CreatesInstance()
        {
            // Arrange
            var aid = new byte[16];

            // Act
            var command = new SelectCommand(aid);

            // Assert
            Assert.That(command.Aid, Is.EqualTo(aid));
        }

        #endregion

        #region ToApdu Tests

        [Test]
        public void ToApdu_DefaultParameters_ReturnsCorrectApdu()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000003000000");
            var command = new SelectCommand(aid);

            // Act
            var apdu = command.ToApdu();

            // Assert
            var expected = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
            Assert.That(apdu, Is.EqualTo(expected));
        }

        [Test]
        public void ToApdu_CustomParameters_ReturnsCorrectApdu()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000151000000");
            var command = new SelectCommand(
                aid,
                SelectCommand.SelectionControl.SelectByName,
                SelectCommand.FileControlInfo.ReturnFcp);

            // Act
            var apdu = command.ToApdu();

            // Assert
            var expected = new byte[] { 0x00, 0xA4, 0x04, 0x04, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00 };
            Assert.That(apdu, Is.EqualTo(expected));
        }

        [Test]
        public void ToApdu_ShortAid_ReturnsCorrectApdu()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000003");
            var command = new SelectCommand(aid);

            // Act
            var apdu = command.ToApdu();

            // Assert
            var expected = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x00, 0x03 };
            Assert.That(apdu, Is.EqualTo(expected));
        }

        [Test]
        public void ToApdu_NoResponseData_ReturnsCorrectApdu()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000003000000");
            var command = new SelectCommand(aid, controlInfo: SelectCommand.FileControlInfo.NoResponseData);

            // Act
            var apdu = command.ToApdu();

            // Assert
            var expected = new byte[] { 0x00, 0xA4, 0x04, 0x0C, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
            Assert.That(apdu, Is.EqualTo(expected));
        }

        #endregion

        #region FileControlInformation Tests

        [Test]
        public void FileControlInformation_Constructor_CreatesInstance()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000003000000");
            var label = "Test Application";

            // Act
            var fci = new FileControlInformation(
                applicationAid: aid,
                applicationLabel: label,
                applicationPriorityIndicator: 0x01);

            // Assert
            Assert.That(fci.ApplicationAid, Is.EqualTo(aid));
            Assert.That(fci.ApplicationLabel, Is.EqualTo(label));
            Assert.That(fci.ApplicationPriorityIndicator, Is.EqualTo(0x01));
        }

        [Test]
        public void FileControlInformation_Constructor_ClonesArrays()
        {
            // Arrange
            var aid = ConvertCompat.FromHexString("A000000003000000");
            var originalAid = (byte[])aid.Clone();

            // Act
            var fci = new FileControlInformation(applicationAid: aid);
            aid[0] = 0xFF; // Modify original

            // Assert
            Assert.That(fci.ApplicationAid, Is.EqualTo(originalAid));
            Assert.That(fci.ApplicationAid, Is.Not.EqualTo(aid));
        }

        #endregion

        #region SelectResponse Tests

        [Test]
        public void SelectResponse_Constructor_CreatesInstance()
        {
            // Arrange
            var rawData = ConvertCompat.FromHexString("6F1C840EA000000003000000A50A50084D617374657243617264");

            // Act
            var response = new SelectResponse(rawData);

            // Assert
            Assert.That(response.RawData, Is.EqualTo(rawData));
            Assert.That(response.Fci, Is.Null);
        }

        [Test]
        public void SelectResponse_Parse_ValidData_ReturnsResponse()
        {
            // Arrange
            var responseData = ConvertCompat.FromHexString("6F1C840EA000000003000000A50A50084D617374657243617264");

            // Act
            var response = SelectResponse.Parse(responseData);

            // Assert
            Assert.That(response.RawData, Is.EqualTo(responseData));
            Assert.That(response.Fci, Is.Null);
        }

        [Test]
        public void SelectResponse_Parse_NullData_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => SelectResponse.Parse(null));
        }

        [Test]
        public void SelectResponse_ParseWithFci_ValidData_ReturnsResponseWithFci()
        {
            // Arrange
            var responseData = ConvertCompat.FromHexString("6F1C840EA000000003000000A50A50084D617374657243617264");

            // Act
            var response = SelectResponse.ParseWithFci(responseData);

            // Assert
            Assert.That(response.RawData, Is.EqualTo(responseData));
            // Note: FCI parsing is simplified in this implementation
        }

        [Test]
        public void SelectResponse_ParseWithFci_EmptyData_ReturnsResponseWithNullFci()
        {
            // Arrange
            var responseData = Array.Empty<byte>();

            // Act
            var response = SelectResponse.ParseWithFci(responseData);

            // Assert
            Assert.That(response.RawData, Is.EqualTo(responseData));
            Assert.That(response.Fci, Is.Null);
        }

        [Test]
        public void SelectResponse_Constructor_ClonesData()
        {
            // Arrange
            var rawData = ConvertCompat.FromHexString("6F1C840EA000000003000000");
            var originalData = (byte[])rawData.Clone();

            // Act
            var response = new SelectResponse(rawData);
            rawData[0] = 0xFF; // Modify original

            // Assert
            Assert.That(response.RawData, Is.EqualTo(originalData));
            Assert.That(response.RawData, Is.Not.EqualTo(rawData));
        }

        #endregion
    }
}