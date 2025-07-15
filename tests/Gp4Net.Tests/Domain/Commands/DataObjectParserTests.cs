using System;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
    [TestFixture]
    public class DataObjectParserTests
    {
        [Test]
        public void ParseRawDataObject_WithColonSeparator_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "9F70:040102";

            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var (tag, data) = result.Value;
            Assert.That(tag, Is.EqualTo(0x9F70));
            Assert.That(data, Is.EqualTo(new byte[] { 0x04, 0x01, 0x02 }));
        }

        [Test]
        public void ParseRawDataObject_WithEqualsSeparator_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "9F70=040102";

            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var (tag, data) = result.Value;
            Assert.That(tag, Is.EqualTo(0x9F70));
            Assert.That(data, Is.EqualTo(new byte[] { 0x04, 0x01, 0x02 }));
        }

        [Test]
        public void ParseRawDataObject_WithLongData_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "DF21:112233445566778899AABBCCDDEEFF00";

            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var (tag, data) = result.Value;
            Assert.That(tag, Is.EqualTo(0xDF21));
            Assert.That(data.Length, Is.EqualTo(16));
            Assert.That(data[0], Is.EqualTo(0x11));
            Assert.That(data[15], Is.EqualTo(0x00));
        }

        [Test]
        public void ParseRawDataObject_WithSingleByteTag_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "C0:01020304";

            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var (tag, data) = result.Value;
            Assert.That(tag, Is.EqualTo(0x00C0));
            Assert.That(data, Is.EqualTo(new byte[] { 0x01, 0x02, 0x03, 0x04 }));
        }

        [Test]
        public void ParseRawDataObject_WithEmptyData_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "9F70:";

            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var (tag, data) = result.Value;
            Assert.That(tag, Is.EqualTo(0x9F70));
            Assert.That(data, Is.Empty);
        }

        [Test]
        [TestCase("")]
        [TestCase(" ")]
        public void ParseRawDataObject_WithEmptyInput_ReturnsFailure(string dataObject)
        {
            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Is.EqualTo("Data object cannot be null or empty"));
        }

        [Test]
        public void ParseRawDataObject_WithNullInput_ReturnsFailure()
        {
            // Act
            var result = DataObjectParser.ParseRawDataObject(null!);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Is.EqualTo("Data object cannot be null or empty"));
        }

        [Test]
        [TestCase("9F70")]
        [TestCase("9F70-040102")]
        [TestCase("9F70_040102")]
        [TestCase("InvalidFormat")]
        public void ParseRawDataObject_WithInvalidFormat_ReturnsFailure(string dataObject)
        {
            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Is.EqualTo("Invalid data object format"));
        }

        [Test]
        [TestCase("GHIJ:040102")]
        [TestCase("9Z70:040102")]
        [TestCase("9F7G:040102")]
        public void ParseRawDataObject_WithInvalidHexTag_ReturnsFailure(string dataObject)
        {
            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Is.EqualTo("Invalid data object format"));
        }

        [Test]
        [TestCase("9F70:04010")]
        [TestCase("9F70:0401G2")]
        [TestCase("9F70:ZZ")]
        public void ParseRawDataObject_WithOddHexData_ReturnsFailure(string dataObject)
        {
            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("even number of hex characters") 
                .Or.Contain("hex characters"));
        }

        [Test]
        [TestCase("9F70:040102", (ushort)0x9F70)]
        [TestCase("DF21:1122", (ushort)0xDF21)]
        [TestCase("C0:33", (ushort)0x00C0)]
        [TestCase("5F2D:0011", (ushort)0x5F2D)]
        public void ValidateDataObject_WithValidTag_ReturnsTrue(string dataObject, ushort expectedTag)
        {
            // Arrange
            var result = DataObjectParser.ParseRawDataObject(dataObject);
            Assert.That(result.IsSuccess, Is.True);
            var (tag, data) = result.Value;

            // Act
            var isValid = DataObjectParser.ValidateDataObject(tag, data);

            // Assert
            Assert.That(isValid, Is.True);
            Assert.That(tag, Is.EqualTo(expectedTag));
        }

        [Test]
        public void ValidateDataObject_WithZeroTag_ReturnsFalse()
        {
            // Arrange
            ushort tag = 0x0000;
            var data = new byte[] { 0x01, 0x02 };

            // Act
            var isValid = DataObjectParser.ValidateDataObject(tag, data);

            // Assert
            Assert.That(isValid, Is.False);
        }

        [Test]
        public void ValidateDataObject_WithNullData_ReturnsFalse()
        {
            // Arrange
            ushort tag = 0x9F70;
            byte[] data = null;

            // Act
            var isValid = DataObjectParser.ValidateDataObject(tag, data);

            // Assert
            Assert.That(isValid, Is.False);
        }

        [Test]
        public void ValidateDataObject_WithEmptyData_ReturnsTrue()
        {
            // Arrange
            ushort tag = 0x9F70;
            var data = Array.Empty<byte>();

            // Act
            var isValid = DataObjectParser.ValidateDataObject(tag, data);

            // Assert
            Assert.That(isValid, Is.True); // Empty data is allowed for some tags
        }

        [Test]
        [TestCase("9f70:040102")]
        [TestCase("9F70:040102")]
        [TestCase("df21:AABBCC")]
        [TestCase("DF21:aabbcc")]
        public void ParseRawDataObject_IsCaseInsensitive(string dataObject)
        {
            // Act
            var result = DataObjectParser.ParseRawDataObject(dataObject);
            
            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var (tag, data) = result.Value;
            Assert.That(tag, Is.GreaterThan(0));
            Assert.That(data, Is.Not.Null);
        }
    }
}