using System;
using Gp4Net.Utils;

namespace Gp4Net.Tests.Utils
{
    /// <summary>
    /// Tests for the ConvertCompat utility class.
    /// Ensures compatibility across different .NET versions for hex string operations.
    /// </summary>
    [TestFixture]
    public class ConvertCompatTests
    {
        #region FromHexString Tests

        [Test]
        public void FromHexString_ValidUppercaseHex_ReturnsCorrectBytes()
        {
            // Arrange
            var hex = "48656C6C6F";
            var expected = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };

            // Act
            var result = ConvertCompat.FromHexString(hex);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void FromHexString_ValidLowercaseHex_ReturnsCorrectBytes()
        {
            // Arrange
            var hex = "48656c6c6f";
            var expected = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };

            // Act
            var result = ConvertCompat.FromHexString(hex);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void FromHexString_MixedCaseHex_ReturnsCorrectBytes()
        {
            // Arrange
            var hex = "48656C6c6F";
            var expected = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };

            // Act
            var result = ConvertCompat.FromHexString(hex);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void FromHexString_EmptyString_ReturnsEmptyArray()
        {
            // Act
            var result = ConvertCompat.FromHexString("");

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.Length, Is.EqualTo(0));
        }

        [Test]
        public void FromHexString_AllZeros_ReturnsZeroBytes()
        {
            // Arrange
            var hex = "0000";
            var expected = new byte[] { 0x00, 0x00 };

            // Act
            var result = ConvertCompat.FromHexString(hex);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void FromHexString_AllFs_ReturnsMaxBytes()
        {
            // Arrange
            var hex = "FFFF";
            var expected = new byte[] { 0xFF, 0xFF };

            // Act
            var result = ConvertCompat.FromHexString(hex);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void FromHexString_NullInput_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => ConvertCompat.FromHexString(null));
        }

        [Test]
        public void FromHexString_OddLength_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() => ConvertCompat.FromHexString("ABC"));
        }

        [Test]
        public void FromHexString_InvalidCharacters_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() => ConvertCompat.FromHexString("ABCG"));
        }

        [Test]
        public void FromHexString_NonHexCharacters_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() => ConvertCompat.FromHexString("HELLO"));
        }

        #endregion

        #region ToHexString Tests

        [Test]
        public void ToHexString_ValidBytes_ReturnsUppercaseHex()
        {
            // Arrange
            var bytes = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
            var expected = "48656C6C6F";

            // Act
            var result = ConvertCompat.ToHexString(bytes);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void ToHexString_EmptyArray_ReturnsEmptyString()
        {
            // Act
            var result = ConvertCompat.ToHexString(new byte[0]);

            // Assert
            Assert.That(result, Is.EqualTo(""));
        }

        [Test]
        public void ToHexString_AllZeros_ReturnsZeroString()
        {
            // Arrange
            var bytes = new byte[] { 0x00, 0x00 };
            var expected = "0000";

            // Act
            var result = ConvertCompat.ToHexString(bytes);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void ToHexString_AllFs_ReturnsFFString()
        {
            // Arrange
            var bytes = new byte[] { 0xFF, 0xFF };
            var expected = "FFFF";

            // Act
            var result = ConvertCompat.ToHexString(bytes);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void ToHexString_NullInput_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => ConvertCompat.ToHexString(null));
        }

        #endregion

        #region ToHexStringLower Tests

        [Test]
        public void ToHexStringLower_ValidBytes_ReturnsLowercaseHex()
        {
            // Arrange
            var bytes = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
            var expected = "48656c6c6f";

            // Act
            var result = ConvertCompat.ToHexStringLower(bytes);

            // Assert
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void ToHexStringLower_EmptyArray_ReturnsEmptyString()
        {
            // Act
            var result = ConvertCompat.ToHexStringLower(new byte[0]);

            // Assert
            Assert.That(result, Is.EqualTo(""));
        }

        [Test]
        public void ToHexStringLower_NullInput_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => ConvertCompat.ToHexStringLower(null));
        }

        #endregion

        #region TryFromHexString Tests

        [Test]
        public void TryFromHexString_ValidHex_ReturnsTrueAndCorrectBytes()
        {
            // Arrange
            var hex = "48656C6C6F";
            var expected = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };

            // Act
            var success = ConvertCompat.TryFromHexString(hex, out var result);

            // Assert
            Assert.That(success, Is.True);
            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void TryFromHexString_EmptyString_ReturnsFalse()
        {
            // Act
            var success = ConvertCompat.TryFromHexString("", out var result);

            // Assert
            Assert.That(success, Is.False);
            Assert.That(result, Is.Null);
        }

        [Test]
        public void TryFromHexString_NullString_ReturnsFalse()
        {
            // Act
            var success = ConvertCompat.TryFromHexString(null, out var result);

            // Assert
            Assert.That(success, Is.False);
            Assert.That(result, Is.Null);
        }

        [Test]
        public void TryFromHexString_OddLength_ReturnsFalse()
        {
            // Act
            var success = ConvertCompat.TryFromHexString("ABC", out var result);

            // Assert
            Assert.That(success, Is.False);
            Assert.That(result, Is.Null);
        }

        [Test]
        public void TryFromHexString_InvalidCharacters_ReturnsFalse()
        {
            // Act
            var success = ConvertCompat.TryFromHexString("ABCG", out var result);

            // Assert
            Assert.That(success, Is.False);
            Assert.That(result, Is.Null);
        }

        #endregion

        #region Round-trip Tests

        [Test]
        public void RoundTrip_FromHexToHex_PreservesOriginal()
        {
            // Arrange
            var original = "48656C6C6F";

            // Act
            var bytes = ConvertCompat.FromHexString(original);
            var result = ConvertCompat.ToHexString(bytes);

            // Assert
            Assert.That(result, Is.EqualTo(original));
        }

        [Test]
        public void RoundTrip_FromBytesToBytes_PreservesOriginal()
        {
            // Arrange
            var original = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };

            // Act
            var hex = ConvertCompat.ToHexString(original);
            var result = ConvertCompat.FromHexString(hex);

            // Assert
            Assert.That(result, Is.EqualTo(original));
        }

        [Test]
        public void RoundTrip_LowercaseToUppercase_WorksCorrectly()
        {
            // Arrange
            var lowercase = "48656c6c6f";
            var expectedUppercase = "48656C6C6F";

            // Act
            var bytes = ConvertCompat.FromHexString(lowercase);
            var result = ConvertCompat.ToHexString(bytes);

            // Assert
            Assert.That(result, Is.EqualTo(expectedUppercase));
        }

        #endregion
    }
}
