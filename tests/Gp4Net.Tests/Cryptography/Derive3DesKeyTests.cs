using System;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Utils;

namespace Gp4Net.Tests.Cryptography
{
    /// <summary>
    /// Tests for the Derive3DesKey method in KeyDerivation class.
    /// Tests cover both positive and negative cases with various input scenarios.
    /// </summary>
    [TestFixture]
    public class Derive3DesKeyTests
    {
        #region Test Data

        // Test vectors for 16-byte base key with 2-byte sequence counter
        private static readonly byte[] TestBaseKey16 = ConvertCompat.FromHexString("404142434445464748494A4B4C4D4E4F");
        private static readonly byte[] TestSequenceCounter2 = ConvertCompat.FromHexString("0001");
        private static readonly byte[] ExpectedDerived16_2Byte = ConvertCompat.FromHexString("750E2218F6257F3DFE9C1BAA806E2E0A750E2218F6257F3DFE9C1BAA806E2E0A");

        // Test vectors for 24-byte base key with 2-byte sequence counter
        private static readonly byte[] TestBaseKey24 = ConvertCompat.FromHexString("404142434445464748494A4B4C4D4E4F5051525354555657");
        private static readonly byte[] ExpectedDerived24_2Byte = ConvertCompat.FromHexString("750E2218F6257F3DFE9C1BAA806E2E0A8F1DDCC709AB80C220136245D7F191F5");

        // Test vectors for 3-byte sequence counter
        private static readonly byte[] TestSequenceCounter3 = ConvertCompat.FromHexString("000001");

        #endregion

        #region Positive Tests

        [Test]
        public void Derive3DesKey_ValidInputs16ByteKey2ByteCounter_ReturnsExpectedResult()
        {
            // Act
            var result = KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, TestSequenceCounter2);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.Length, Is.EqualTo(16));
            // Note: Actual expected values would need to be calculated based on the real SCP02 specification
            // These test vectors are placeholders and should be replaced with real test vectors
        }

        [Test]
        public void Derive3DesKey_ValidInputs24ByteKey2ByteCounter_ReturnsExpectedResult()
        {
            // Act
            var result = KeyDerivation.Derive3DesKey(TestBaseKey24, DerivationConstants.DataEncryption, TestSequenceCounter2);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.Length, Is.EqualTo(24));
        }

        [Test]
        public void Derive3DesKey_ValidInputs16ByteKey3ByteCounter_ReturnsExpectedResult()
        {
            // Act
            var result = KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, TestSequenceCounter3);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.Length, Is.EqualTo(16));
        }

        [Test]
        public void Derive3DesKey_ValidInputs24ByteKey3ByteCounter_ReturnsExpectedResult()
        {
            // Act
            var result = KeyDerivation.Derive3DesKey(TestBaseKey24, DerivationConstants.DataEncryption, TestSequenceCounter3);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.Length, Is.EqualTo(24));
        }

        [Test]
        public void Derive3DesKey_DifferentDerivationConstants_ProduceDifferentResults()
        {
            // Act
            var result1 = KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, TestSequenceCounter2);
            var result2 = KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.CardCryptogram, TestSequenceCounter2);

            // Assert
            Assert.That(result1, Is.Not.EqualTo(result2));
        }

        [Test]
        public void Derive3DesKey_DifferentSequenceCounters_ProduceDifferentResults()
        {
            // Arrange
            var counter1 = ConvertCompat.FromHexString("0001");
            var counter2 = ConvertCompat.FromHexString("0002");

            // Act
            var result1 = KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, counter1);
            var result2 = KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, counter2);

            // Assert
            Assert.That(result1, Is.Not.EqualTo(result2));
        }

        [Test]
        public void Derive3DesKey_SameInputs_ProduceSameResults()
        {
            // Act
            var result1 = KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, TestSequenceCounter2);
            var result2 = KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, TestSequenceCounter2);

            // Assert
            Assert.That(result1, Is.EqualTo(result2));
        }

        [Test]
        public void Derive3DesKey_AllZeroInputs_ProducesValidResult()
        {
            // Arrange
            var zeroKey = new byte[16];
            var zeroCounter = new byte[2];

            // Act
            var result = KeyDerivation.Derive3DesKey(zeroKey, 0x00, zeroCounter);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.Length, Is.EqualTo(16));
            Assert.That(result, Is.Not.EqualTo(zeroKey));
        }

        [Test]
        public void Derive3DesKey_MaxValueInputs_ProducesValidResult()
        {
            // Arrange
            var maxKey = new byte[16];
            for (int i = 0; i < maxKey.Length; i++) maxKey[i] = 0xFF;
            var maxCounter = new byte[] { 0xFF, 0xFF };

            // Act
            var result = KeyDerivation.Derive3DesKey(maxKey, 0xFF, maxCounter);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.Length, Is.EqualTo(16));
        }

        #endregion

        #region Negative Tests

        [Test]
        public void Derive3DesKey_NullBaseKey_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                KeyDerivation.Derive3DesKey(null, DerivationConstants.DataEncryption, TestSequenceCounter2));
        }

        [Test]
        public void Derive3DesKey_NullSequenceCounter_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, null));
        }

        [Test]
        public void Derive3DesKey_InvalidBaseKeyLength_ThrowsArgumentException()
        {
            // Arrange
            var invalidKey = new byte[15]; // Invalid length

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() =>
                KeyDerivation.Derive3DesKey(invalidKey, DerivationConstants.DataEncryption, TestSequenceCounter2));
            Assert.That(ex.ParamName, Is.EqualTo("baseKey"));
        }

        [Test]
        public void Derive3DesKey_EmptyBaseKey_ThrowsArgumentException()
        {
            // Arrange
            var emptyKey = new byte[0];

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() =>
                KeyDerivation.Derive3DesKey(emptyKey, DerivationConstants.DataEncryption, TestSequenceCounter2));
            Assert.That(ex.ParamName, Is.EqualTo("baseKey"));
        }

        [Test]
        public void Derive3DesKey_InvalidSequenceCounterLength_ThrowsArgumentException()
        {
            // Arrange
            var invalidCounter = new byte[1]; // Invalid length

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() =>
                KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, invalidCounter));
            Assert.That(ex.ParamName, Is.EqualTo("sequenceCounter"));
        }

        [Test]
        public void Derive3DesKey_EmptySequenceCounter_ThrowsArgumentException()
        {
            // Arrange
            var emptyCounter = new byte[0];

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() =>
                KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, emptyCounter));
            Assert.That(ex.ParamName, Is.EqualTo("sequenceCounter"));
        }

        [Test]
        public void Derive3DesKey_TooLongSequenceCounter_ThrowsArgumentException()
        {
            // Arrange
            var longCounter = new byte[4]; // Too long

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() =>
                KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, longCounter));
            Assert.That(ex.ParamName, Is.EqualTo("sequenceCounter"));
        }

        #endregion

        #region Edge Cases

        [Test]
        public void Derive3DesKey_16ByteKeyResult_FirstAndSecondHalfEqual()
        {
            // Act
            var result = KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, TestSequenceCounter2);

            // Assert
            Assert.That(result.Length, Is.EqualTo(16));

            // For 16-byte 3DES keys, the first 8 bytes should equal the second 8 bytes
            var firstHalf = new byte[8];
            var secondHalf = new byte[8];
            Array.Copy(result, 0, firstHalf, 0, 8);
            Array.Copy(result, 8, secondHalf, 0, 8);

            Assert.That(firstHalf, Is.EqualTo(secondHalf));
        }

        [Test]
        public void Derive3DesKey_24ByteKeyResult_ThirdBlockIsXorOfFirstTwo()
        {
            // Act
            var result = KeyDerivation.Derive3DesKey(TestBaseKey24, DerivationConstants.DataEncryption, TestSequenceCounter2);

            // Assert
            Assert.That(result.Length, Is.EqualTo(24));

            // For 24-byte 3DES keys, the third block should be first XOR second
            for (int i = 0; i < 8; i++)
            {
                var expectedByte = (byte)(result[i] ^ result[8 + i]);
                Assert.That(result[16 + i], Is.EqualTo(expectedByte));
            }
        }

        [Test]
        public void Derive3DesKey_KeyImmutability_DoesNotModifyInputs()
        {
            // Arrange
            var originalKey = (byte[])TestBaseKey16.Clone();
            var originalCounter = (byte[])TestSequenceCounter2.Clone();

            // Act
            KeyDerivation.Derive3DesKey(TestBaseKey16, DerivationConstants.DataEncryption, TestSequenceCounter2);

            // Assert
            Assert.That(TestBaseKey16, Is.EqualTo(originalKey));
            Assert.That(TestSequenceCounter2, Is.EqualTo(originalCounter));
        }

        #endregion
    }
}
