using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core.Tlv;
using NUnit.Framework;

namespace Gp4Net.Tests.Compliance;

/// <summary>
/// Tests for GlobalPlatform 2.3.1 specification compliance.
/// Validates specific GP requirements that deviate from standard ISO/IEC specifications.
/// </summary>
[TestFixture]
[Category("Unit")]
[Category("GpCompliance")]
public class GlobalPlatformSpecificationTests
{
    /// <summary>
    /// GP Card Specification v2.3.1: Install Token, Make Selectable Token, Extradition Token, Registry Update Token
    /// "The length field for [tokens] is as defined for ASN.1 BER-TLV (see [ISO 8825-1]) 
    /// except that the length 128 may also be coded on one byte as '80'."
    /// </summary>
    [Test]
    public void TlvParser_Should_Handle_GP_Length_128_Extension()
    {
        // Arrange - GP-specific: 0x80 alone means length 128
        byte[] data = new byte[131]; // Tag(1) + Length(1) + Value(128) + extra byte
        data[0] = 0x84;  // Arbitrary tag
        data[1] = 0x80;  // GP-specific: length 128 (not indefinite length!)

        // Fill value with test pattern
        for (int i = 0; i < 128; i++)
        {
            data[2 + i] = (byte)(i & 0xFF);
        }
        data[130] = 0xFF; // Extra byte to ensure we don't over-read

        // Act
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeTrue("GP specification requires 0x80 to be interpreted as length 128");
        _ = tlv.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x84 });
        _ = tlv.Value.Length.Should().Be(128, "GP Card Specification v2.3.1: 0x80 = length 128");
        _ = tlv.Value.Value.Length.Should().Be(128);

        // Verify the test pattern was read correctly
        for (int i = 0; i < 128; i++)
        {
            _ = tlv.Value.Value[i].Should().Be((byte)(i & 0xFF));
        }
    }

    /// <summary>
    /// Validates that standard ASN.1 BER-TLV length encoding still works correctly.
    /// The GP extension should not break normal ASN.1 compliance.
    /// </summary>
    [Test]
    public void TlvParser_Should_Still_Handle_Standard_ASN1_Length_Encoding()
    {
        // Arrange - Standard ASN.1 BER-TLV long form for length 128: 0x81 0x80
        byte[] data = new byte[131]; // Tag(1) + Length(2) + Value(128)
        data[0] = 0x84;  // Arbitrary tag
        data[1] = 0x81;  // Long form, 1 byte follows
        data[2] = 0x80;  // Length = 128

        // Fill value with different test pattern
        for (int i = 0; i < 128; i++)
        {
            data[3 + i] = (byte)((i + 1) & 0xFF);
        }

        // Act
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeTrue("Standard ASN.1 BER-TLV should still work");
        _ = tlv.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x84 });
        _ = tlv.Value.Length.Should().Be(128, "Standard ASN.1: 0x81 0x80 = length 128");
        _ = tlv.Value.Value.Length.Should().Be(128);

        // Verify the test pattern
        for (int i = 0; i < 128; i++)
        {
            _ = tlv.Value.Value[i].Should().Be((byte)((i + 1) & 0xFF));
        }
    }

    /// <summary>
    /// Tests that smaller lengths still work with short form encoding.
    /// </summary>
    [Test]
    public void TlvParser_Should_Handle_Short_Form_Lengths_Below_128()
    {
        // Arrange - Short form lengths (0x00 to 0x7F)
        byte[] testCases = [0x00, 0x01, 0x7F];

        foreach (byte expectedLength in testCases)
        {
            byte[] data = new byte[expectedLength + 2]; // Tag + Length + Value
            data[0] = 0x84; // Arbitrary tag
            data[1] = expectedLength; // Short form length

            for (int i = 0; i < expectedLength; i++)
            {
                data[2 + i] = (byte)(i & 0xFF);
            }

            // Act
            Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

            // Assert
            _ = tlv.HasValue.Should().BeTrue($"Short form length {expectedLength} should work");
            _ = tlv.Value.Length.Should().Be(expectedLength);
            _ = tlv.Value.Value.Length.Should().Be(expectedLength);
        }
    }

    /// <summary>
    /// Validates that the GP extension doesn't interfere with other long form encodings.
    /// </summary>
    [Test]
    public void TlvParser_Should_Handle_Other_Long_Form_Lengths()
    {
        // Arrange - Test various long form lengths (not 128)
        var testCases = new[]
        {
            new { bytes = new byte[] { 0x81, 0xFF }, expected = 255 },     // 1-byte long form  
            new { bytes = new byte[] { 0x82, 0x01, 0x00 }, expected = 256 } // 2-byte long form
        };

        foreach (var testCase in testCases)
        {
            byte[] data = new byte[testCase.bytes.Length + 1 + testCase.expected];
            data[0] = 0x84; // Arbitrary tag
            Array.Copy(testCase.bytes, 0, data, 1, testCase.bytes.Length);

            // Fill value
            for (int i = 0; i < testCase.expected; i++)
            {
                data[1 + testCase.bytes.Length + i] = (byte)(i & 0xFF);
            }

            // Act
            Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

            // Assert
            _ = tlv.HasValue.Should().BeTrue($"Long form length {testCase.expected} should work");
            _ = tlv.Value.Length.Should().Be(testCase.expected);
            _ = tlv.Value.Value.Length.Should().Be(testCase.expected);
        }
    }

    /// <summary>
    /// Test edge case: ensure that 0x80 in the middle of data doesn't get misinterpreted.
    /// Only the length field should be interpreted as GP-specific.
    /// </summary>
    [Test]
    public void TlvParser_Should_Only_Apply_GP_Extension_To_Length_Field()
    {
        // Arrange - TLV with 0x80 in the value, not the length
        byte[] data = [0x84, 0x03, 0x80, 0x01, 0x02]; // Tag, Length=3, Value=[0x80, 0x01, 0x02]

        // Act
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeTrue();
        _ = tlv.Value.Length.Should().Be(3, "Length field is 0x03, not affected by 0x80 in value");
        _ = tlv.Value.Value.Should().BeEquivalentTo(new byte[] { 0x80, 0x01, 0x02 });
    }

    /// <summary>
    /// Validates the specific GP tokens that use this extension.
    /// This test documents which GP structures benefit from the 0x80 = 128 extension.
    /// </summary>
    [Test]
    public void GP_Length_128_Extension_Should_Support_All_Specified_Tokens()
    {
        // This test documents the GP specification sections that require this extension:
        // 1. Install Token - GP Card Specification v2.3.1
        // 2. Make Selectable Token - GP Card Specification v2.3.1  
        // 3. Extradition Token - GP Card Specification v2.3.1
        // 4. Registry Update Token - GP Card Specification v2.3.1

        // All these tokens can use 0x80 to encode length 128 instead of 0x81 0x80

        // Simulate a token structure with GP-specific length encoding
        byte[] tokenData = new byte[130]; // Token tag + GP length + 128 bytes of token data
        tokenData[0] = 0xE3; // Example: GP Registry Data tag  
        tokenData[1] = 0x80; // GP-specific: length 128

        // Fill with token data
        for (int i = 0; i < 128; i++)
        {
            tokenData[2 + i] = (byte)(i & 0xFF);
        }

        // Act
        Maybe<TlvObject> parsedToken = TlvParser.ParseSingle(tokenData);

        // Assert
        _ = parsedToken.HasValue.Should().BeTrue("GP tokens should parse with 0x80 length encoding");
        _ = parsedToken.Value.Length.Should().Be(128, "GP specification: 0x80 = 128 bytes for tokens");

        // This validates that GP cards can use the more compact encoding
        // 0x80 (1 byte) instead of 0x81 0x80 (2 bytes) for 128-byte structures
    }
}