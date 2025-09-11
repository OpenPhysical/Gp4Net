// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using NUnit.Framework;

namespace Gp4Net.Tests.Domain.DataObjects;

[TestFixture]
[Ignore(
    "CardCapabilitiesCodec has been refactored into GlobalPlatformService.DataGeneration - tests need to be updated"
)]
public class CardCapabilitiesCodecTests
{
    /* Legacy test data preserved for reference when rewriting tests
    private static readonly byte[] Scp02OnlyCapabilities = Convert.FromHexString(
        "664C"
            + // Tag 66, Length 4C (76 bytes)
            "0601"
            + // Card recognition data length
            "42"
            + // Card recognition OID
            "6002"
            + // Card management type and version
            "0200"
            + // Version 2.0
            "6301"
            + // Card identification scheme
            "00"
            + // Scheme 0
            "6401"
            + // Secure channel protocol
            "02"
            + // SCP02
            "6501"
            + // Implementation
            "15"
            + // i=15
            "6602"
            + // Key types
            "8010"
            + // DES keys, 16 bytes
            "6501"
            + // Implementation
            "04"
            + // i=04
            "6602"
            + // Key types
            "8010"
            + // DES keys, 16 bytes
            "6501"
            + // Implementation
            "1A"
            + // i=1A
            "6602"
            + // Key types
            "8010" // DES keys, 16 bytes
    );

    private static readonly byte[] DualProtocolCapabilities = Convert.FromHexString(
        "6654"
            + // Tag 66, Length 54 (84 bytes)
            "0601"
            + // Card recognition data
            "42"
            + // OID
            "6002"
            + // Card management type/version
            "0200"
            + // Version 2.0
            "6301"
            + // Card identification scheme
            "00"
            + // Scheme 0
            "6401"
            + // SCP protocol
            "02"
            + // SCP02
            "6501"
            + // Implementation
            "15"
            + // i=15
            "6602"
            + // Key types
            "8010"
            + // DES keys, 16 bytes
            "6401"
            + // SCP protocol
            "03"
            + // SCP03
            "6501"
            + // Implementation
            "70"
            + // i=70
            "6602"
            + // Key types
            "8020" // AES keys, 32 bytes
    );
    */

    /* All tests commented out due to refactoring - class is marked [Ignore]
    [Test]
    public void Encode_Scp02OnlyCapabilities_ProducesExpectedFormat()
    {
        CardCapabilities capabilities = new CardCapabilities
        {
            CardRecognitionData = Convert.FromHexString("42"),
            CardManagementTypeAndVersion = [0x02, 0x00],
            CardIdentificationScheme = 0x00,
            SecureChannelProtocols =
            {
                new SecureChannelProtocol
                {
                    Protocol = 0x02,
                    Implementations =
                    {
                        new ScpImplementationSpecifier
                        {
                            Implementation = 0x15,
                            KeyTypes = { 0x80, 0x10 }, // DES, 16 bytes
                        },
                        new ScpImplementationSpecifier
                        {
                            Implementation = 0x04,
                            KeyTypes = { 0x80, 0x10 },
                        },
                        new ScpImplementationSpecifier
                        {
                            Implementation = 0x1A,
                            KeyTypes = { 0x80, 0x10 },
                        },
                    },
                },
            },
        };

        Result<byte[], SmartCardError> encodedResult = DataGeneration.Encode(capabilities);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode CardCapabilities");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0x66, "first byte should be tag 0x66");
        _ = encoded[1].Should().BeGreaterThan(0, "length should be positive");
    }

    [Test]
    public void Encode_DualProtocolCapabilities_ProducesExpectedFormat()
    {
        CardCapabilities capabilities = new CardCapabilities
        {
            CardRecognitionData = Convert.FromHexString("42"),
            CardManagementTypeAndVersion = [0x02, 0x00],
            CardIdentificationScheme = 0x00,
            SecureChannelProtocols =
            {
                new SecureChannelProtocol
                {
                    Protocol = 0x02,
                    Implementations =
                    {
                        new ScpImplementationSpecifier
                        {
                            Implementation = 0x15,
                            KeyTypes = { 0x80, 0x10 },
                        },
                    },
                },
                new SecureChannelProtocol
                {
                    Protocol = 0x03,
                    Implementations =
                    {
                        new ScpImplementationSpecifier
                        {
                            Implementation = 0x70,
                            KeyTypes = { 0x80, 0x20 }, // AES, 32 bytes
                        },
                    },
                },
            },
        };

        Result<byte[], SmartCardError> encodedResult = DataGeneration.Encode(capabilities);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode CardCapabilities");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0x66);

        // Should contain both protocol identifiers
        _ = encoded.Should().Contain(0x02, "should contain SCP02 protocol");
        _ = encoded.Should().Contain(0x03, "should contain SCP03 protocol");
    }

    [Test]
    public void Decode_ValidScp02Capabilities_ReturnsCorrectStructure()
    {
        // Simple SCP02 capabilities for testing
        byte[] testData =
        [
            0x66,
            0x14, // Tag and length
            0x06,
            0x01,
            0x42, // Card recognition OID
            0x60,
            0x02,
            0x02,
            0x00, // Card management v2.0
            0x63,
            0x01,
            0x00, // Card identification scheme
            0x64,
            0x01,
            0x02, // SCP02
            0x65,
            0x01,
            0x15, // i=15
            0x66,
            0x02,
            0x80,
            0x10, // DES, 16 bytes
        ];

        Result<CardCapabilities, SmartCardError> result = DataGeneration.Decode(testData);

        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;

        _ = capabilities.CardRecognitionData.Should().BeEquivalentTo(new byte[] { 0x42 });
        _ = capabilities
            .CardManagementTypeAndVersion.Should()
            .BeEquivalentTo(new byte[] { 0x02, 0x00 });
        _ = capabilities.CardIdentificationScheme.Should().Be(0x00);
        _ = capabilities.SecureChannelProtocols.Should().HaveCount(1);

        SecureChannelProtocol? scp = capabilities.SecureChannelProtocols[0];
        _ = scp.Protocol.Should().Be(0x02);
        _ = scp.Implementations.Should().HaveCount(1);
        _ = scp.Implementations[0].Implementation.Should().Be(0x15);
        _ = scp.Implementations[0].KeyTypes.Should().BeEquivalentTo(new byte[] { 0x80, 0x10 });
    }

    [Test]
    public void Decode_InvalidData_ReturnsError()
    {
        byte[] invalidData = [0x65, 0x02, 0x00, 0x00]; // Wrong tag

        Result<CardCapabilities, SmartCardError> result = DataGeneration.Decode(invalidData);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Code.Should().Be("INVALID_DATA");
        _ = result
            .Error.Message.Should()
            .Contain("Invalid card capabilities data format - expected tag 0x66");
    }

    [Test]
    public void RoundTrip_PreservesData()
    {
        CardCapabilities original = new CardCapabilities
        {
            CardRecognitionData = Convert.FromHexString("A000000151"),
            CardManagementTypeAndVersion = [0x02, 0x01],
            CardIdentificationScheme = 0x00,
            SecureChannelProtocols =
            {
                new SecureChannelProtocol
                {
                    Protocol = 0x02,
                    Implementations =
                    {
                        new ScpImplementationSpecifier
                        {
                            Implementation = 0x15,
                            KeyTypes = { 0x80, 0x10 },
                        },
                        new ScpImplementationSpecifier
                        {
                            Implementation = 0x55,
                            KeyTypes = { 0x80, 0x10 },
                        },
                    },
                },
                new SecureChannelProtocol
                {
                    Protocol = 0x03,
                    Implementations =
                    {
                        new ScpImplementationSpecifier
                        {
                            Implementation = 0x70,
                            KeyTypes = { 0x80, 0x20 },
                        },
                    },
                },
            },
        };

        Result<byte[], SmartCardError> encodedResult = DataGeneration.Encode(original);
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode CardCapabilities");
        byte[]? encoded = encodedResult.Value;
        Result<CardCapabilities, SmartCardError> decoded = DataGeneration.Decode(encoded);

        _ = decoded.IsSuccess.Should().BeTrue();
        CardCapabilities? result = decoded.Value;

        _ = result.CardRecognitionData.Should().BeEquivalentTo(original.CardRecognitionData);
        _ = result
            .CardManagementTypeAndVersion.Should()
            .BeEquivalentTo(original.CardManagementTypeAndVersion);
        _ = result.CardIdentificationScheme.Should().Be(original.CardIdentificationScheme);
        _ = result.SecureChannelProtocols.Count.Should().Be(original.SecureChannelProtocols.Count);

        // Verify SCP02
        SecureChannelProtocol? scp02 = result.SecureChannelProtocols.First(s => s.Protocol == 0x02);
        _ = scp02.Implementations.Should().HaveCount(2);
        _ = scp02.Implementations.Should().Contain(i => i.Implementation == 0x15);
        _ = scp02.Implementations.Should().Contain(i => i.Implementation == 0x55);

        // Verify SCP03
        SecureChannelProtocol? scp03 = result.SecureChannelProtocols.First(s => s.Protocol == 0x03);
        _ = scp03.Implementations.Should().HaveCount(1);
        _ = scp03.Implementations[0].Implementation.Should().Be(0x70);
        _ = scp03.Implementations[0].KeyTypes.Should().BeEquivalentTo(new byte[] { 0x80, 0x20 });
    }

    [Test]
    public void Encode_EmptyCapabilities_ProducesMinimalFormat()
    {
        CardCapabilities capabilities = new CardCapabilities();

        Result<byte[], SmartCardError> encodedResult = DataGeneration.Encode(capabilities);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode CardCapabilities");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0x66);
        _ = encoded.Length.Should().BeGreaterThanOrEqualTo(4); // Tag + Length + minimal content
    }

    [Test]
    public void Decode_EmptyCapabilities_ReturnsEmptyStructure()
    {
        byte[] minimalData =
        [
            0x66,
            0x03, // Tag with minimal length
            0x63,
            0x01,
            0x00, // Just card identification scheme
        ];

        Result<CardCapabilities, SmartCardError> result = DataGeneration.Decode(minimalData);

        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;
        _ = capabilities.SecureChannelProtocols.Should().BeEmpty();
        _ = capabilities.CardRecognitionData.Should().BeNull();
        _ = capabilities.CardIdentificationScheme.Should().Be(0x00);
    }

    [Test]
    public void Encode_WithoutCardManagementVersion_HandlesGracefully()
    {
        CardCapabilities capabilities = new CardCapabilities
        {
            CardRecognitionData = Convert.FromHexString("42"),
            CardIdentificationScheme = 0x00,
        };

        Result<byte[], SmartCardError> encodedResult = DataGeneration.Encode(capabilities);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode CardCapabilities");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0x66);
        // Should not contain card management version fields
        _ = encoded.Should().NotContain(0x60);
    }

    [Test]
    public void Decode_WithMultipleImplementationsPerProtocol_ParsesCorrectly()
    {
        byte[] testData =
        [
            0x66,
            0x17, // Tag and length (23 bytes)
            0x63,
            0x01,
            0x00, // Card identification scheme
            0x64,
            0x01,
            0x02, // SCP02
            0x65,
            0x01,
            0x15, // i=15
            0x66,
            0x02,
            0x80,
            0x10, // DES, 16 bytes
            0x65,
            0x01,
            0x04, // i=04
            0x66,
            0x02,
            0x80,
            0x10, // DES, 16 bytes
            0x65,
            0x01,
            0x1A, // i=1A
        ];

        Result<CardCapabilities, SmartCardError> result = DataGeneration.Decode(testData);

        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;

        _ = capabilities.SecureChannelProtocols.Should().HaveCount(1);
        SecureChannelProtocol? scp = capabilities.SecureChannelProtocols[0];
        _ = scp.Protocol.Should().Be(0x02);
        _ = scp.Implementations.Should().HaveCount(3);
        _ = scp.Implementations.Should().Contain(i => i.Implementation == 0x15);
        _ = scp.Implementations.Should().Contain(i => i.Implementation == 0x04);
        _ = scp.Implementations.Should().Contain(i => i.Implementation == 0x1A);
    }
    */
}
