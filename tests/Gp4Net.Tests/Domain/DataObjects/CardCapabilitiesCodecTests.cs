// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using FluentAssertions;
using Gp4Net.Domain.DataObjects;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.DataObjects
{
    [TestFixture]
    public class CardCapabilitiesCodecTests
    {
        private static readonly byte[] Scp02OnlyCapabilities = Convert.FromHexString(
            "664C" + // Tag 66, Length 4C (76 bytes)
            "0601" + // Card recognition data length
            "42" +   // Card recognition OID
            "6002" + // Card management type and version
            "0200" + // Version 2.0
            "6301" + // Card identification scheme
            "00" +   // Scheme 0
            "6401" + // Secure channel protocol
            "02" +   // SCP02
            "6501" + // Implementation
            "15" +   // i=15
            "6602" + // Key types
            "8010" + // DES keys, 16 bytes
            "6501" + // Implementation
            "04" +   // i=04
            "6602" + // Key types
            "8010" + // DES keys, 16 bytes
            "6501" + // Implementation
            "1A" +   // i=1A
            "6602" + // Key types
            "8010"   // DES keys, 16 bytes
        );

        private static readonly byte[] DualProtocolCapabilities = Convert.FromHexString(
            "6654" + // Tag 66, Length 54 (84 bytes)
            "0601" + // Card recognition data
            "42" +   // OID
            "6002" + // Card management type/version
            "0200" + // Version 2.0
            "6301" + // Card identification scheme
            "00" +   // Scheme 0
            "6401" + // SCP protocol
            "02" +   // SCP02
            "6501" + // Implementation
            "15" +   // i=15
            "6602" + // Key types
            "8010" + // DES keys, 16 bytes
            "6401" + // SCP protocol
            "03" +   // SCP03
            "6501" + // Implementation
            "70" +   // i=70
            "6602" + // Key types
            "8020"   // AES keys, 32 bytes
        );

        [Test]
        public void Encode_Scp02OnlyCapabilities_ProducesExpectedFormat()
        {
            var capabilities = new CardCapabilities
            {
                CardRecognitionData = Convert.FromHexString("42"),
                CardManagementTypeAndVersion = new byte[] { 0x02, 0x00 },
                CardIdentificationScheme = 0x00,
                SecureChannelProtocols =
                {
                    new SecureChannelProtocol
                    {
                        Protocol = 0x02,
                        Implementations =
                        {
                            new ScpImplementation
                            {
                                Implementation = 0x15,
                                KeyTypes = { 0x80, 0x10 } // DES, 16 bytes
                            },
                            new ScpImplementation
                            {
                                Implementation = 0x04,
                                KeyTypes = { 0x80, 0x10 }
                            },
                            new ScpImplementation
                            {
                                Implementation = 0x1A,
                                KeyTypes = { 0x80, 0x10 }
                            }
                        }
                    }
                }
            };

            var encoded = CardCapabilitiesCodec.Encode(capabilities);

            encoded.Should().NotBeEmpty();
            encoded[0].Should().Be(0x66, "first byte should be tag 0x66");
            encoded[1].Should().BeGreaterThan(0, "length should be positive");
        }

        [Test]
        public void Encode_DualProtocolCapabilities_ProducesExpectedFormat()
        {
            var capabilities = new CardCapabilities
            {
                CardRecognitionData = Convert.FromHexString("42"),
                CardManagementTypeAndVersion = new byte[] { 0x02, 0x00 },
                CardIdentificationScheme = 0x00,
                SecureChannelProtocols =
                {
                    new SecureChannelProtocol
                    {
                        Protocol = 0x02,
                        Implementations =
                        {
                            new ScpImplementation
                            {
                                Implementation = 0x15,
                                KeyTypes = { 0x80, 0x10 }
                            }
                        }
                    },
                    new SecureChannelProtocol
                    {
                        Protocol = 0x03,
                        Implementations =
                        {
                            new ScpImplementation
                            {
                                Implementation = 0x70,
                                KeyTypes = { 0x80, 0x20 } // AES, 32 bytes
                            }
                        }
                    }
                }
            };

            var encoded = CardCapabilitiesCodec.Encode(capabilities);

            encoded.Should().NotBeEmpty();
            encoded[0].Should().Be(0x66);
            
            // Should contain both protocol identifiers
            encoded.Should().Contain(0x02, "should contain SCP02 protocol");
            encoded.Should().Contain(0x03, "should contain SCP03 protocol");
        }

        [Test]
        public void Decode_ValidScp02Capabilities_ReturnsCorrectStructure()
        {
            // Simple SCP02 capabilities for testing
            var testData = new byte[]
            {
                0x66, 0x14, // Tag and length
                0x06, 0x01, 0x42, // Card recognition OID
                0x60, 0x02, 0x02, 0x00, // Card management v2.0
                0x63, 0x01, 0x00, // Card identification scheme
                0x64, 0x01, 0x02, // SCP02
                0x65, 0x01, 0x15, // i=15
                0x66, 0x02, 0x80, 0x10 // DES, 16 bytes
            };

            var result = CardCapabilitiesCodec.Decode(testData);

            result.IsSuccess.Should().BeTrue();
            var capabilities = result.Value;
            
            capabilities.CardRecognitionData.Should().Equal(new byte[] { 0x42 });
            capabilities.CardManagementTypeAndVersion.Should().Equal(new byte[] { 0x02, 0x00 });
            capabilities.CardIdentificationScheme.Should().Be(0x00);
            capabilities.SecureChannelProtocols.Should().HaveCount(1);
            
            var scp = capabilities.SecureChannelProtocols[0];
            scp.Protocol.Should().Be(0x02);
            scp.Implementations.Should().HaveCount(1);
            scp.Implementations[0].Implementation.Should().Be(0x15);
            scp.Implementations[0].KeyTypes.Should().Equal(new byte[] { 0x80, 0x10 });
        }

        [Test]
        public void Decode_InvalidData_ReturnsError()
        {
            var invalidData = new byte[] { 0x65, 0x02, 0x00, 0x00 }; // Wrong tag

            var result = CardCapabilitiesCodec.Decode(invalidData);

            result.IsFailure.Should().BeTrue();
            result.Error.Code.Should().Be("INVALID_DATA");
        }

        [Test]
        public void RoundTrip_PreservesData()
        {
            var original = new CardCapabilities
            {
                CardRecognitionData = Convert.FromHexString("A000000151"),
                CardManagementTypeAndVersion = new byte[] { 0x02, 0x01 },
                CardIdentificationScheme = 0x00,
                SecureChannelProtocols =
                {
                    new SecureChannelProtocol
                    {
                        Protocol = 0x02,
                        Implementations =
                        {
                            new ScpImplementation
                            {
                                Implementation = 0x15,
                                KeyTypes = { 0x80, 0x10 }
                            },
                            new ScpImplementation
                            {
                                Implementation = 0x55,
                                KeyTypes = { 0x80, 0x10 }
                            }
                        }
                    },
                    new SecureChannelProtocol
                    {
                        Protocol = 0x03,
                        Implementations =
                        {
                            new ScpImplementation
                            {
                                Implementation = 0x70,
                                KeyTypes = { 0x80, 0x20 }
                            }
                        }
                    }
                }
            };

            var encoded = CardCapabilitiesCodec.Encode(original);
            var decoded = CardCapabilitiesCodec.Decode(encoded);

            decoded.IsSuccess.Should().BeTrue();
            var result = decoded.Value;
            
            result.CardRecognitionData.Should().Equal(original.CardRecognitionData);
            result.CardManagementTypeAndVersion.Should().Equal(original.CardManagementTypeAndVersion);
            result.CardIdentificationScheme.Should().Be(original.CardIdentificationScheme);
            result.SecureChannelProtocols.Should().HaveCount(original.SecureChannelProtocols.Count);
            
            // Verify SCP02
            var scp02 = result.SecureChannelProtocols.First(s => s.Protocol == 0x02);
            scp02.Implementations.Should().HaveCount(2);
            scp02.Implementations.Should().Contain(i => i.Implementation == 0x15);
            scp02.Implementations.Should().Contain(i => i.Implementation == 0x55);
            
            // Verify SCP03
            var scp03 = result.SecureChannelProtocols.First(s => s.Protocol == 0x03);
            scp03.Implementations.Should().HaveCount(1);
            scp03.Implementations[0].Implementation.Should().Be(0x70);
            scp03.Implementations[0].KeyTypes.Should().Equal(new byte[] { 0x80, 0x20 });
        }

        [Test]
        public void Encode_EmptyCapabilities_ProducesMinimalFormat()
        {
            var capabilities = new CardCapabilities();

            var encoded = CardCapabilitiesCodec.Encode(capabilities);

            encoded.Should().NotBeEmpty();
            encoded[0].Should().Be(0x66);
            encoded.Length.Should().BeGreaterOrEqualTo(4); // Tag + Length + minimal content
        }

        [Test]
        public void Decode_EmptyCapabilities_ReturnsEmptyStructure()
        {
            var minimalData = new byte[] 
            { 
                0x66, 0x03, // Tag with minimal length
                0x63, 0x01, 0x00 // Just card identification scheme
            };

            var result = CardCapabilitiesCodec.Decode(minimalData);

            result.IsSuccess.Should().BeTrue();
            var capabilities = result.Value;
            capabilities.SecureChannelProtocols.Should().BeEmpty();
            capabilities.CardRecognitionData.Should().BeNull();
            capabilities.CardIdentificationScheme.Should().Be(0x00);
        }

        [Test]
        public void Encode_WithoutCardManagementVersion_HandlesGracefully()
        {
            var capabilities = new CardCapabilities
            {
                CardRecognitionData = Convert.FromHexString("42"),
                CardIdentificationScheme = 0x00
            };

            var encoded = CardCapabilitiesCodec.Encode(capabilities);

            encoded.Should().NotBeEmpty();
            encoded[0].Should().Be(0x66);
            // Should not contain card management version fields
            encoded.Should().NotContain(0x60);
        }

        [Test]
        public void Decode_WithMultipleImplementationsPerProtocol_ParsesCorrectly()
        {
            var testData = new byte[]
            {
                0x66, 0x16, // Tag and length
                0x63, 0x01, 0x00, // Card identification scheme
                0x64, 0x01, 0x02, // SCP02
                0x65, 0x01, 0x15, // i=15
                0x66, 0x02, 0x80, 0x10, // DES, 16 bytes
                0x65, 0x01, 0x04, // i=04
                0x66, 0x02, 0x80, 0x10, // DES, 16 bytes
                0x65, 0x01, 0x1A // i=1A
            };

            var result = CardCapabilitiesCodec.Decode(testData);

            result.IsSuccess.Should().BeTrue();
            var capabilities = result.Value;
            
            capabilities.SecureChannelProtocols.Should().HaveCount(1);
            var scp = capabilities.SecureChannelProtocols[0];
            scp.Protocol.Should().Be(0x02);
            scp.Implementations.Should().HaveCount(3);
            scp.Implementations.Should().Contain(i => i.Implementation == 0x15);
            scp.Implementations.Should().Contain(i => i.Implementation == 0x04);
            scp.Implementations.Should().Contain(i => i.Implementation == 0x1A);
        }
    }
}