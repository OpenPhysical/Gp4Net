// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using static Gp4Net.Services.TlvService;
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects;

/// <summary>
/// Encodes and decodes GlobalPlatform card capabilities according to GP Card Specification.
/// Card capabilities are returned in response to GET DATA for tag 0x0066.
/// This codec delegates to UnifiedTlvParser for TLV operations.
/// </summary>
[Obsolete("Use UnifiedTlvParser with domain-specific capabilities parsing logic for new code. This codec will be removed in a future version.")]
[PublicAPI]
public static class CardCapabilitiesCodec
{
    /// <summary>
    /// Encodes card capabilities into the binary format expected by GET DATA 0x0066.
    /// </summary>
    /// <param name="capabilities">The capabilities to encode.</param>
    /// <returns>A Result containing the encoded capabilities data, or an error if capabilities is null.</returns>
    public static Result<byte[], SmartCardError> Encode(CardCapabilities capabilities)
    {
        if (capabilities is null)
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Capabilities cannot be null")
            );

        using MemoryStream stream = new MemoryStream();

        // Tag 0x66 for card capabilities
        stream.WriteByte(0x66);

        // Calculate and write length (will be updated at the end)
        long lengthPosition = stream.Position;
        stream.WriteByte(0x00); // Placeholder for length

        // OID for card recognition data
        if (capabilities.CardRecognitionData != null)
        {
            WriteTlv(stream, 0x06, capabilities.CardRecognitionData);
        }

        // Card management type and version
        if (capabilities.CardManagementTypeAndVersion is { Length: 2 })
        {
            WriteTlv(stream, 0x60, capabilities.CardManagementTypeAndVersion);
        }

        // Card identification scheme
        WriteTlv(stream, 0x63, [capabilities.CardIdentificationScheme]);

        // Secure channel protocol and implementation
        foreach (SecureChannelProtocol scp in capabilities.SecureChannelProtocols)
        {
            WriteTlv(stream, 0x64, [scp.Protocol]);

            foreach (ScpImplementationSpecifier impl in scp.Implementations)
            {
                WriteTlv(stream, 0x65, [impl.Implementation]);

                if (impl.KeyTypes.Any())
                {
                    WriteTlv(stream, 0x66, [.. impl.KeyTypes]);
                }
            }
        }

        // Card configuration details
        if (capabilities.CardConfigurationDetails != null)
        {
            WriteTlv(stream, 0x73, capabilities.CardConfigurationDetails);
        }

        // Card/chip details
        if (capabilities.CardChipDetails != null)
        {
            WriteTlv(stream, 0x74, capabilities.CardChipDetails);
        }

        byte[] data = stream.ToArray();

        // Update length field
        int contentLength = data.Length - 2; // Exclude tag and length byte
        if (contentLength <= 127)
        {
            data[1] = (byte)contentLength;
        }
        else
        {
            // Extended length encoding would be needed for larger capabilities
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidData("Card capabilities too large for simple length encoding")
            );
        }

        return Result.Success<byte[], SmartCardError>(data);
    }

    /// <summary>
    /// Decodes card capabilities from the binary format returned by GET DATA 0x0066.
    /// </summary>
    /// <param name="data">The encoded capabilities data.</param>
    /// <returns>A Result containing the decoded card capabilities, or an error if data is invalid.</returns>
    public static Result<CardCapabilities, SmartCardError> Decode(byte[] data)
    {
        if (data is null)
            return Result.Failure<CardCapabilities, SmartCardError>(
                SmartCardError.InvalidArgument("Data cannot be null")
            );

        // Parse the outer TLV structure
        var parseResult = TlvParser.Parse(data.ToImmutableArray());
        if (parseResult.IsFailure)
        {
            return Result.Failure<CardCapabilities, SmartCardError>(parseResult.Error);
        }

        if (!parseResult.IsSuccess)
        {
            return Result.Failure<CardCapabilities, SmartCardError>(
                SmartCardError.InvalidData("Parse result was not successful"));
        }

        var outerTlv = parseResult.Value;
        var tagResult = outerTlv.Tag.ToNumber();
        if (tagResult.IsFailure)
        {
            return Result.Failure<CardCapabilities, SmartCardError>(tagResult.Error);
        }

        if (tagResult.IsSuccess && tagResult.Value != 0x66)
        {
            return Result.Failure<CardCapabilities, SmartCardError>(
                SmartCardError.InvalidData("Invalid card capabilities data format - expected tag 0x66"));
        }

        try
        {
            CardCapabilities capabilities = new CardCapabilities();

            // Parse all TLV elements within the capabilities data
            var elementsResult = TlvParser.ParseMultiple(outerTlv.TlvData.Bytes);
            if (elementsResult.IsFailure)
            {
                return Result.Failure<CardCapabilities, SmartCardError>(elementsResult.Error);
            }
            var elements = elementsResult.Value.Objects;

            // Track the current protocol and implementation context
            Maybe<SecureChannelProtocol> currentProtocol = Maybe<SecureChannelProtocol>.None;
            Maybe<ScpImplementationSpecifier> currentImplementation = Maybe<ScpImplementationSpecifier>.None;

            foreach (TlvObject element in elements)
            {
                var tagNumberResult = element.Tag.ToNumber();
                if (tagNumberResult.IsFailure)
                    continue;

                if (tagNumberResult.IsSuccess)
                {
                    switch (tagNumberResult.Value)
                {
                    case 0x06: // Card recognition data OID
                        capabilities.CardRecognitionData = element.TlvData.Bytes.ToArray();
                        break;

                    case 0x60: // Card management type and version
                        if (element.Length.LengthValue == 2)
                        {
                            capabilities.CardManagementTypeAndVersion = element.TlvData.Bytes.ToArray();
                        }
                        break;

                    case 0x63: // Card identification scheme
                        if (element.Length.LengthValue == 1)
                        {
                            capabilities.CardIdentificationScheme = element.TlvData.Bytes[0];
                        }
                        break;

                    case 0x64: // Secure channel protocol
                        if (element.Length.LengthValue == 1)
                        {
                            var protocol = new SecureChannelProtocol
                            {
                                Protocol = element.TlvData.Bytes[0],
                            };
                            currentProtocol = Maybe<SecureChannelProtocol>.From(protocol);
                            var protocolList = capabilities.SecureChannelProtocols.ToList();
                            protocolList.Add(protocol);
                            capabilities.SecureChannelProtocols = protocolList;
                            currentImplementation = Maybe<ScpImplementationSpecifier>.None; // Reset implementation context
                        }
                        break;

                    case 0x65: // Secure channel implementation
                        if (element.Length.LengthValue == 1 && currentProtocol.HasValue)
                        {
                            // If we already have a currentImplementation, it means we're seeing a new one
                            var implementation = new ScpImplementationSpecifier
                            {
                                Implementation = element.TlvData.Bytes[0],
                            };
                            currentImplementation = Maybe<ScpImplementationSpecifier>.From(implementation);
                            currentProtocol.Match(
                                scp =>
                                {
                                    var implList = scp.Implementations.ToList();
                                    implList.Add(implementation);
                                    scp.Implementations = implList;
                                },
                                () => { /* No current protocol to add implementation to */ }
                            );
                        }
                        break;

                    case 0x66: // Key types for implementation
                        currentImplementation.Match(
                            impl =>
                            {
                                var keyTypesList = impl.KeyTypes.ToList();
                                keyTypesList.AddRange(element.TlvData.Bytes.ToArray());
                                impl.KeyTypes = keyTypesList;
                            },
                            () => { /* No current implementation to add key types to */ }
                        );
                        break;

                    case 0x73: // Card configuration details
                        capabilities.CardConfigurationDetails = element.TlvData.Bytes.ToArray();
                        break;

                    case 0x74: // Card/chip details
                        capabilities.CardChipDetails = element.TlvData.Bytes.ToArray();
                        break;
                }
                }
            }

            return capabilities;
        }
        catch (Exception ex)
        {
            return SmartCardError.InvalidData($"Failed to parse card capabilities: {ex.Message}");
        }
    }

    private static void WriteTlv(Stream stream, byte tag, byte[] value)
    {
        stream.WriteByte(tag);

        switch (value.Length)
        {
            // Write length
            case <= 127:
                stream.WriteByte((byte)value.Length);
                break;
            case <= 255:
                stream.WriteByte(0x81);
                stream.WriteByte((byte)value.Length);
                break;
            default:
                throw new ArgumentException(
                    $"Value too long for simple TLV encoding: {value.Length} bytes"
                );
        }

        stream.Write(value, 0, value.Length);
    }
}

/// <summary>
/// Represents GlobalPlatform card capabilities.
/// </summary>
[PublicAPI]
public class CardCapabilities
{
    /// <summary>
    /// Card recognition data (OID).
    /// </summary>
    public byte[] CardRecognitionData { get; set; }

    /// <summary>
    /// Card management type and version (2 bytes).
    /// </summary>
    public byte[] CardManagementTypeAndVersion { get; set; }

    /// <summary>
    /// Card identification scheme.
    /// </summary>
    public byte CardIdentificationScheme { get; set; }

    /// <summary>
    /// Supported secure channel protocols.
    /// </summary>
    public List<SecureChannelProtocol> SecureChannelProtocols { get; set; } = [];

    /// <summary>
    /// Card configuration details.
    /// </summary>
    public byte[] CardConfigurationDetails { get; set; }

    /// <summary>
    /// Card/chip details.
    /// </summary>
    public byte[] CardChipDetails { get; set; }
}

/// <summary>
/// Represents a secure channel protocol capability.
/// </summary>
[PublicAPI]
public class SecureChannelProtocol
{
    /// <summary>
    /// Protocol identifier (0x02 for SCP02, 0x03 for SCP03).
    /// </summary>
    public byte Protocol { get; set; }

    /// <summary>
    /// Supported implementations for this protocol.
    /// </summary>
    public List<ScpImplementationSpecifier> Implementations { get; set; } = [];
}

/// <summary>
/// Specifies a supported secure channel protocol implementation from card capabilities.
/// Used for parsing and representing SCP implementation details from card responses.
/// </summary>
[PublicAPI]
public class ScpImplementationSpecifier
{
    /// <summary>
    /// Implementation parameter (e.g., 0x15 for SCP02, 0x70 for SCP03).
    /// </summary>
    public byte Implementation { get; set; }

    /// <summary>
    /// Supported key types for this implementation.
    /// </summary>
    public List<byte> KeyTypes { get; set; } = [];
}
