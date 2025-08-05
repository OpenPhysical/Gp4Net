// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects;

/// <summary>
/// Encodes and decodes GlobalPlatform card capabilities according to GP Card Specification.
/// Card capabilities are returned in response to GET DATA for tag 0x0066.
/// </summary>
[PublicAPI]
public static class CardCapabilitiesCodec
{
    /// <summary>
    /// Encodes card capabilities into the binary format expected by GET DATA 0x0066.
    /// </summary>
    /// <param name="capabilities">The capabilities to encode.</param>
    /// <returns>The encoded capabilities data.</returns>
    public static byte[] Encode(CardCapabilities capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
            
        using var stream = new MemoryStream();
            
        // Tag 0x66 for card capabilities
        stream.WriteByte(0x66);
            
        // Calculate and write length (will be updated at the end)
        var lengthPosition = stream.Position;
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
        WriteTlv(stream, 0x63, new[] { capabilities.CardIdentificationScheme });
            
        // Secure channel protocol and implementation
        foreach (var scp in capabilities.SecureChannelProtocols)
        {
            WriteTlv(stream, 0x64, new[] { scp.Protocol });
                
            foreach (var impl in scp.Implementations)
            {
                WriteTlv(stream, 0x65, new[] { impl.Implementation });
                    
                if (impl.KeyTypes.Any())
                {
                    WriteTlv(stream, 0x66, impl.KeyTypes.ToArray());
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
            
        var data = stream.ToArray();
            
        // Update length field
        var contentLength = data.Length - 2; // Exclude tag and length byte
        if (contentLength <= 127)
        {
            data[1] = (byte)contentLength;
        }
        else
        {
            // Extended length encoding would be needed for larger capabilities
            throw new InvalidOperationException("Card capabilities too large for simple length encoding");
        }
            
        return data;
    }
        
    /// <summary>
    /// Decodes card capabilities from the binary format returned by GET DATA 0x0066.
    /// </summary>
    /// <param name="data">The encoded capabilities data.</param>
    /// <returns>The decoded capabilities.</returns>
    public static Result<CardCapabilities, SmartCardError> Decode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
            
        // Parse the outer TLV structure
        var outerTlvMaybe = TlvParser.ParseSingle(data);
        if (!outerTlvMaybe.HasValue || outerTlvMaybe.Value.TagNumber != 0x66)
        {
            return SmartCardError.InvalidData("Invalid card capabilities data format - expected tag 0x66");
        }
        
        var outerTlv = outerTlvMaybe.Value;
            
        try
        {
            var capabilities = new CardCapabilities();
            
            // Parse all TLV elements within the capabilities data
            var elements = TlvParser.ParseAll(outerTlv.Value);
            
            // Track the current protocol and implementation context
            SecureChannelProtocol currentProtocol = null;
            ScpImplementationSpecifier currentImplementation = null;
                
            foreach (var element in elements)
            {
                switch (element.TagNumber)
                {
                    case 0x06: // Card recognition data OID
                        capabilities.CardRecognitionData = element.Value;
                        break;
                            
                    case 0x60: // Card management type and version
                        if (element.Length == 2)
                        {
                            capabilities.CardManagementTypeAndVersion = element.Value;
                        }
                        break;
                            
                    case 0x63: // Card identification scheme
                        if (element.Length == 1)
                        {
                            capabilities.CardIdentificationScheme = element.Value[0];
                        }
                        break;
                            
                    case 0x64: // Secure channel protocol
                        if (element.Length == 1)
                        {
                            currentProtocol = new SecureChannelProtocol { Protocol = element.Value[0] };
                            capabilities.SecureChannelProtocols.Add(currentProtocol);
                            currentImplementation = null; // Reset implementation context
                        }
                        break;
                            
                    case 0x65: // Secure channel implementation
                        if (element.Length == 1 && currentProtocol != null)
                        {
                            // If we already have a currentImplementation, it means we're seeing a new one
                            currentImplementation = new ScpImplementationSpecifier { Implementation = element.Value[0] };
                            currentProtocol.Implementations.Add(currentImplementation);
                        }
                        break;
                            
                    case 0x66: // Key types for implementation
                        if (currentImplementation != null)
                        {
                            currentImplementation.KeyTypes.AddRange(element.Value);
                        }
                        break;
                            
                    case 0x73: // Card configuration details
                        capabilities.CardConfigurationDetails = element.Value;
                        break;
                            
                    case 0x74: // Card/chip details
                        capabilities.CardChipDetails = element.Value;
                        break;
                        
                    default:
                        // Unknown tags are ignored for forward compatibility
                        break;
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
        
        // Write length
        if (value.Length <= 127)
        {
            stream.WriteByte((byte)value.Length);
        }
        else if (value.Length <= 255)
        {
            stream.WriteByte(0x81);
            stream.WriteByte((byte)value.Length);
        }
        else
        {
            throw new ArgumentException($"Value too long for simple TLV encoding: {value.Length} bytes");
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
    public List<SecureChannelProtocol> SecureChannelProtocols { get; set; } = new();
        
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
    public List<ScpImplementationSpecifier> Implementations { get; set; } = new();
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
    public List<byte> KeyTypes { get; set; } = new();
}