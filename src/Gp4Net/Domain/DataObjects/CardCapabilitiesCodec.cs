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
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects
{
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
                WriteTag(stream, 0x06, capabilities.CardRecognitionData);
            }
            
            // Card management type and version
            if (capabilities.CardManagementTypeAndVersion != null && capabilities.CardManagementTypeAndVersion.Length == 2)
            {
                stream.WriteByte(0x60);
                stream.WriteByte(0x02);
                stream.WriteByte(capabilities.CardManagementTypeAndVersion[0]);
                stream.WriteByte(capabilities.CardManagementTypeAndVersion[1]);
            }
            
            // Card identification scheme
            stream.WriteByte(0x63);
            stream.WriteByte(0x01);
            stream.WriteByte(capabilities.CardIdentificationScheme);
            
            // Secure channel protocol and implementation
            foreach (var scp in capabilities.SecureChannelProtocols)
            {
                stream.WriteByte(0x64);
                stream.WriteByte(0x01);
                stream.WriteByte(scp.Protocol);
                
                foreach (var impl in scp.Implementations)
                {
                    stream.WriteByte(0x65);
                    stream.WriteByte(0x01);
                    stream.WriteByte(impl.Implementation);
                    
                    if (impl.KeyTypes.Any())
                    {
                        stream.WriteByte(0x66);
                        stream.WriteByte((byte)impl.KeyTypes.Count);
                        foreach (var keyType in impl.KeyTypes)
                        {
                            stream.WriteByte(keyType);
                        }
                    }
                }
            }
            
            // Card configuration details
            if (capabilities.CardConfigurationDetails != null)
            {
                WriteTag(stream, 0x73, capabilities.CardConfigurationDetails);
            }
            
            // Card/chip details
            if (capabilities.CardChipDetails != null)
            {
                WriteTag(stream, 0x74, capabilities.CardChipDetails);
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
            
            if (data.Length < 2 || data[0] != 0x66)
            {
                return SmartCardError.InvalidData("Invalid card capabilities data format");
            }
            
            try
            {
                using var stream = new MemoryStream(data, 2, data.Length - 2);
                var capabilities = new CardCapabilities();
                
                while (stream.Position < stream.Length)
                {
                    var tag = (byte)stream.ReadByte();
                    var length = (byte)stream.ReadByte();
                    var value = new byte[length];
                    stream.Read(value, 0, length);
                    
                    switch (tag)
                    {
                        case 0x06: // Card recognition data OID
                            capabilities.CardRecognitionData = value;
                            break;
                            
                        case 0x60: // Card management type and version
                            if (length == 2)
                            {
                                capabilities.CardManagementTypeAndVersion = value;
                            }
                            break;
                            
                        case 0x63: // Card identification scheme
                            if (length == 1)
                            {
                                capabilities.CardIdentificationScheme = value[0];
                            }
                            break;
                            
                        case 0x64: // Secure channel protocol
                            if (length == 1)
                            {
                                var protocol = new SecureChannelProtocol { Protocol = value[0] };
                                capabilities.SecureChannelProtocols.Add(protocol);
                            }
                            break;
                            
                        case 0x65: // Secure channel implementation
                            if (length == 1 && capabilities.SecureChannelProtocols.Count > 0)
                            {
                                var lastProtocol = capabilities.SecureChannelProtocols.Last();
                                var implementation = new ScpImplementation { Implementation = value[0] };
                                lastProtocol.Implementations.Add(implementation);
                            }
                            break;
                            
                        case 0x66: // Key types for implementation
                            if (capabilities.SecureChannelProtocols.Count > 0)
                            {
                                var lastProtocol = capabilities.SecureChannelProtocols.Last();
                                if (lastProtocol.Implementations.Count > 0)
                                {
                                    var lastImpl = lastProtocol.Implementations.Last();
                                    lastImpl.KeyTypes.AddRange(value);
                                }
                            }
                            break;
                            
                        case 0x73: // Card configuration details
                            capabilities.CardConfigurationDetails = value;
                            break;
                            
                        case 0x74: // Card/chip details
                            capabilities.CardChipDetails = value;
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
        
        private static void WriteTag(Stream stream, byte tag, byte[] value)
        {
            stream.WriteByte(tag);
            stream.WriteByte((byte)value.Length);
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
        public byte[]? CardRecognitionData { get; set; }
        
        /// <summary>
        /// Card management type and version (2 bytes).
        /// </summary>
        public byte[]? CardManagementTypeAndVersion { get; set; }
        
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
        public byte[]? CardConfigurationDetails { get; set; }
        
        /// <summary>
        /// Card/chip details.
        /// </summary>
        public byte[]? CardChipDetails { get; set; }
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
        public List<ScpImplementation> Implementations { get; set; } = new();
    }
    
    /// <summary>
    /// Represents a secure channel protocol implementation.
    /// </summary>
    [PublicAPI]
    public class ScpImplementation
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
}