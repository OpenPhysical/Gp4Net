// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects
{
    /// <summary>
    /// Codec for GlobalPlatform Key Information Template (GET DATA tag 0x00E0).
    /// Encodes and decodes key information according to GP Card Specification.
    /// </summary>
    [PublicAPI]
    public static class KeyInfoTemplateCodec
    {
        /// <summary>
        /// Encodes key information template into binary format.
        /// </summary>
        /// <param name="keyInfo">The key information to encode.</param>
        /// <returns>The encoded key information data.</returns>
        public static byte[] Encode(KeyInfoTemplate keyInfo)
        {
            ArgumentNullException.ThrowIfNull(keyInfo);
            
            using var stream = new MemoryStream();
            
            // Tag 0xE0 for key information template
            stream.WriteByte(0xE0);
            
            // Calculate content length
            var contentStream = new MemoryStream();
            
            // Key version number (C0)
            if (keyInfo.KeyVersionNumber.HasValue)
            {
                contentStream.WriteByte(0xC0);
                contentStream.WriteByte(0x01);
                contentStream.WriteByte(keyInfo.KeyVersionNumber.Value);
            }
            
            // Key identifier (C1)
            if (keyInfo.KeyIdentifier.HasValue)
            {
                contentStream.WriteByte(0xC1);
                contentStream.WriteByte(0x01);
                contentStream.WriteByte(keyInfo.KeyIdentifier.Value);
            }
            
            // Key types and lengths (C2)
            if (keyInfo.KeyTypesAndLengths.Count > 0)
            {
                contentStream.WriteByte(0xC2);
                contentStream.WriteByte((byte)(keyInfo.KeyTypesAndLengths.Count * 2));
                foreach (var keyType in keyInfo.KeyTypesAndLengths)
                {
                    contentStream.WriteByte(keyType.Type);
                    contentStream.WriteByte(keyType.Length);
                }
            }
            
            var content = contentStream.ToArray();
            
            // Write length
            if (content.Length <= 127)
            {
                stream.WriteByte((byte)content.Length);
            }
            else
            {
                stream.WriteByte(0x81);
                stream.WriteByte((byte)content.Length);
            }
            
            // Write content
            stream.Write(content, 0, content.Length);
            
            return stream.ToArray();
        }
        
        /// <summary>
        /// Decodes key information template from binary format.
        /// </summary>
        /// <param name="data">The encoded key information data.</param>
        /// <returns>The decoded key information.</returns>
        public static Result<KeyInfoTemplate, SmartCardError> Decode(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);
            
            if (data.Length < 2 || data[0] != 0xE0)
            {
                return SmartCardError.InvalidData("Invalid key information template format");
            }
            
            try
            {
                var offset = 1;
                var length = data[offset++];
                
                // Handle extended length
                if ((length & 0x80) != 0)
                {
                    var lengthBytes = length & 0x7F;
                    if (lengthBytes == 1)
                    {
                        length = data[offset++];
                    }
                    else
                    {
                        return SmartCardError.InvalidData("Extended length not supported");
                    }
                }
                
                var keyInfo = new KeyInfoTemplate();
                var endOffset = offset + length;
                
                while (offset < endOffset && offset < data.Length)
                {
                    var tag = data[offset++];
                    var tagLength = data[offset++];
                    
                    if (offset + tagLength > data.Length)
                    {
                        break;
                    }
                    
                    switch (tag)
                    {
                        case 0xC0: // Key version number
                            if (tagLength == 1)
                            {
                                keyInfo.KeyVersionNumber = data[offset];
                            }
                            break;
                            
                        case 0xC1: // Key identifier
                            if (tagLength == 1)
                            {
                                keyInfo.KeyIdentifier = data[offset];
                            }
                            break;
                            
                        case 0xC2: // Key types and lengths
                            for (int i = 0; i < tagLength; i += 2)
                            {
                                if (i + 1 < tagLength)
                                {
                                    keyInfo.KeyTypesAndLengths.Add(new KeyTypeAndLength
                                    {
                                        Type = data[offset + i],
                                        Length = data[offset + i + 1]
                                    });
                                }
                            }
                            break;
                    }
                    
                    offset += tagLength;
                }
                
                return keyInfo;
            }
            catch (Exception ex)
            {
                return SmartCardError.InvalidData($"Failed to parse key information template: {ex.Message}");
            }
        }
    }
    
    /// <summary>
    /// Represents GlobalPlatform key information template.
    /// </summary>
    [PublicAPI]
    public class KeyInfoTemplate
    {
        /// <summary>
        /// Key version number.
        /// </summary>
        public byte? KeyVersionNumber { get; set; }
        
        /// <summary>
        /// Key identifier.
        /// </summary>
        public byte? KeyIdentifier { get; set; }
        
        /// <summary>
        /// Key types and their lengths.
        /// </summary>
        public List<KeyTypeAndLength> KeyTypesAndLengths { get; set; } = new();
    }
    
    /// <summary>
    /// Represents a key type and its length.
    /// </summary>
    [PublicAPI]
    public class KeyTypeAndLength
    {
        /// <summary>
        /// Key type identifier.
        /// </summary>
        public byte Type { get; set; }
        
        /// <summary>
        /// Key length in bytes.
        /// </summary>
        public byte Length { get; set; }
    }
}