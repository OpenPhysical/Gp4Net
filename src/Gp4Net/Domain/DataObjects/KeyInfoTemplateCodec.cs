// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects;

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
            WriteTlv(contentStream, 0xC0, new[] { keyInfo.KeyVersionNumber.Value });
        }
            
        // Key identifier (C1)
        if (keyInfo.KeyIdentifier.HasValue)
        {
            WriteTlv(contentStream, 0xC1, new[] { keyInfo.KeyIdentifier.Value });
        }
            
        // Key types and lengths (C2)
        if (keyInfo.KeyTypesAndLengths.Count > 0)
        {
            var keyData = new byte[keyInfo.KeyTypesAndLengths.Count * 2];
            var index = 0;
            foreach (var keyType in keyInfo.KeyTypesAndLengths)
            {
                keyData[index++] = keyType.Type;
                keyData[index++] = keyType.Length;
            }
            WriteTlv(contentStream, 0xC2, keyData);
        }
            
        var content = contentStream.ToArray();
            
        // Write length
        if (content.Length <= 127)
        {
            stream.WriteByte((byte)content.Length);
        }
        else if (content.Length <= 255)
        {
            stream.WriteByte(0x81);
            stream.WriteByte((byte)content.Length);
        }
        else
        {
            throw new InvalidOperationException("Key information template too large for encoding");
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
            
        // Parse the outer TLV structure
        var outerTlvMaybe = TlvParser.ParseSingle(data);
        if (!outerTlvMaybe.HasValue || outerTlvMaybe.Value.TagNumber != 0xE0)
        {
            return SmartCardError.InvalidData("Invalid key information template format - expected tag 0xE0");
        }
        
        var outerTlv = outerTlvMaybe.Value;
            
        try
        {
            var keyInfo = new KeyInfoTemplate();
                
            // Parse all TLV elements within the key information data
            var elements = TlvParser.ParseAll(outerTlv.Value);
                
            foreach (var element in elements)
            {
                switch (element.TagNumber)
                {
                    case 0xC0: // Key version number
                        if (element.Length == 1)
                        {
                            keyInfo.KeyVersionNumber = element.Value[0];
                        }
                        break;
                            
                    case 0xC1: // Key identifier
                        if (element.Length == 1)
                        {
                            keyInfo.KeyIdentifier = element.Value[0];
                        }
                        break;
                            
                    case 0xC2: // Key types and lengths
                        if (element.Value is { Length: >= 2 })
                        {
                            for (int i = 0; i < element.Value.Length; i += 2)
                            {
                                if (i + 1 < element.Value.Length)
                                {
                                    keyInfo.KeyTypesAndLengths.Add(new KeyTypeAndLength
                                    {
                                        Type = element.Value[i],
                                        Length = element.Value[i + 1]
                                    });
                                }
                            }
                        }
                        break;
                        
                    default:
                        // Unknown tags are ignored for forward compatibility
                        break;
                }
            }
                
            return keyInfo;
        }
        catch (Exception ex)
        {
            return SmartCardError.InvalidData($"Failed to parse key information template: {ex.Message}");
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
/// Represents GlobalPlatform key information template.
/// </summary>
[PublicAPI]
public class KeyInfoTemplate
{
    /// <summary>
    /// Key version number.
    /// </summary>
    public Maybe<byte> KeyVersionNumber { get; set; } = Maybe<byte>.None;
        
    /// <summary>
    /// Key identifier.
    /// </summary>
    public Maybe<byte> KeyIdentifier { get; set; } = Maybe<byte>.None;
        
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