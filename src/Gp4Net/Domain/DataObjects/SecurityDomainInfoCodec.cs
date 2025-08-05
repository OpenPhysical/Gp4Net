// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.IO;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects;

/// <summary>
/// Codec for GlobalPlatform Security Domain Information (GET DATA tag 0x00C1).
/// Encodes and decodes security domain data according to GP Card Specification.
/// </summary>
[PublicAPI]
public static class SecurityDomainInfoCodec
{
    /// <summary>
    /// Encodes security domain information into binary format.
    /// </summary>
    /// <param name="sdInfo">The security domain information to encode.</param>
    /// <returns>The encoded security domain data.</returns>
    public static byte[] Encode(SecurityDomainInfo sdInfo)
    {
        ArgumentNullException.ThrowIfNull(sdInfo);
            
        using var stream = new MemoryStream();
            
        // Tag 0xC1 for security domain information
        stream.WriteByte(0xC1);
            
        // Calculate content length
        var contentStream = new MemoryStream();
            
        // OID (9F70) - two-byte tag
        if (sdInfo.Oid != null)
        {
            WriteTlvWithTag(contentStream, new byte[] { 0x9F, 0x70 }, sdInfo.Oid);
        }
            
        // Security Domain AID (if present)
        if (sdInfo.SecurityDomainAid != null)
        {
            contentStream.Write(sdInfo.SecurityDomainAid, 0, sdInfo.SecurityDomainAid.Length);
        }
            
        // Image data (C5)
        if (sdInfo.ImageData != null)
        {
            WriteTlv(contentStream, 0xC5, sdInfo.ImageData);
        }
            
        // Application production life cycle data (C4)
        if (sdInfo.LifeCycleData != null)
        {
            WriteTlv(contentStream, 0xC4, sdInfo.LifeCycleData);
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
            throw new InvalidOperationException("Security domain information too large for encoding");
        }
            
        // Write content
        stream.Write(content, 0, content.Length);
            
        return stream.ToArray();
    }
        
    /// <summary>
    /// Decodes security domain information from binary format.
    /// </summary>
    /// <param name="data">The encoded security domain data.</param>
    /// <returns>The decoded security domain information.</returns>
    public static Result<SecurityDomainInfo, SmartCardError> Decode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
            
        // Parse the outer TLV structure
        var outerTlvMaybe = TlvParser.ParseSingle(data);
        if (!outerTlvMaybe.HasValue || outerTlvMaybe.Value.TagNumber != 0xC1)
        {
            return SmartCardError.InvalidData("Invalid security domain information format - expected tag 0xC1");
        }
        
        var outerTlv = outerTlvMaybe.Value;
            
        try
        {
            var sdInfo = new SecurityDomainInfo();
            
            // Parse all TLV elements within the security domain data
            var elements = TlvParser.ParseAll(outerTlv.Value);
                
            foreach (var element in elements)
            {
                // Handle two-byte tags for OID (9F70)
                if (element.Tag.Length == 2 && element.Tag[0] == 0x9F && element.Tag[1] == 0x70)
                {
                    // Only set OID if it has actual content
                    if (element.Value.Length > 0)
                    {
                        sdInfo.Oid = element.Value;
                    }
                }
                else if (element.Tag.Length == 1)
                {
                    switch (element.TagNumber)
                    {
                        case 0xC5: // Image data
                            sdInfo.ImageData = element.Value;
                            break;
                                
                        case 0xC4: // Life cycle data
                            sdInfo.LifeCycleData = element.Value;
                            break;
                                
                        default:
                            // Could be AID data - store as SecurityDomainAid if not yet set
                            if (sdInfo.SecurityDomainAid == null && element.Length > 0)
                            {
                                // Reconstruct TLV format for AID
                                using var aidStream = new MemoryStream();
                                WriteTlv(aidStream, (byte)element.TagNumber, element.Value);
                                sdInfo.SecurityDomainAid = aidStream.ToArray();
                            }
                            break;
                    }
                }
            }
                
            return sdInfo;
        }
        catch (Exception ex)
        {
            return SmartCardError.InvalidData($"Failed to parse security domain information: {ex.Message}");
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
    
    private static void WriteTlvWithTag(Stream stream, byte[] tag, byte[] value)
    {
        stream.Write(tag, 0, tag.Length);
        
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
/// Represents GlobalPlatform security domain information.
/// </summary>
[PublicAPI]
public class SecurityDomainInfo
{
    /// <summary>
    /// Object identifier (OID) for the security domain.
    /// </summary>
    public byte[] Oid { get; set; }
        
    /// <summary>
    /// Security Domain AID with length encoding.
    /// </summary>
    public byte[] SecurityDomainAid { get; set; }
        
    /// <summary>
    /// Image data for security domain.
    /// </summary>
    public byte[] ImageData { get; set; }
        
    /// <summary>
    /// Application production life cycle data.
    /// </summary>
    public byte[] LifeCycleData { get; set; }
}