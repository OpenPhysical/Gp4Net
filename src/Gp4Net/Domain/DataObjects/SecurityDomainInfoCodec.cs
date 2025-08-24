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
    /// <returns>A Result containing the encoded security domain data, or an error if sdInfo is null.</returns>
    public static Result<byte[], SmartCardError> Encode(SecurityDomainInfo sdInfo)
    {
        if (sdInfo is null)
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Security domain info cannot be null"));
            
        using var stream = new MemoryStream();
            
        // Tag 0xC1 for security domain information
        stream.WriteByte(0xC1);
            
        // Calculate content length
        var contentStream = new MemoryStream();
            
        // OID (9F70) - two-byte tag
        if (sdInfo.Oid != null)
        {
            WriteTlvWithTag(contentStream, [0x9F, 0x70], sdInfo.Oid);
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

        switch (content.Length)
        {
            // Write length
            case <= 127:
                stream.WriteByte((byte)content.Length);
                break;
            case <= 255:
                stream.WriteByte(0x81);
                stream.WriteByte((byte)content.Length);
                break;
            default:
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Security domain information too large for encoding"));
        }
            
        // Write content
        stream.Write(content, 0, content.Length);
            
        return Result.Success<byte[], SmartCardError>(stream.ToArray());
    }
        
    /// <summary>
    /// Decodes security domain information from binary format.
    /// </summary>
    /// <param name="data">The encoded security domain data.</param>
    /// <returns>A Result containing the decoded security domain information, or an error if data is invalid.</returns>
    public static Result<SecurityDomainInfo, SmartCardError> Decode(byte[] data)
    {
        if (data is null)
            return Result.Failure<SecurityDomainInfo, SmartCardError>(
                SmartCardError.InvalidArgument("Data cannot be null"));
            
        // Parse the outer TLV structure
        var outerTlvMaybe = TlvParser.ParseSingle(data);
        if (!outerTlvMaybe.HasValue)
        {
            return SmartCardError.InvalidData("No TLV data found");
        }
        
        var tagResult = outerTlvMaybe.Value.GetTagNumber();
        if (tagResult.IsFailure || tagResult.Value != 0xC1)
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
                switch (element.Tag.Length)
                {
                    // Handle two-byte tags for OID (9F70)
                    case 2 when element.Tag[0] == 0x9F && element.Tag[1] == 0x70:
                    {
                        // Only set OID if it has actual content
                        if (element.Value.Length > 0)
                        {
                            sdInfo.Oid = element.Value;
                        }
                        break;
                    }
                    case 1:
                        var elementTagNumber = element.GetTagNumber();
                        if (elementTagNumber.IsFailure) continue;
                        
                        switch (elementTagNumber.Value)
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
                                    WriteTlv(aidStream, (byte)elementTagNumber.Value, element.Value);
                                    sdInfo.SecurityDomainAid = aidStream.ToArray();
                                }
                                break;
                        }
                        break;
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
                throw new ArgumentException($"Value too long for simple TLV encoding: {value.Length} bytes");
        }
        
        stream.Write(value, 0, value.Length);
    }
    
    private static void WriteTlvWithTag(Stream stream, byte[] tag, byte[] value)
    {
        stream.Write(tag, 0, tag.Length);

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