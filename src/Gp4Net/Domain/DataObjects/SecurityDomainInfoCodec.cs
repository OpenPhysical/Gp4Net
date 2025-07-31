// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.IO;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects
{
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
            
            // OID (9F70)
            if (sdInfo.Oid != null)
            {
                contentStream.WriteByte(0x9F);
                contentStream.WriteByte(0x70);
                contentStream.WriteByte((byte)sdInfo.Oid.Length);
                contentStream.Write(sdInfo.Oid, 0, sdInfo.Oid.Length);
            }
            
            // Security Domain AID (if present)
            if (sdInfo.SecurityDomainAid != null)
            {
                contentStream.Write(sdInfo.SecurityDomainAid, 0, sdInfo.SecurityDomainAid.Length);
            }
            
            // Image data (C5)
            if (sdInfo.ImageData != null)
            {
                contentStream.WriteByte(0xC5);
                contentStream.WriteByte((byte)sdInfo.ImageData.Length);
                contentStream.Write(sdInfo.ImageData, 0, sdInfo.ImageData.Length);
            }
            
            // Application production life cycle data (C4)
            if (sdInfo.LifeCycleData != null)
            {
                contentStream.WriteByte(0xC4);
                contentStream.WriteByte((byte)sdInfo.LifeCycleData.Length);
                contentStream.Write(sdInfo.LifeCycleData, 0, sdInfo.LifeCycleData.Length);
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
        /// Decodes security domain information from binary format.
        /// </summary>
        /// <param name="data">The encoded security domain data.</param>
        /// <returns>The decoded security domain information.</returns>
        public static Result<SecurityDomainInfo, SmartCardError> Decode(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);
            
            if (data.Length < 2 || data[0] != 0xC1)
            {
                return SmartCardError.InvalidData("Invalid security domain information format");
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
                
                var sdInfo = new SecurityDomainInfo();
                var endOffset = offset + length;
                
                while (offset < endOffset && offset < data.Length)
                {
                    if (offset + 1 >= data.Length) break;
                    
                    var tag = data[offset++];
                    
                    // Handle two-byte tags
                    if (tag == 0x9F && offset < data.Length)
                    {
                        var tag2 = data[offset++];
                        if (tag2 == 0x70) // OID tag
                        {
                            if (offset >= data.Length) break;
                            var oidLength = data[offset++];
                            if (offset + oidLength <= data.Length)
                            {
                                sdInfo.Oid = new byte[oidLength];
                                Array.Copy(data, offset, sdInfo.Oid, 0, oidLength);
                                offset += oidLength;
                            }
                        }
                        continue;
                    }
                    
                    if (offset >= data.Length) break;
                    var tagLength = data[offset++];
                    
                    if (offset + tagLength > data.Length) break;
                    
                    switch (tag)
                    {
                        case 0xC5: // Image data
                            sdInfo.ImageData = new byte[tagLength];
                            Array.Copy(data, offset, sdInfo.ImageData, 0, tagLength);
                            break;
                            
                        case 0xC4: // Life cycle data
                            sdInfo.LifeCycleData = new byte[tagLength];
                            Array.Copy(data, offset, sdInfo.LifeCycleData, 0, tagLength);
                            break;
                            
                        default:
                            // Could be AID data - store as SecurityDomainAid if not yet set
                            if (sdInfo.SecurityDomainAid == null && tagLength > 0)
                            {
                                sdInfo.SecurityDomainAid = new byte[tagLength + 2];
                                sdInfo.SecurityDomainAid[0] = tag;
                                sdInfo.SecurityDomainAid[1] = tagLength;
                                Array.Copy(data, offset, sdInfo.SecurityDomainAid, 2, tagLength);
                            }
                            break;
                    }
                    
                    offset += tagLength;
                }
                
                return sdInfo;
            }
            catch (Exception ex)
            {
                return SmartCardError.InvalidData($"Failed to parse security domain information: {ex.Message}");
            }
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
        public byte[]? Oid { get; set; }
        
        /// <summary>
        /// Security Domain AID with length encoding.
        /// </summary>
        public byte[]? SecurityDomainAid { get; set; }
        
        /// <summary>
        /// Image data for security domain.
        /// </summary>
        public byte[]? ImageData { get; set; }
        
        /// <summary>
        /// Application production life cycle data.
        /// </summary>
        public byte[]? LifeCycleData { get; set; }
    }
}