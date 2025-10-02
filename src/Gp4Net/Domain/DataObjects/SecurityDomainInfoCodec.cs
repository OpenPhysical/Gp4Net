// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System.IO;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Services.TlvService;

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
                SmartCardError.InvalidArgument("Security domain info cannot be null")
            );

        using var stream = new MemoryStream();

        // Tag 0xC1 for security domain information
        stream.WriteByte(0xC1);

        // Calculate content length
        var contentStream = new MemoryStream();

        // OID (9F70) - two-byte tag
        sdInfo.Oid.Match(
            oid =>
            {
                WriteTlvWithTag(contentStream, [0x9F, 0x70], oid);
            },
            () => { /* No OID to write */
            }
        );

        // Security Domain AID (if present)
        sdInfo.SecurityDomainAid.Match(
            aid =>
            {
                contentStream.Write(aid, 0, aid.Length);
            },
            () => { /* No AID to write */
            }
        );

        // Image data (C5)
        sdInfo.ImageData.Match(
            imageData =>
            {
                WriteTlv(contentStream, 0xC5, imageData);
            },
            () => { /* No image data to write */
            }
        );

        // Application production life cycle data (C4)
        sdInfo.LifeCycleData.Match(
            lifeCycleData =>
            {
                WriteTlv(contentStream, 0xC4, lifeCycleData);
            },
            () => { /* No life cycle data to write */
            }
        );

        byte[] content = contentStream.ToArray();

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
                    SmartCardError.InvalidData("Security domain information too large for encoding")
                );
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
                SmartCardError.InvalidArgument("Data cannot be null")
            );

        // Parse the outer TLV structure using functional composition
        return TlvParser
            .Parse([.. data])
            .Bind(outerTlv =>
                outerTlv
                    .Tag.ToNumber()
                    .Bind(tagNumber =>
                        tagNumber != 0xC1
                            ? Result.Failure<SecurityDomainInfo, SmartCardError>(
                                SmartCardError.InvalidData(
                                    "Invalid security domain information format - expected tag 0xC1"
                                )
                            )
                            : ParseSecurityDomainContent(outerTlv)
                    )
            );
    }

    private static Result<SecurityDomainInfo, SmartCardError> ParseSecurityDomainContent(
        TlvObject outerTlv
    )
    {
        var sdInfo = new SecurityDomainInfo();

        // Parse all TLV elements within the security domain data
        var elementsResult = TlvParser.ParseMultiple(outerTlv.TlvData.Bytes);
        if (elementsResult.IsFailure)
            return Result.Failure<SecurityDomainInfo, SmartCardError>(elementsResult.Error);
        var elements = elementsResult.Value.Objects;

        foreach (var element in elements)
        {
            switch (element.Tag.Bytes.Length)
            {
                // Handle two-byte tags for OID (9F70)
                case 2 when element.Tag.Bytes[0] == 0x9F && element.Tag.Bytes[1] == 0x70:
                {
                    // Only set OID if it has actual content
                    if (element.TlvData.Bytes.Length > 0)
                    {
                        sdInfo = sdInfo with
                        {
                            Oid = Maybe<byte[]>.From(element.TlvData.Bytes.ToArray()),
                        };
                    }
                    break;
                }
                case 1:
                    var elementTagNumber = element.Tag.ToNumber();
                    elementTagNumber.Match(
                        tagNumber =>
                        {
                            switch (tagNumber)
                            {
                                case 0xC5: // Image data
                                    sdInfo = sdInfo with
                                    {
                                        ImageData = Maybe<byte[]>.From(
                                            element.TlvData.Bytes.ToArray()
                                        ),
                                    };
                                    break;

                                case 0xC4: // Life cycle data
                                    sdInfo = sdInfo with
                                    {
                                        LifeCycleData = Maybe<byte[]>.From(
                                            element.TlvData.Bytes.ToArray()
                                        ),
                                    };
                                    break;

                                default:
                                    // Could be AID data - store as SecurityDomainAid if not yet set
                                    if (
                                        !sdInfo.SecurityDomainAid.HasValue
                                        && element.TlvData.Bytes.Length > 0
                                    )
                                    {
                                        // Reconstruct TLV format for AID
                                        using var aidStream = new MemoryStream();
                                        WriteTlv(
                                            aidStream,
                                            (byte)tagNumber,
                                            element.TlvData.Bytes.ToArray()
                                        );
                                        sdInfo = sdInfo with
                                        {
                                            SecurityDomainAid = Maybe<byte[]>.From(
                                                aidStream.ToArray()
                                            ),
                                        };
                                    }
                                    break;
                            }
                        },
                        error =>
                        { /* Ignore invalid tag numbers */
                        }
                    );
                    break;
            }
        }

        return sdInfo;
    }

    private static Result WriteTlv(Stream stream, byte tag, byte[] value)
    {
        if (value.Length > 255)
        {
            return Result.Failure(
                SmartCardError
                    .InvalidData($"Value too long for simple TLV encoding: {value.Length} bytes")
                    .Message
            );
        }

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
        }

        stream.Write(value, 0, value.Length);
        return Result.Success();
    }

    private static Result WriteTlvWithTag(Stream stream, byte[] tag, byte[] value)
    {
        if (value.Length > 255)
        {
            return Result.Failure(
                SmartCardError
                    .InvalidData($"Value too long for simple TLV encoding: {value.Length} bytes")
                    .Message
            );
        }

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
        }

        stream.Write(value, 0, value.Length);
        return Result.Success();
    }
}

/// <summary>
/// Represents GlobalPlatform security domain information.
/// </summary>
[PublicAPI]
public record SecurityDomainInfo
{
    /// <summary>
    /// Object identifier (OID) for the security domain.
    /// </summary>
    public Maybe<byte[]> Oid { get; init; } = Maybe<byte[]>.None;

    /// <summary>
    /// Security Domain AID with length encoding.
    /// </summary>
    public Maybe<byte[]> SecurityDomainAid { get; init; } = Maybe<byte[]>.None;

    /// <summary>
    /// Image data for security domain.
    /// </summary>
    public Maybe<byte[]> ImageData { get; init; } = Maybe<byte[]>.None;

    /// <summary>
    /// Application production life cycle data.
    /// </summary>
    public Maybe<byte[]> LifeCycleData { get; init; } = Maybe<byte[]>.None;
}
