using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using Org.BouncyCastle.Asn1;
using static Gp4Net.Services.TlvService;

namespace Gp4Net.Services;

/// <summary>
/// Pure functional parser for GlobalPlatform Card Recognition Data (tag 73).
/// Per GP Card Specification v2.3.1 Section E.2.1.1, parses nested application tags
/// and OIDs within the Card Recognition Data structure.
/// </summary>
public static class CardDataParser
{
    /// <summary>
    /// Parses Card Recognition Data from tag 73 into structured CardRecognitionData.
    /// Uses functional composition to extract nested application tags and OIDs.
    /// </summary>
    /// <param name="tag73Data">Raw bytes from tag 73 (Card Recognition Data)</param>
    /// <returns>Result containing parsed CardRecognitionData or SmartCardError</returns>
    public static Result<CardRecognitionData, SmartCardError> ParseCardRecognitionData(
        byte[] tag73Data
    )
    {
        return tag73Data.Length == 0
            ? Result.Success<CardRecognitionData, SmartCardError>(CardRecognitionData.Empty)
            : ParseCardRecognitionElements(tag73Data);
    }

    /// <summary>
    /// Pure function to parse card recognition elements into structured information.
    /// Per GP Card Specification v2.3.1 Section E.2.1.1, extracts application tags and nested OIDs.
    /// </summary>
    private static Result<CardRecognitionData, SmartCardError> ParseCardRecognitionElements(
        byte[] data
    )
    {
        return Result.Try(
            () =>
            {
                var directOid = ExtractDirectOid(data);
                var applicationTags = ExtractApplicationTags(data);

                return new CardRecognitionData(directOid, applicationTags);
            },
            ex => SmartCardError.InvalidData($"Failed to parse card recognition data: {ex.Message}")
        );
    }

    /// <summary>
    /// Extracts the direct OID from the Card Recognition Data if present.
    /// Per GP specification, this is typically the GlobalPlatform Card Recognition OID (1.2.840.114283.1).
    /// </summary>
    private static Maybe<string> ExtractDirectOid(byte[] data)
    {
        return TlvParser
            .ParseMultiple([.. data])
            .Match(
                parseResult =>
                    parseResult
                        .Objects.Where(element =>
                            element
                                .Tag.ToNumber()
                                .Match(
                                    tagNumber => tagNumber == 0x06, // OID tag
                                    _ => false
                                )
                        )
                        .Select(element => ParseOid(element.TlvData.Bytes.ToArray()))
                        .Where(oid => oid.HasValue)
                        .Select(oid => oid.Value)
                        .Aggregate(Maybe<string>.None, (_, current) => Maybe<string>.From(current)),
                _ => Maybe<string>.None
            );
    }

    /// <summary>
    /// Extracts all application tags (60, 63, 64, 65, 66, etc.) from the Card Recognition Data.
    /// Each application tag may contain nested TLV structures including OIDs.
    /// </summary>
    private static IReadOnlyList<ApplicationTag> ExtractApplicationTags(byte[] data)
    {
        return TlvParser
            .ParseMultiple([.. data])
            .Match(
                parseResult =>
                    parseResult
                        .Objects.Select(element =>
                            element
                                .Tag.ToNumber()
                                .Match(
                                    tagNumber =>
                                        IsApplicationTag((int)tagNumber)
                                            ? Maybe<ApplicationTag>.From(
                                                ParseApplicationTag(
                                                    (byte)tagNumber,
                                                    element.TlvData.Bytes.ToArray()
                                                )
                                            )
                                            : Maybe<ApplicationTag>.None,
                                    _ => Maybe<ApplicationTag>.None
                                )
                        )
                        .Where(tag => tag.HasValue)
                        .Select(tag => tag.Value)
                        .ToImmutableList(),
                _ => ImmutableList<ApplicationTag>.Empty
            );
    }

    /// <summary>
    /// Determines if a tag number represents an application tag per GP specification.
    /// Application tags are 60, 63, 64, 65, 66, 67, 68, etc.
    /// </summary>
    private static bool IsApplicationTag(int tagNumber) =>
        tagNumber switch
        {
            0x60 => true, // Card Management Type and Version
            0x63 => true, // Card Identification Scheme
            0x64 => true, // Secure Channel Protocol
            0x65 => true, // Card Configuration Details (optional)
            0x66 => true, // Card/Chip Details (optional)
            0x67 => true, // ISD Trust Point Certificate (optional)
            0x68 => true, // ISD Certificate (conditional)
            _ => false,
        };

    /// <summary>
    /// Parses an individual application tag and extracts nested OID if present.
    /// </summary>
    private static ApplicationTag ParseApplicationTag(byte tagNumber, byte[] tagData)
    {
        var nestedOid = ExtractNestedOid(tagData);
        return ApplicationTag.Create(tagNumber, tagData, nestedOid);
    }

    /// <summary>
    /// Extracts nested OID from within an application tag's data.
    /// Searches recursively through nested TLV structures.
    /// </summary>
    private static Maybe<string> ExtractNestedOid(byte[] tagData)
    {
        return TlvParser
            .ParseMultiple([.. tagData])
            .Match(
                parseResult =>
                    parseResult
                        .Objects.SelectMany(element =>
                            element
                                .Tag.ToNumber()
                                .Match(
                                    tagNumber =>
                                        tagNumber == 0x06
                                            ? [ParseOid(element.TlvData.Bytes.ToArray())]
                                            : ExtractOidsRecursive(element.TlvData.Bytes.ToArray())
                                                .ToArray(),
                                    _ => []
                                )
                        )
                        .Where(oid => oid.HasValue)
                        .Select(oid => oid.Value)
                        .Aggregate(Maybe<string>.None, (_, current) => Maybe<string>.From(current)),
                _ => Maybe<string>.None
            );
    }

    /// <summary>
    /// Recursively extracts OIDs from nested TLV structures.
    /// </summary>
    private static IEnumerable<Maybe<string>> ExtractOidsRecursive(byte[] data)
    {
        return TlvParser
            .ParseMultiple([.. data])
            .Match(
                parseResult =>
                    parseResult.Objects.SelectMany(element =>
                        element
                            .Tag.ToNumber()
                            .Match(
                                tagNumber =>
                                    tagNumber == 0x06
                                        ? [ParseOid(element.TlvData.Bytes.ToArray())]
                                        : element.TlvData.Bytes.Length >= 2
                                            ? ExtractOidsRecursive(element.TlvData.Bytes.ToArray())
                                            : [],
                                _ => []
                            )
                    ),
                _ => []
            );
    }

    /// <summary>
    /// Pure function to parse a single OID from bytes using BouncyCastle.
    /// </summary>
    private static Maybe<string> ParseOid(byte[] oidBytes)
    {
        // Use Result.Try for functional exception handling
        return Result
            .Try(() =>
            {
                // Create DER-encoded OID from content
                byte[] derBytes = new byte[oidBytes.Length + 2];
                derBytes[0] = 0x06; // OID tag
                derBytes[1] = (byte)oidBytes.Length;
                Buffer.BlockCopy(oidBytes, 0, derBytes, 2, oidBytes.Length);

                var asn1Object = Asn1Object.FromByteArray(derBytes);
                return asn1Object is DerObjectIdentifier oidObj
                    ? Maybe<string>.From(oidObj.Id)
                    : Maybe<string>.None;
            })
            .Match(success => success, _ => Maybe<string>.None);
    }
}
