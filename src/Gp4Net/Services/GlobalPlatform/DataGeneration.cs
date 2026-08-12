// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.DataObjects;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using static Gp4Net.Services.TlvCodec;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// Data object generation for virtual card responses.
/// Complements the existing Responses parsing functionality by providing generation capabilities.
/// Used primarily by CardEmulator to generate proper GP-compliant responses.
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.3
/// </summary>
[PublicAPI]
public static class DataGeneration
{
    /// <summary>
    /// Generates card capabilities data object (tag 0x0066) for virtual cards.
    /// This creates the structured card capabilities data that describes supported protocols and features.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Table H-6
    /// </summary>
    /// <param name="supportedScp02Implementations">SCP02 implementations supported by the virtual card.</param>
    /// <param name="supportedScp03Implementations">SCP03 implementations supported by the virtual card.</param>
    /// <param name="keyTypes">Supported key types and lengths.</param>
    /// <returns>The encoded card capabilities data or an error.</returns>
    public static Result<byte[], SmartCardError> BuildCardCapabilities(
        ImmutableList<ScpImplementation> supportedScp02Implementations,
        ImmutableList<ScpImplementation> supportedScp03Implementations,
        ImmutableList<KeyTypeAndLength> keyTypes
    )
    {
        // Build protocol TLVs functionally
        var scp02TlvResult =
            supportedScp02Implementations.Count > 0
                ? BuildScpProtocolTlv(Protocols.SCP02, supportedScp02Implementations, keyTypes)
                    .Map(Maybe<TlvObject>.From)
                : Result.Success<Maybe<TlvObject>, SmartCardError>(Maybe<TlvObject>.None);

        var scp03TlvResult =
            supportedScp03Implementations.Count > 0
                ? BuildScpProtocolTlv(Protocols.SCP03, supportedScp03Implementations, keyTypes)
                    .Map(Maybe<TlvObject>.From)
                : Result.Success<Maybe<TlvObject>, SmartCardError>(Maybe<TlvObject>.None);

        return scp02TlvResult
            .Bind(scp02Maybe =>
                scp03TlvResult.Map(
                    (Maybe<TlvObject> scp03Maybe) =>
                        new[] { scp02Maybe, scp03Maybe }
                            .Where(maybe => maybe.HasValue)
                            .Select(maybe => maybe.Value)
                            .ToImmutableArray()
                )
            )
            .Bind(tlvObjects => TlvEncoder.EncodeMultiple(tlvObjects))
            .Map(encoded => encoded.ToArray())
            .MapError(error =>
                SmartCardError.InvalidData($"Failed to encode card capabilities: {error}")
            );
    }

    /// <summary>
    /// Generates key information template data object (tag 0x00E0) for virtual cards.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.3.3.1.1.
    /// </summary>
    /// <param name="keyVersionNumber">The key version number.</param>
    /// <param name="keyIdentifier">The key identifier.</param>
    /// <param name="keyTypes">The key types and lengths supported.</param>
    /// <returns>The encoded key information template or an error.</returns>
    public static Result<byte[], SmartCardError> BuildKeyInformationTemplate(
        byte keyVersionNumber,
        byte keyIdentifier,
        ImmutableList<KeyTypeAndLength> keyTypes
    )
    {
        var keyInfo = new KeyInfoTemplate
        {
            KeyVersionNumber = Maybe<byte>.From(keyVersionNumber),
            KeyIdentifier = Maybe<byte>.From(keyIdentifier),
            KeyTypesAndLengths = [.. keyTypes],
        };

        return KeyInfoTemplateCodec.Encode(keyInfo);
    }

    /// <summary>
    /// Generates CPLC (Card Production Life Cycle) data object (tag 0x9F7F).
    /// Returns standard test CPLC data suitable for virtual card emulation.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 9.1.2
    /// </summary>
    /// <returns>Standard CPLC data for virtual cards.</returns>
    public static Result<byte[], SmartCardError> BuildCplcData()
    {
        // Standard test CPLC data - 45 bytes as per GP specification
        var cplcData = Convert.FromHexString(
            "4790D3214700000000002345558919204839000000000000000018649535383931390000000000000000"
        );

        return Result.Success<byte[], SmartCardError>(cplcData);
    }

    /// <summary>
    /// Generates legacy card capabilities data object (tag 0x0067).
    /// Returns fixed legacy format capabilities data for backward compatibility.
    /// </summary>
    /// <returns>Legacy card capabilities data.</returns>
    public static Result<byte[], SmartCardError> BuildLegacyCardCapabilities()
    {
        // Legacy format card capabilities data
        var legacyData = Convert.FromHexString(
            "6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B"
        );

        return Result.Success<byte[], SmartCardError>(legacyData);
    }

    /// <summary>
    /// Generates a complete GET DATA response for the specified tag with appropriate data.
    /// Dispatches to the correct data generation method based on the tag.
    /// </summary>
    /// <param name="tag">The data object tag being requested.</param>
    /// <param name="supportedScp02">SCP02 implementations for card capabilities.</param>
    /// <param name="supportedScp03">SCP03 implementations for card capabilities.</param>
    /// <param name="keyTypes">Key types for capabilities and key info.</param>
    /// <param name="keyVersionNumber">Key version for key info template.</param>
    /// <param name="keyIdentifier">Key identifier for key info template.</param>
    /// <returns>The generated data object or an error.</returns>
    public static Result<byte[], SmartCardError> BuildGetDataResponse(
        ushort tag,
        ImmutableList<ScpImplementation> supportedScp02,
        ImmutableList<ScpImplementation> supportedScp03,
        ImmutableList<KeyTypeAndLength> keyTypes,
        byte keyVersionNumber = 0x01,
        byte keyIdentifier = 0x00
    )
    {
        return tag switch
        {
            0x0066 => BuildCardCapabilities(supportedScp02, supportedScp03, keyTypes),
            0x0067 => BuildLegacyCardCapabilities(),
            0x00E0 => BuildKeyInformationTemplate(keyVersionNumber, keyIdentifier, keyTypes),
            0x9F7F => BuildCplcData(),
            _
                => Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported data object tag: 0x{tag:X4}")
                ),
        };
    }

    #region Private Helper Methods

    /// <summary>
    /// Builds a TLV object for a specific SCP protocol with its implementations.
    /// </summary>
    private static Result<TlvObject, SmartCardError> BuildScpProtocolTlv(
        byte protocol,
        ImmutableList<ScpImplementation> implementations,
        ImmutableList<KeyTypeAndLength> keyTypes
    )
    {
        // Build TLV components functionally
        var protocolTlvResult = TlvObject.Create(TlvTag.FromByte(0x80), new TlvValue([protocol]));

        var implementationsTlvResult =
            implementations.Count > 0
                ? TlvObject
                    .Create(
                        TlvTag.FromByte(0x81),
                        new TlvValue([.. implementations.Select(impl => (byte)impl)])
                    )
                    .Map(Maybe<TlvObject>.From)
                : Result.Success<Maybe<TlvObject>, SmartCardError>(Maybe<TlvObject>.None);

        var relevantKeyTypes = keyTypes
            .Where(kt => IsKeyTypeRelevantForProtocol(kt, protocol))
            .ToImmutableArray();
        var keyTypesTlvResult =
            relevantKeyTypes.Length > 0
                ? TlvObject
                    .Create(
                        TlvTag.FromByte(0x82),
                        new TlvValue(
                            [
                                .. relevantKeyTypes.SelectMany(kt =>
                                    new byte[] { (byte)kt.Type, (byte)kt.Length }
                                )
                            ]
                        )
                    )
                    .Map(Maybe<TlvObject>.From)
                : Result.Success<Maybe<TlvObject>, SmartCardError>(Maybe<TlvObject>.None);

        // Combine all results functionally
        return protocolTlvResult
            .Bind(protocolTlv =>
                implementationsTlvResult.Bind(implementationsMaybe =>
                    keyTypesTlvResult.Map(
                        (Maybe<TlvObject> keyTypesMaybe) =>
                        {
                            var tlvObjects = new[]
                            {
                                Maybe<TlvObject>.From(protocolTlv),
                                implementationsMaybe,
                                keyTypesMaybe,
                            }
                                .Where(maybe => maybe.HasValue)
                                .Select(maybe => maybe.Value)
                                .ToImmutableArray();
                            return tlvObjects;
                        }
                    )
                )
            )
            .Bind(allTlvs => TlvEncoder.EncodeMultiple(allTlvs))
            .Bind(encoded => TlvObject.Create(TlvTag.FromByte(0xA0), new TlvValue(encoded)));
    }

    /// <summary>
    /// Determines if a key type is relevant for the specified protocol.
    /// </summary>
    private static bool IsKeyTypeRelevantForProtocol(KeyTypeAndLength keyType, byte protocol)
    {
        return protocol switch
        {
            Protocols.SCP02 => keyType.Type == 0x80 || keyType.Type == 0x81 || keyType.Type == 0x82, // DES keys
            Protocols.SCP03 => keyType.Type == 0x88, // AES keys
            _ => false,
        };
    }

    #endregion
}
