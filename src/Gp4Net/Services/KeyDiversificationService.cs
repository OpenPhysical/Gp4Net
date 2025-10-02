using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// Applies GlobalPlatform key diversification schemes to static key sets.
/// Provides host-side diversification identical to GlobalPlatformPro so traces and
/// live cards can be validated using the same inputs (mother key + KDD).
/// </summary>
[PublicAPI]
public static class KeyDiversificationService
{
    private static readonly IReadOnlyDictionary<string, string> SchemeAliases = new Dictionary<
        string,
        string
    >(StringComparer.OrdinalIgnoreCase)
    {
        ["scp03"] = "scp03",
        ["scp03-default"] = "scp03",
        ["key-derivation-function-3"] = "scp03",
        ["kdf3"] = "scp03",
        ["gp-default"] = "scp03",
        ["emv"] = "emv",
        ["visa"] = "visa",
        ["visa2"] = "visa2",
    };

    private static readonly IReadOnlyDictionary<string, string> Templates = new Dictionary<
        string,
        string
    >(StringComparer.OrdinalIgnoreCase)
    {
        ["emv"] = "$4 $5 $6 $7 $8 $9 0xF0 $k $4 $5 $6 $7 $8 $9 0x0F $k",
        ["visa"] = "$0 $1 $2 $3 $8 $9 0xF0 $k $0 $1 $2 $3 $8 $9 0x0F $k",
        ["visa2"] = "$0 $1 $4 $5 $6 $7 0xF0 $k $0 $1 $4 $5 $6 $7 0x0F $k",
        // GlobalPlatform "Key Derivation Function 3" (KDF3) for SCP03 static keys.
        // See GP Card Specification v2.3.1 Annex D and SCP03 v1.1.1 Section 4.1.5.
        ["scp03"] = "$_ 0x00 0x00 0x00 $k 0x00 $0 $1 $2 $3 $4 $5 $6 $7 $8 $9",
    };

    private enum DiversificationKeyPurpose : byte
    {
        Enc = 0x01,
        Mac = 0x02,
        Dek = 0x03,
    }

    /// <summary>
    /// Creates a diversification spec after validating that the scheme exists.
    /// </summary>
    public static Result<KeyDiversificationSpec, SmartCardError> CreateSpec(string scheme)
    {
        return NormalizeScheme(scheme)
            .Bind(KeyDiversificationSpec.Create)
            .Bind(spec =>
                Templates.ContainsKey(spec.Scheme)
                    ? Result.Success<KeyDiversificationSpec, SmartCardError>(spec)
                    : Result.Failure<KeyDiversificationSpec, SmartCardError>(
                        SmartCardError.Unsupported(
                            $"Unsupported diversification scheme '{scheme}'. Supported schemes: {string.Join(", ", Templates.Keys)}"
                        )
                    )
            );
    }

    private static Result<string, SmartCardError> NormalizeScheme(string scheme)
    {
        if (string.IsNullOrWhiteSpace(scheme))
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument("Diversification scheme cannot be empty")
            );
        }

        var normalized = scheme.Trim().ToLowerInvariant();

        return Result.Success<string, SmartCardError>(
            SchemeAliases.TryGetValue(normalized, out var canonical) ? canonical : normalized
        );
    }

    /// <summary>
    /// Diversifies an SCP03 key set using the provided diversification specification and key diversification data.
    /// Returns the base key set unchanged when no diversification data is available.
    /// </summary>
    public static Result<Scp03KeySet, SmartCardError> DiversifyScp03KeySet(
        Scp03KeySet baseKeySet,
        KeyDiversificationSpec spec,
        byte[] keyDiversificationData
    )
    {
        if (keyDiversificationData is null || keyDiversificationData.Length == 0)
        {
            // No diversification requested
            return Result.Success<Scp03KeySet, SmartCardError>(baseKeySet);
        }

        if (!Templates.TryGetValue(spec.Scheme, out var template))
        {
            return Result.Failure<Scp03KeySet, SmartCardError>(
                SmartCardError.Unsupported(
                    $"Diversification scheme '{spec.Scheme}' is not supported for SCP03"
                )
            );
        }

        return DiversifyKey(
                baseKeySet.EncKey,
                template,
                keyDiversificationData,
                DiversificationKeyPurpose.Enc
            )
            .Bind(enc =>
                DiversifyKey(
                        baseKeySet.MacKey,
                        template,
                        keyDiversificationData,
                        DiversificationKeyPurpose.Mac
                    )
                    .Bind(mac =>
                        DiversifyKey(
                                baseKeySet.DekKey,
                                template,
                                keyDiversificationData,
                                DiversificationKeyPurpose.Dek
                            )
                            .Bind(dek =>
                                Scp03KeySet.Create(
                                    enc,
                                    mac,
                                    dek,
                                    baseKeySet.KeyVersion,
                                    baseKeySet.KeyId
                                )
                            )
                    )
            );
    }

    private static Result<byte[], SmartCardError> DiversifyKey(
        byte[] baseKey,
        string template,
        byte[] kdd,
        DiversificationKeyPurpose purpose
    )
    {
        var normalizedTemplate = NormalizeTemplate(template);
        var expandedTemplate = ExpandTemplate(
            normalizedTemplate,
            kdd,
            (byte)purpose,
            baseKey.Length * 8
        );

        return expandedTemplate.Bind(blocks =>
            CryptoService.KeyDerivation.DeriveScp03Data(
                baseKey,
                blocks.BlockA,
                blocks.BlockB,
                baseKey.Length * 8
            )
        );
    }

    private static string NormalizeTemplate(string template)
    {
        return template
            .ToLowerInvariant()
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("0x", string.Empty, StringComparison.Ordinal);
    }

    private static Result<(byte[] BlockA, byte[] BlockB), SmartCardError> ExpandTemplate(
        string template,
        byte[] kdd,
        byte keyType,
        int outputLengthBits
    )
    {
        var expanded = template;
        for (int i = 0; i < kdd.Length; i++)
        {
            var token = "$" + i.ToString("x", CultureInfo.InvariantCulture);
            expanded = expanded.Replace(
                token,
                kdd[i].ToString("x2", CultureInfo.InvariantCulture),
                StringComparison.Ordinal
            );
        }

        expanded = expanded.Replace(
            "$k",
            keyType.ToString("x2", CultureInfo.InvariantCulture),
            StringComparison.Ordinal
        );

        if (expanded.Contains("$l$l", StringComparison.Ordinal))
        {
            expanded = expanded.Replace(
                "$l$l",
                outputLengthBits.ToString("x4", CultureInfo.InvariantCulture),
                StringComparison.Ordinal
            );
        }

        var parts = expanded.Split("$_", StringSplitOptions.None);
        if (parts.Length > 2)
        {
            return Result.Failure<(byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Diversification template produced unexpected format: '{expanded}'"
                )
            );
        }

        if (parts.Any(segment => segment.Contains('$')))
        {
            return Result.Failure<(byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Diversification template still contains unresolved variables: '{expanded}'"
                )
            );
        }

        var blockAHex = parts.Length > 1 ? parts[0] : string.Empty;
        var blockBHex = parts.Length > 1 ? parts[1] : parts[0];

        var blockAResult = HexToBytes(blockAHex);
        var blockBResult = HexToBytes(blockBHex);

        if (blockAResult.IsFailure)
            return Result.Failure<(byte[], byte[]), SmartCardError>(blockAResult.Error);
        if (blockBResult.IsFailure)
            return Result.Failure<(byte[], byte[]), SmartCardError>(blockBResult.Error);

        return Result.Success<(byte[], byte[]), SmartCardError>(
            (blockAResult.Value, blockBResult.Value)
        );
    }

    private static Result<byte[], SmartCardError> HexToBytes(string hex)
    {
        if (string.IsNullOrEmpty(hex))
            return Result.Success<byte[], SmartCardError>(Array.Empty<byte>());

        if (hex.Length % 2 != 0)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Diversification template produced uneven hex string '{hex}'"
                )
            );
        }

        return Result.Try(
            () => Convert.FromHexString(hex),
            ex =>
                SmartCardError.InvalidArgument(
                    $"Invalid hex in diversification template: {ex.Message}"
                )
        );
    }
}
