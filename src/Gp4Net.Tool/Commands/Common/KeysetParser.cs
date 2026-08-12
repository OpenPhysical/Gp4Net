using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoOperations;

namespace Gp4Net.Tool.Commands.Common;

/// <summary>
/// Parses keyset specifications from CLI strings.
/// Converts string formats to byte arrays for the library.
/// </summary>
[PublicAPI]
public static class KeysetParser
{
    /// <summary>
    /// Parses a keyset specification string into a protocol-agnostic RawKeyset.
    /// Use this when the protocol will be negotiated with the card.
    /// Formats:
    /// - "gp_test" -> GP test keys (default if empty)
    /// - "404142..." -> Single hex key for all three
    /// - "404142...:515253...:606162..." -> Three separate hex keys (ENC:MAC:DEK)
    /// </summary>
    /// <param name="keysetSpec">The keyset specification string.</param>
    /// <param name="keyVersion">The key version number.</param>
    /// <returns>A Result containing the parsed RawKeyset or an error.</returns>
    public static Result<RawKeyset, SmartCardError> ParseRawKeysetSpecification(
        string keysetSpec,
        byte keyVersion = 0x00
    )
    {
        // Use existing GP test keys from library
        if (
            string.IsNullOrWhiteSpace(keysetSpec)
            || keysetSpec.Equals("gp_test", StringComparison.OrdinalIgnoreCase)
        )
            return GpTestKeys.CreateRawTestKeyset(keyVersion);

        // Detect diversification-based specification (scheme:first[:second...])
        var diversificationParsed = TryParseDiversifiedRawKeyset(keysetSpec, keyVersion);
        if (diversificationParsed.IsFailure)
        {
            if (diversificationParsed.Error.HasValue)
                return Result.Failure<RawKeyset, SmartCardError>(diversificationParsed.Error.Value);
        }
        else if (diversificationParsed.Value.HasValue)
        {
            return Result.Success<RawKeyset, SmartCardError>(diversificationParsed.Value.Value);
        }

        // Check for three-key format (ENC:MAC:DEK)
        if (keysetSpec.Contains(':'))
            return ParseRawThreeKeyFormat(keysetSpec, keyVersion);

        // Single hex key
        return ParseRawSingleKeyFormat(keysetSpec, keyVersion);
    }

    /// <summary>
    /// Parses a keyset specification string into a protocol-specific keyset.
    /// Use this when you know the protocol in advance.
    /// Formats:
    /// - "gp_test" -> GP test keys (default if empty)
    /// - "404142..." -> Single hex key for all three
    /// - "404142...:515253...:606162..." -> Three separate hex keys (ENC:MAC:DEK)
    /// </summary>
    /// <param name="keysetSpec">The keyset specification string.</param>
    /// <param name="scpVersion">The SCP protocol version.</param>
    /// <param name="keyVersion">The key version number.</param>
    /// <returns>A Result containing the parsed keyset or an error.</returns>
    public static Result<IKeySet, SmartCardError> ParseKeysetSpecification(
        string keysetSpec,
        ScpVersion scpVersion,
        byte keyVersion = 0x00
    )
    {
        // Use existing GP test keys from library
        if (
            string.IsNullOrWhiteSpace(keysetSpec)
            || keysetSpec.Equals("gp_test", StringComparison.OrdinalIgnoreCase)
        )
            return GpTestKeys.GetTestKeySet(scpVersion, keyVersion);

        // Diversification-based specification support
        var diversificationParsed = TryParseDiversifiedRawKeyset(keysetSpec, keyVersion);
        if (diversificationParsed.IsFailure)
        {
            if (diversificationParsed.Error.HasValue)
                return Result.Failure<IKeySet, SmartCardError>(diversificationParsed.Error.Value);
        }
        else if (diversificationParsed.Value.HasValue)
        {
            return diversificationParsed.Value.Value.ToTypedKeyset(scpVersion);
        }

        // Check for three-key format (ENC:MAC:DEK)
        if (keysetSpec.Contains(':'))
            return ParseThreeKeyFormat(keysetSpec, scpVersion, keyVersion);

        // Single hex key
        return ParseSingleKeyFormat(keysetSpec, scpVersion, keyVersion);
    }

    private static Result<Maybe<RawKeyset>, Maybe<SmartCardError>> TryParseDiversifiedRawKeyset(
        string spec,
        byte keyVersion
    )
    {
        var firstColon = spec.IndexOf(':');
        if (firstColon <= 0)
        {
            return Result.Success<Maybe<RawKeyset>, Maybe<SmartCardError>>(Maybe<RawKeyset>.None);
        }

        var schemeCandidate = spec[..firstColon];
        var rest = spec[(firstColon + 1)..];

        var specResult = KeyDiversification.CreateSpec(schemeCandidate);
        if (specResult.IsFailure)
        {
            // Not a recognized diversification scheme - fall back to standard parsing
            return Result.Success<Maybe<RawKeyset>, Maybe<SmartCardError>>(Maybe<RawKeyset>.None);
        }

        // Parse the remainder using existing helpers (single or three key formats)
        Result<RawKeyset, SmartCardError> baseKeysResult = rest.Contains(':')
            ? ParseRawThreeKeyFormat(rest, keyVersion)
            : ParseRawSingleKeyFormat(rest, keyVersion);

        if (baseKeysResult.IsFailure)
        {
            return Result.Failure<Maybe<RawKeyset>, Maybe<SmartCardError>>(
                Maybe<SmartCardError>.From(baseKeysResult.Error)
            );
        }

        var diversified = baseKeysResult.Value.WithDiversification(specResult.Value);
        return Result.Success<Maybe<RawKeyset>, Maybe<SmartCardError>>(
            Maybe<RawKeyset>.From(diversified)
        );
    }

    private static Result<RawKeyset, SmartCardError> ParseRawThreeKeyFormat(
        string spec,
        byte keyVersion
    )
    {
        var parts = spec.Split(':');
        if (parts.Length != 3)
            return Result.Failure<RawKeyset, SmartCardError>(
                SmartCardError.InvalidArgument(
                    "Three-key format must be ENC:MAC:DEK (e.g., 404142...:505152...:606162...)"
                )
            );

        return Result
            .Try(
                () =>
                    new
                    {
                        Enc = Convert.FromHexString(parts[0]),
                        Mac = Convert.FromHexString(parts[1]),
                        Dek = Convert.FromHexString(parts[2])
                    },
                ex => SmartCardError.InvalidArgument($"Invalid hex in keyset: {ex.Message}")
            )
            .Bind(keys => Keysets.CreateRawFromThreeKeys(keys.Enc, keys.Mac, keys.Dek, keyVersion));
    }

    private static Result<RawKeyset, SmartCardError> ParseRawSingleKeyFormat(
        string hexKey,
        byte keyVersion
    )
    {
        return Result
            .Try(
                () => Convert.FromHexString(hexKey),
                ex => SmartCardError.InvalidArgument($"Invalid hex key: {ex.Message}")
            )
            .Bind(key => Keysets.CreateRawFromSingleKey(key, keyVersion));
    }

    private static Result<IKeySet, SmartCardError> ParseThreeKeyFormat(
        string spec,
        ScpVersion scpVersion,
        byte keyVersion
    )
    {
        var parts = spec.Split(':');
        if (parts.Length != 3)
            return Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.InvalidArgument(
                    "Three-key format must be ENC:MAC:DEK (e.g., 404142...:505152...:606162...)"
                )
            );

        return Result
            .Try(
                () =>
                    new
                    {
                        Enc = Convert.FromHexString(parts[0]),
                        Mac = Convert.FromHexString(parts[1]),
                        Dek = Convert.FromHexString(parts[2])
                    },
                ex => SmartCardError.InvalidArgument($"Invalid hex in keyset: {ex.Message}")
            )
            .Bind(keys =>
                Keysets.CreateFromThreeKeys(keys.Enc, keys.Mac, keys.Dek, scpVersion, keyVersion)
            );
    }

    private static Result<IKeySet, SmartCardError> ParseSingleKeyFormat(
        string hexKey,
        ScpVersion scpVersion,
        byte keyVersion
    )
    {
        return Result
            .Try(
                () => Convert.FromHexString(hexKey),
                ex => SmartCardError.InvalidArgument($"Invalid hex key: {ex.Message}")
            )
            .Bind(key => Keysets.CreateFromSingleKey(key, scpVersion, keyVersion));
    }
}
