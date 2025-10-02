using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Provides standard GlobalPlatform test keys (404142434445464748494A4B4C4D4E4F) for testing.
/// Only provides the standard test key - no zero keys, no FF keys, no card-specific diversification.
/// This is a pure test utility for development and testing scenarios.
/// </summary>
[PublicAPI]
public static partial class GpTestKeys
{
    /// <summary>
    /// The standard GlobalPlatform test key (404142434445464748494A4B4C4D4E4F).
    /// This is the official GP test key specified in GP specifications for testing purposes.
    /// Used as ENC, MAC, and DEK keys in test environments.
    /// </summary>
    public static readonly byte[] GpTestKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    /// <summary>
    /// Gets the standard GP test key set for the given protocol version.
    /// Always returns the same test key (404142...4F) for ENC, MAC, and DEK.
    /// </summary>
    /// <param name="protocolVersion">The protocol version (SCP02 or SCP03).</param>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The standard test key set.</returns>
    public static Result<IKeySet, SmartCardError> GetTestKeySet(
        byte protocolVersion,
        byte keyVersion = 0x00
    )
    {
        return protocolVersion switch
        {
            0x02
                => Scp02KeySet
                    .Create(
                        (byte[])GpTestKey.Clone(),
                        (byte[])GpTestKey.Clone(),
                        (byte[])GpTestKey.Clone(),
                        keyVersion
                    )
                    .Map(ks => (IKeySet)ks),
            0x03
                => Scp03KeySet
                    .Create(
                        (byte[])GpTestKey.Clone(),
                        (byte[])GpTestKey.Clone(),
                        (byte[])GpTestKey.Clone(),
                        keyVersion
                    )
                    .Map(ks => (IKeySet)ks),
            _
                => Result.Failure<IKeySet, SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"Unsupported protocol version: {protocolVersion:X2}"
                    )
                ),
        };
    }

    /// <summary>
    /// Gets the standard GP test key set for the given protocol version using ScpVersion enum.
    /// Always returns the same test key (404142...4F) for ENC, MAC, and DEK.
    /// </summary>
    /// <param name="protocolVersion">The protocol version.</param>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The standard test key set.</returns>
    public static Result<IKeySet, SmartCardError> GetTestKeySet(
        ScpVersion protocolVersion,
        byte keyVersion = 0x00
    )
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02
                => Scp02KeySet
                    .Create(
                        (byte[])GpTestKey.Clone(),
                        (byte[])GpTestKey.Clone(),
                        (byte[])GpTestKey.Clone(),
                        keyVersion
                    )
                    .Map(ks => (IKeySet)ks),
            ScpVersion.Scp03
                => Scp03KeySet
                    .Create(
                        (byte[])GpTestKey.Clone(),
                        (byte[])GpTestKey.Clone(),
                        (byte[])GpTestKey.Clone(),
                        keyVersion
                    )
                    .Map(ks => (IKeySet)ks),
            _
                => Result.Failure<IKeySet, SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"Unsupported protocol version: {protocolVersion}"
                    )
                ),
        };
    }

    /// <summary>
    /// Gets the standard GP test key set for the given card response.
    /// Uses the response only for protocol/version info - always returns standard test keys.
    /// </summary>
    /// <param name="cardResponse">The INITIALIZE UPDATE response (optional).</param>
    /// <returns>The standard test key set.</returns>
    public static Result<IKeySet, SmartCardError> GetTestKeys(
        Maybe<InitializeUpdateResponse> cardResponse
    )
    {
        return cardResponse.Match(
            response =>
                response.ScpVersion.Match(
                    scpVersion => GetTestKeySet(scpVersion, response.KeyVersion),
                    () => GetTestKeySet(ScpVersion.Scp02) // Default to SCP02 v00 if ScpVersion is not available
                ),
            () => GetTestKeySet(ScpVersion.Scp02) // Default to SCP02 v00
        );
    }

    /// <summary>
    /// Creates an SCP02 test key set using the standard GP test keys.
    /// </summary>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP02 test key set.</returns>
    public static Result<Scp02KeySet, SmartCardError> CreateScp02TestKeySet(byte keyVersion = 0x00)
    {
        return Scp02KeySet.Create(
            (byte[])GpTestKey.Clone(),
            (byte[])GpTestKey.Clone(),
            (byte[])GpTestKey.Clone(),
            keyVersion
        );
    }

    /// <summary>
    /// Creates an SCP03 test key set using the standard GP test keys.
    /// </summary>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The SCP03 test key set.</returns>
    public static Result<Scp03KeySet, SmartCardError> CreateScp03TestKeySet(byte keyVersion = 0x00)
    {
        return Scp03KeySet.Create(
            (byte[])GpTestKey.Clone(),
            (byte[])GpTestKey.Clone(),
            (byte[])GpTestKey.Clone(),
            keyVersion
        );
    }

    /// <summary>
    /// Creates a protocol-agnostic test key set that can be converted to SCP02 or SCP03
    /// after protocol negotiation with the card.
    /// </summary>
    /// <param name="keyVersion">The key version (default: 0x00).</param>
    /// <returns>The protocol-agnostic test key set.</returns>
    public static Result<RawKeyset, SmartCardError> CreateRawTestKeyset(byte keyVersion = 0x00)
    {
        return RawKeyset.Create(
            (byte[])GpTestKey.Clone(),
            (byte[])GpTestKey.Clone(),
            (byte[])GpTestKey.Clone(),
            keyVersion
        );
    }
}
