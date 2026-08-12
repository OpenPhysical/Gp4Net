using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// Simple keyset resolver implementation that delegates to GpTestKeys for test scenarios.
/// This provides the core functionality needed after removing the facade layers.
/// </summary>
[PublicAPI]
public sealed class KeysetResolver : IKeysetResolver
{
    /// <summary>
    /// Resolves a keyset based on hex string keys.
    /// </summary>
    public Result<IKeySet, SmartCardError> ResolveFromHexKeys(
        string hexEncKey,
        string hexMacKey,
        string hexDekKey,
        byte keyVersion
    )
    {
        return Result
            .Try(
                () => Convert.FromHexString(hexEncKey),
                ex => SmartCardError.InvalidArgument($"Invalid ENC key: {ex.Message}")
            )
            .Bind(encKey =>
                Result
                    .Try(
                        () => Convert.FromHexString(hexMacKey),
                        ex => SmartCardError.InvalidArgument($"Invalid MAC key: {ex.Message}")
                    )
                    .Bind(macKey =>
                        Result
                            .Try(
                                () => Convert.FromHexString(hexDekKey),
                                ex =>
                                    SmartCardError.InvalidArgument($"Invalid DEK key: {ex.Message}")
                            )
                            .Bind(dekKey =>
                                Scp02KeySet
                                    .Create(encKey, macKey, dekKey, keyVersion)
                                    .Map(keySet => (IKeySet)keySet)
                            )
                    )
            );
    }

    /// <summary>
    /// Resolves a keyset from a key identifier for SCP02.
    /// </summary>
    public Result<Scp02KeySet, SmartCardError> ResolveScp02KeySet(string keyId, byte keyVersion)
    {
        return IsTestKeyset(keyId)
            ? GpTestKeys.CreateScp02TestKeySet(keyVersion)
            : Result.Failure<Scp02KeySet, SmartCardError>(UnknownKeyset(keyId));
    }

    /// <summary>
    /// Resolves a keyset from a key identifier for SCP03.
    /// </summary>
    public Result<Scp03KeySet, SmartCardError> ResolveScp03KeySet(string keyId, byte keyVersion)
    {
        return IsTestKeyset(keyId)
            ? GpTestKeys.CreateScp03TestKeySet(keyVersion)
            : Result.Failure<Scp03KeySet, SmartCardError>(UnknownKeyset(keyId));
    }

    /// <summary>
    /// Gets test keys for development and testing purposes.
    /// </summary>
    public Result<IKeySet, SmartCardError> GetTestKeys(byte protocolVersion, byte keyVersion)
    {
        return protocolVersion switch
        {
            0x02 => GpTestKeys.GetTestKeySet(CryptoService.ScpVersion.Scp02, keyVersion),
            0x03 => GpTestKeys.GetTestKeySet(CryptoService.ScpVersion.Scp03, keyVersion),
            _
                => Result.Failure<IKeySet, SmartCardError>(
                    SmartCardError.Unsupported($"Unsupported SCP version: {protocolVersion:X2}")
                ),
        };
    }

    /// <summary>
    /// Legacy ResolveKeyset method for backward compatibility.
    /// This method signature is expected by GlobalPlatformService but was not in the interface.
    /// </summary>
    public Result<IKeySet, SmartCardError> ResolveKeyset(
        string keysetName,
        Dictionary<string, string> parameters,
        Maybe<byte[]> encKey,
        Maybe<byte[]> macKey,
        Maybe<byte[]> dekKey,
        byte keyVersion,
        Maybe<InitializeUpdateResponse> cardResponse
    )
    {
        // GP Card Specification v2.3.1, Section 7.5.1.
        if (!encKey.HasValue && !macKey.HasValue && !dekKey.HasValue && !IsTestKeyset(keysetName))
            return Result.Failure<IKeySet, SmartCardError>(UnknownKeyset(keysetName));

        if (encKey.HasValue != macKey.HasValue || encKey.HasValue != dekKey.HasValue)
            return Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.InvalidArgument("ENC, MAC, and DEK keys must be supplied together")
            );

        var explicitKeysResult = encKey.Bind(enc =>
            macKey.Bind(mac => dekKey.Map(dek => (enc, mac, dek)))
        );

        return explicitKeysResult.Match(
            keyTuple =>
            {
                (byte[] enc, byte[] mac, byte[] dek) = keyTuple;
                // GP Card Specification v2.3.1, Appendix E.2; SCP03 Amendment D v1.1.2, Section 4.1.
                return cardResponse
                    .Bind(response => response.ScpVersion)
                    .ToResult(SmartCardError.InvalidArgument("SCP version is required"))
                    .Bind(protocolVersion =>
                        CreateKeyset(protocolVersion, enc, mac, dek, keyVersion)
                    );
            },
            () =>
            {
                return cardResponse.Match(
                    response =>
                        response.ScpVersion.Match(
                            scpVersion => GetTestKeys((byte)scpVersion, keyVersion),
                            () =>
                                Result.Failure<IKeySet, SmartCardError>(
                                    SmartCardError.InvalidArgument("SCP version is required")
                                )
                        ),
                    () =>
                        Result.Failure<IKeySet, SmartCardError>(
                            SmartCardError.InvalidArgument("INITIALIZE UPDATE response is required")
                        )
                );
            }
        );
    }

    private static Result<IKeySet, SmartCardError> CreateKeyset(
        CryptoService.ScpVersion protocolVersion,
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion
    )
    {
        return protocolVersion switch
        {
            CryptoService.ScpVersion.Scp02
                => Scp02KeySet
                    .Create(encKey, macKey, dekKey, keyVersion)
                    .Map(keyset => (IKeySet)keyset),
            CryptoService.ScpVersion.Scp03
                => Scp03KeySet
                    .Create(encKey, macKey, dekKey, keyVersion)
                    .Map(keyset => (IKeySet)keyset),
            _
                => Result.Failure<IKeySet, SmartCardError>(
                    SmartCardError.Unsupported(
                        $"Unsupported SCP version: {(byte)protocolVersion:X2}"
                    )
                ),
        };
    }

    private static bool IsTestKeyset(string keysetName) =>
        string.Equals(keysetName, "gp_test", StringComparison.OrdinalIgnoreCase);

    private static SmartCardError UnknownKeyset(string keysetName) =>
        SmartCardError.InvalidArgument($"Unknown keyset: {keysetName}");
}
