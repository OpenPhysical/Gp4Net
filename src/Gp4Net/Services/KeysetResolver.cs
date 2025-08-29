using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
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
        byte keyVersion)
    {
        return Result.Try(() => Convert.FromHexString(hexEncKey), ex => SmartCardError.InvalidArgument($"Invalid ENC key: {ex.Message}"))
            .Bind(encKey => Result.Try(() => Convert.FromHexString(hexMacKey), ex => SmartCardError.InvalidArgument($"Invalid MAC key: {ex.Message}"))
                .Bind(macKey => Result.Try(() => Convert.FromHexString(hexDekKey), ex => SmartCardError.InvalidArgument($"Invalid DEK key: {ex.Message}"))
                    .Bind(dekKey => Scp02KeySet.Create(encKey, macKey, dekKey, keyVersion)
                        .Map(keySet => (IKeySet)keySet))));
    }

    /// <summary>
    /// Resolves a keyset from a key identifier for SCP02.
    /// </summary>
    public Result<Scp02KeySet, SmartCardError> ResolveScp02KeySet(string keyId, byte keyVersion)
    {
        // For simplicity, delegate to test keys
        return GpTestKeys.CreateScp02TestKeySet(keyVersion);
    }

    /// <summary>
    /// Resolves a keyset from a key identifier for SCP03.
    /// </summary>
    public Result<Scp03KeySet, SmartCardError> ResolveScp03KeySet(string keyId, byte keyVersion)
    {
        // For simplicity, delegate to test keys
        return GpTestKeys.CreateScp03TestKeySet(keyVersion);
    }

    /// <summary>
    /// Gets test keys for development and testing purposes.
    /// </summary>
    public Result<IKeySet, SmartCardError> GetTestKeys(byte protocolVersion, byte keyVersion)
    {
        ScpVersion scpVersion = protocolVersion switch
        {
            0x02 => ScpVersion.Scp02,
            0x03 => ScpVersion.Scp03,
            _ => ScpVersion.Scp02 // Default fallback
        };
        return GpTestKeys.GetTestKeySet(scpVersion, keyVersion);
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
        Maybe<InitializeUpdateResponse> cardResponse)
    {
        // Check if all explicit keys are provided
        Maybe<(byte[] enc, byte[] mac, byte[] dek)> explicitKeysResult = encKey
            .Bind(enc => macKey
                .Bind(mac => dekKey
                    .Map(dek => (enc, mac, dek))));

        return explicitKeysResult.Match(
            keyTuple =>
            {
                (byte[] enc, byte[] mac, byte[] dek) = keyTuple;
                return ResolveFromHexKeys(
                    Convert.ToHexString(enc),
                    Convert.ToHexString(mac), 
                    Convert.ToHexString(dek),
                    keyVersion);
            },
            () =>
            {
                // Use test keys based on card response if available
                return cardResponse.Match(
                    response => response.ScpId.Match(
                        scpVersion => GetTestKeys((byte)scpVersion, keyVersion),
                        () => GetTestKeys(0x02, keyVersion)),
                    () => GetTestKeys(0x02, keyVersion) // Fallback to SCP02 test keys
                );
            }
        );
    }
}