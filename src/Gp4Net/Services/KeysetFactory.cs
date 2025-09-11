using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Services;

/// <summary>
/// Factory for creating keysets from byte arrays.
/// Pure functional - no string parsing, only byte array operations.
/// </summary>
[PublicAPI]
public static class KeysetFactory
{
    /// <summary>
    /// Creates a protocol-agnostic RawKeyset from a single key (used for all three: ENC, MAC, DEK).
    /// Use this when the protocol will be negotiated with the card.
    /// </summary>
    /// <param name="key">The key bytes to use for all three key types.</param>
    /// <param name="keyVersion">The key version number.</param>
    /// <returns>A Result containing the created RawKeyset or an error.</returns>
    public static Result<RawKeyset, SmartCardError> CreateRawFromSingleKey(
        byte[] key,
        byte keyVersion = 0x00)
    {
        if (key.Length == 0)
            return SmartCardError.InvalidArgument("Key cannot be empty");
            
        // Clone for immutability
        var encKey = (byte[])key.Clone();
        var macKey = (byte[])key.Clone();
        var dekKey = (byte[])key.Clone();
        
        return RawKeyset.Create(encKey, macKey, dekKey, keyVersion);
    }
    
    /// <summary>
    /// Creates a protocol-agnostic RawKeyset from three separate keys.
    /// Use this when the protocol will be negotiated with the card.
    /// </summary>
    /// <param name="encKey">The encryption key.</param>
    /// <param name="macKey">The MAC key.</param>
    /// <param name="dekKey">The data encryption key.</param>
    /// <param name="keyVersion">The key version number.</param>
    /// <returns>A Result containing the created RawKeyset or an error.</returns>
    public static Result<RawKeyset, SmartCardError> CreateRawFromThreeKeys(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion = 0x00)
    {
        return RawKeyset.Create(encKey, macKey, dekKey, keyVersion);
    }
    
    /// <summary>
    /// Creates a protocol-specific keyset from a single key (used for all three: ENC, MAC, DEK).
    /// Use this when you know the protocol in advance.
    /// </summary>
    /// <param name="key">The key bytes to use for all three key types.</param>
    /// <param name="scpVersion">The SCP protocol version.</param>
    /// <param name="keyVersion">The key version number.</param>
    /// <returns>A Result containing the created keyset or an error.</returns>
    public static Result<IKeySet, SmartCardError> CreateFromSingleKey(
        byte[] key,
        ScpVersion scpVersion,
        byte keyVersion = 0x00)
    {
        if (key.Length == 0)
            return SmartCardError.InvalidArgument("Key cannot be empty");
            
        // Clone for immutability
        var encKey = (byte[])key.Clone();
        var macKey = (byte[])key.Clone();
        var dekKey = (byte[])key.Clone();
        
        return CreateFromThreeKeys(encKey, macKey, dekKey, scpVersion, keyVersion);
    }
    
    /// <summary>
    /// Creates a protocol-specific keyset from three separate keys.
    /// Use this when you know the protocol in advance.
    /// </summary>
    /// <param name="encKey">The encryption key.</param>
    /// <param name="macKey">The MAC key.</param>
    /// <param name="dekKey">The data encryption key.</param>
    /// <param name="scpVersion">The SCP protocol version.</param>
    /// <param name="keyVersion">The key version number.</param>
    /// <returns>A Result containing the created keyset or an error.</returns>
    public static Result<IKeySet, SmartCardError> CreateFromThreeKeys(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        ScpVersion scpVersion,
        byte keyVersion = 0x00)
    {
        return scpVersion switch
        {
            ScpVersion.Scp02 => Scp02KeySet.Create(encKey, macKey, dekKey, keyVersion)
                .Map(ks => (IKeySet)ks),
            ScpVersion.Scp03 => Scp03KeySet.Create(encKey, macKey, dekKey, keyVersion)
                .Map(ks => (IKeySet)ks),
            _ => Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.Unsupported($"SCP version: {scpVersion}"))
        };
    }
}