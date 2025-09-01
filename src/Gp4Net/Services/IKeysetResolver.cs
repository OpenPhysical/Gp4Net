using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// Interface for resolving keysets based on various input parameters.
/// Provides functional key resolution for different authentication scenarios.
/// </summary>
[PublicAPI]
public interface IKeysetResolver
{
    /// <summary>
    /// Resolves a keyset based on hex string keys.
    /// </summary>
    /// <param name="hexEncKey">The encryption key as hex string.</param>
    /// <param name="hexMacKey">The MAC key as hex string.</param>
    /// <param name="hexDekKey">The DEK key as hex string.</param>
    /// <param name="keyVersion">The key version.</param>
    /// <returns>The resolved keyset or error.</returns>
    Result<IKeySet, SmartCardError> ResolveFromHexKeys(
        string hexEncKey,
        string hexMacKey,
        string hexDekKey,
        byte keyVersion
    );

    /// <summary>
    /// Resolves a keyset from a key identifier for SCP02.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="keyVersion">The key version.</param>
    /// <returns>The resolved SCP02 keyset or error.</returns>
    Result<Scp02KeySet, SmartCardError> ResolveScp02KeySet(string keyId, byte keyVersion);

    /// <summary>
    /// Resolves a keyset from a key identifier for SCP03.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="keyVersion">The key version.</param>
    /// <returns>The resolved SCP03 keyset or error.</returns>
    Result<Scp03KeySet, SmartCardError> ResolveScp03KeySet(string keyId, byte keyVersion);

    /// <summary>
    /// Gets test keys for development and testing purposes.
    /// </summary>
    /// <param name="protocolVersion">The protocol version (0x02 or 0x03).</param>
    /// <param name="keyVersion">The key version.</param>
    /// <returns>The test keyset or error.</returns>
    Result<IKeySet, SmartCardError> GetTestKeys(byte protocolVersion, byte keyVersion);

    /// <summary>
    /// Legacy ResolveKeyset method for backward compatibility.
    /// </summary>
    /// <param name="keysetName">The keyset name.</param>
    /// <param name="parameters">Additional parameters.</param>
    /// <param name="encKey">Optional explicit encryption key.</param>
    /// <param name="macKey">Optional explicit MAC key.</param>
    /// <param name="dekKey">Optional explicit DEK key.</param>
    /// <param name="keyVersion">The key version.</param>
    /// <param name="cardResponse">Optional card response for diversification.</param>
    /// <returns>The resolved keyset or error.</returns>
    Result<IKeySet, SmartCardError> ResolveKeyset(
        string keysetName,
        Dictionary<string, string> parameters,
        Maybe<byte[]> encKey,
        Maybe<byte[]> macKey,
        Maybe<byte[]> dekKey,
        byte keyVersion,
        Maybe<InitializeUpdateResponse> cardResponse
    );
}
