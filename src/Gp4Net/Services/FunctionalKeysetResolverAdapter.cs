using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// Adapter class that implements IKeysetResolver interface using the functional implementation.
/// Provides a bridge between the DI container and the functional keyset resolution logic.
/// </summary>
[PublicAPI]
public sealed class FunctionalKeysetResolverAdapter : IKeysetResolver
{
    private readonly KeysetResolver _functionalResolver;

    /// <summary>
    /// Initializes a new instance of the FunctionalKeysetResolverAdapter class.
    /// </summary>
    public FunctionalKeysetResolverAdapter()
    {
        _functionalResolver = new KeysetResolver();
    }

    /// <inheritdoc />
    public Result<IKeySet, SmartCardError> ResolveFromHexKeys(
        string hexEncKey,
        string hexMacKey,
        string hexDekKey,
        byte keyVersion
    )
    {
        return _functionalResolver.ResolveFromHexKeys(hexEncKey, hexMacKey, hexDekKey, keyVersion);
    }

    /// <inheritdoc />
    public Result<Scp02KeySet, SmartCardError> ResolveScp02KeySet(string keyId, byte keyVersion)
    {
        return _functionalResolver.ResolveScp02KeySet(keyId, keyVersion);
    }

    /// <inheritdoc />
    public Result<Scp03KeySet, SmartCardError> ResolveScp03KeySet(string keyId, byte keyVersion)
    {
        return _functionalResolver.ResolveScp03KeySet(keyId, keyVersion);
    }

    /// <inheritdoc />
    public Result<IKeySet, SmartCardError> GetTestKeys(byte protocolVersion, byte keyVersion)
    {
        return _functionalResolver.GetTestKeys(protocolVersion, keyVersion);
    }

    /// <inheritdoc />
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
        return _functionalResolver.ResolveKeyset(
            keysetName,
            parameters,
            encKey,
            macKey,
            dekKey,
            keyVersion,
            cardResponse
        );
    }
}
