using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Protocol-agnostic keyset data that can be converted to SCP02 or SCP03 keysets
/// after protocol negotiation. Supports optional diversification that is applied
/// once card diversification data is available from INITIALIZE UPDATE.
/// </summary>
[PublicAPI]
public sealed record RawKeyset(
    ImmutableArray<byte> EncKey,
    ImmutableArray<byte> MacKey,
    ImmutableArray<byte> DekKey,
    byte KeyVersion,
    Maybe<KeyDiversificationSpec> Diversification
)
{
    /// <summary>
    /// Creates a RawKeyset from byte arrays with validation.
    /// </summary>
    public static Result<RawKeyset, SmartCardError> Create(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion,
        Maybe<KeyDiversificationSpec> diversification = default
    )
    {
        return Maybe<byte[]>
            .From(encKey)
            .ToResult(SmartCardError.InvalidArgument("Encryption key cannot be null"))
            .Bind(enc =>
                Maybe<byte[]>
                    .From(macKey)
                    .ToResult(SmartCardError.InvalidArgument("MAC key cannot be null"))
                    .Bind(mac =>
                        Maybe<byte[]>
                            .From(dekKey)
                            .ToResult(SmartCardError.InvalidArgument("DEK key cannot be null"))
                            .Map(dek => new RawKeyset(
                                [.. enc],
                                [.. mac],
                                [.. dek],
                                keyVersion,
                                diversification
                            ))
                    )
            );
    }

    /// <summary>
    /// Converts to SCP02 keyset.
    /// </summary>
    public Result<Scp02KeySet, SmartCardError> ToScp02KeySet()
    {
        return Scp02KeySet.Create(EncKey.ToArray(), MacKey.ToArray(), DekKey.ToArray(), KeyVersion);
    }

    /// <summary>
    /// Converts to SCP03 keyset.
    /// </summary>
    public Result<Scp03KeySet, SmartCardError> ToScp03KeySet()
    {
        return Scp03KeySet.Create(EncKey.ToArray(), MacKey.ToArray(), DekKey.ToArray(), KeyVersion);
    }

    /// <summary>
    /// Converts to appropriate typed keyset based on negotiated SCP version.
    /// </summary>
    public Result<IKeySet, SmartCardError> ToTypedKeyset(CryptoService.ScpVersion negotiatedVersion)
    {
        return negotiatedVersion switch
        {
            CryptoService.ScpVersion.Scp02 => ToScp02KeySet().Map(ks => (IKeySet)ks),
            CryptoService.ScpVersion.Scp03 => ToScp03KeySet().Map(ks => (IKeySet)ks),
            _
                => Result.Failure<IKeySet, SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported SCP version: {negotiatedVersion}")
                ),
        };
    }

    /// <summary>
    /// Returns a new raw keyset with the specified diversification spec applied.
    /// </summary>
    public RawKeyset WithDiversification(KeyDiversificationSpec spec) =>
        this with
        {
            Diversification = Maybe<KeyDiversificationSpec>.From(spec)
        };
}
