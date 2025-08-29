using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.CardEmulator.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Persistence;

/// <summary>
/// Interface for card persistence key derivation service.
/// Provides secure key derivation from GlobalPlatform key sets for storage encryption.
/// Supports all SCP02/SCP03 variations with comprehensive key material incorporation.
/// </summary>
[PublicAPI]
public interface ICardPersistenceKeyService
{
    /// <summary>
    /// Derives storage encryption key from ISD keys and card UUID.
    /// Uses KDF108 in counter mode with all available key material.
    /// K1 (KIN) = ENC key, K2 (MAC) and K3 (DEK) encoded in context as secret inputs.
    /// </summary>
    /// <param name="keySet">ISD key set (SCP02 or SCP03).</param>
    /// <param name="cardUuid">Card-specific UUID.</param>
    /// <returns>Derived 256-bit encryption key or error.</returns>
    Result<byte[], SmartCardError> DeriveStorageKey(IKeySet keySet, CardUuid cardUuid);

    /// <summary>
    /// Generates cryptographically secure card UUID.
    /// </summary>
    /// <returns>New card UUID or error.</returns>
    Result<CardUuid, SmartCardError> GenerateCardUuid();

    /// <summary>
    /// Validates key fingerprint for integrity checking.
    /// Computes SHA-256 hash of concatenated key material.
    /// </summary>
    /// <param name="keySet">Key set to validate.</param>
    /// <param name="fingerprint">Expected fingerprint.</param>
    /// <returns>Validation result or error.</returns>
    Result<bool, SmartCardError> ValidateKeyFingerprint(IKeySet keySet, byte[] fingerprint);

    /// <summary>
    /// Computes key fingerprint for a key set.
    /// Used for integrity verification in persistence metadata.
    /// </summary>
    /// <param name="keySet">Key set to fingerprint.</param>
    /// <returns>SHA-256 fingerprint or error.</returns>
    Result<byte[], SmartCardError> ComputeKeyFingerprint(IKeySet keySet);
}