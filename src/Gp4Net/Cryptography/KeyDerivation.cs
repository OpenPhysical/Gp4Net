using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;

namespace Gp4Net.Cryptography;

/// <summary>
/// Static facade for key derivation and cryptogram operations.
/// Uses centralized services to eliminate DRY violations.
/// </summary>
public static class KeyDerivation
{
    private static readonly KeyDerivationService _keyDerivationService = new();
    private static readonly CryptogramService _cryptogramService = new();

    /// <summary>
    /// Derives SCP03 session keys using SP 800-108 KDF in counter mode.
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="cardChallenge">The card challenge (8 bytes).</param>
    /// <param name="keyLength">The desired key length in bits.</param>
    /// <returns>The derived session keys or an error.</returns>
    public static Result<SessionKeys, SmartCardError> DeriveScp03SessionKeys(
        Scp03KeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        int keyLength)
    {
        return _keyDerivationService.DeriveSessionKeys(
            keySet,
            hostChallenge,
            cardChallenge);
    }


    /// <summary>
    /// Derives SCP02 session keys.
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="sequenceCounter">The sequence counter (2 or 3 bytes).</param>
    /// <param name="implicitChannel">Whether to use implicit channel mode.</param>
    /// <returns>The derived session keys or an error.</returns>
    public static Result<SessionKeys, SmartCardError> DeriveScp02SessionKeys(
        Scp02KeySet keySet,
        byte[] sequenceCounter,
        bool implicitChannel = false)
    {
        // Create dummy challenges for SCP02 (not used in key derivation but needed for context)
        var hostChallenge = new byte[8];
        var cardChallenge = new byte[6];
        
        return _keyDerivationService.DeriveSessionKeys(
            keySet,
            hostChallenge,
            cardChallenge,
            Maybe<byte[]>.From(sequenceCounter));
    }


    /// <summary>
    /// Calculates a cryptogram for authentication.
    /// </summary>
    /// <param name="key">The key to use for cryptogram calculation.</param>
    /// <param name="data">The data to calculate cryptogram over.</param>
    /// <param name="isScp03">Whether to use SCP03 (AES) or SCP02 (3DES).</param>
    /// <returns>The cryptogram (8 bytes) or an error.</returns>
    public static Result<byte[], SmartCardError> CalculateCryptogram(byte[] key, byte[] data, bool isScp03)
    {
        var protocol = isScp03 ? ScpVersion.Scp03 : ScpVersion.Scp02;
        return _cryptogramService.CalculateCryptogram(key, data, protocol);
    }
}