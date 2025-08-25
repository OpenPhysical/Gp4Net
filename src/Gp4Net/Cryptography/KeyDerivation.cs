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


    // CalculateCryptogram method removed - use type-safe CryptogramService with Scp02CryptogramParameters/Scp03CryptogramParameters instead
}