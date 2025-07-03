using System;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional
{
    /// <summary>
    /// Interface for cryptographic operations used by virtual cards.
    /// Allows for testing with mocked implementations while supporting real crypto.
    /// </summary>
    [PublicAPI]
    public interface ICryptographicService
    {
        /// <summary>
        /// Generates a random challenge of the specified length.
        /// </summary>
        /// <param name="length">The length of the challenge in bytes.</param>
        /// <returns>A random challenge.</returns>
        Result<byte[], SmartCardError> GenerateChallenge(int length);

        /// <summary>
        /// Calculates a card cryptogram for INITIALIZE UPDATE response.
        /// </summary>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="cardChallenge">The card challenge.</param>
        /// <param name="keys">The key set to use.</param>
        /// <param name="scpVersion">The SCP version.</param>
        /// <returns>The calculated cryptogram.</returns>
        Result<byte[], SmartCardError> CalculateCardCryptogram(
            byte[] hostChallenge,
            byte[] cardChallenge,
            IKeySet keys,
            byte scpVersion);

        /// <summary>
        /// Calculates a host cryptogram for EXTERNAL AUTHENTICATE verification.
        /// </summary>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="cardChallenge">The card challenge.</param>
        /// <param name="keys">The key set to use.</param>
        /// <param name="scpVersion">The SCP version.</param>
        /// <returns>The calculated cryptogram.</returns>
        Result<byte[], SmartCardError> CalculateHostCryptogram(
            byte[] hostChallenge,
            byte[] cardChallenge,
            IKeySet keys,
            byte scpVersion);

        /// <summary>
        /// Verifies that two cryptograms match.
        /// </summary>
        /// <param name="received">The received cryptogram.</param>
        /// <param name="expected">The expected cryptogram.</param>
        /// <returns>True if the cryptograms match.</returns>
        Result<bool, SmartCardError> VerifyCryptogram(byte[] received, byte[] expected);

        /// <summary>
        /// Derives session keys from master keys.
        /// </summary>
        /// <param name="masterKeys">The master key set.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="cardChallenge">The card challenge.</param>
        /// <param name="scpVersion">The SCP version.</param>
        /// <returns>The derived session keys.</returns>
        Result<SessionKeys, SmartCardError> DeriveSessionKeys(
            IKeySet masterKeys,
            byte[] hostChallenge,
            byte[] cardChallenge,
            byte scpVersion);
    }

    /// <summary>
    /// Session keys derived during secure channel establishment.
    /// </summary>
    public record SessionKeys(
        byte[] EncryptionKey,
        byte[] MacKey,
        byte[] DataEncryptionKey
    );

    /// <summary>
    /// Test implementation of cryptographic service for unit testing.
    /// Returns predictable results for testing scenarios.
    /// </summary>
    [PublicAPI]
    public class TestCryptographicService : ICryptographicService
    {
        private readonly Random _random = new(42); // Deterministic for testing

        public Result<byte[], SmartCardError> GenerateChallenge(int length)
        {
            var challenge = new byte[length];
            _random.NextBytes(challenge);
            return new Result<byte[], SmartCardError>.Success(challenge);
        }

        public Result<byte[], SmartCardError> CalculateCardCryptogram(
            byte[] hostChallenge,
            byte[] cardChallenge,
            IKeySet keys,
            byte scpVersion)
        {
            // Simplified test cryptogram - just XOR challenges
            var cryptogram = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                cryptogram[i] = (byte)(hostChallenge[i] ^ cardChallenge[i]);
            }
            return new Result<byte[], SmartCardError>.Success(cryptogram);
        }

        public Result<byte[], SmartCardError> CalculateHostCryptogram(
            byte[] hostChallenge,
            byte[] cardChallenge,
            IKeySet keys,
            byte scpVersion)
        {
            // Simplified test cryptogram - reverse XOR
            var cryptogram = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                cryptogram[i] = (byte)(cardChallenge[i] ^ hostChallenge[i]);
            }
            return new Result<byte[], SmartCardError>.Success(cryptogram);
        }

        public Result<bool, SmartCardError> VerifyCryptogram(byte[] received, byte[] expected)
        {
            var matches = received.Length == expected.Length;
            if (matches)
            {
                for (int i = 0; i < received.Length; i++)
                {
                    if (received[i] != expected[i])
                    {
                        matches = false;
                        break;
                    }
                }
            }
            return new Result<bool, SmartCardError>.Success(matches);
        }

        public Result<SessionKeys, SmartCardError> DeriveSessionKeys(
            IKeySet masterKeys,
            byte[] hostChallenge,
            byte[] cardChallenge,
            byte scpVersion)
        {
            // Simplified test session keys
            var sessionKeys = new SessionKeys(
                EncryptionKey: new byte[16], // All zeros for testing
                MacKey: new byte[16],
                DataEncryptionKey: new byte[16]
            );
            return new Result<SessionKeys, SmartCardError>.Success(sessionKeys);
        }
    }

    /// <summary>
    /// Mock implementation that always fails for testing error conditions.
    /// </summary>
    [PublicAPI]
    public class FailingCryptographicService : ICryptographicService
    {
        public Result<byte[], SmartCardError> GenerateChallenge(int length) =>
            new Result<byte[], SmartCardError>.Failure(SmartCardError.CryptographicError("Mock failure"));

        public Result<byte[], SmartCardError> CalculateCardCryptogram(
            byte[] hostChallenge,
            byte[] cardChallenge,
            IKeySet keys,
            byte scpVersion) =>
            new Result<byte[], SmartCardError>.Failure(SmartCardError.CryptographicError("Mock failure"));

        public Result<byte[], SmartCardError> CalculateHostCryptogram(
            byte[] hostChallenge,
            byte[] cardChallenge,
            IKeySet keys,
            byte scpVersion) =>
            new Result<byte[], SmartCardError>.Failure(SmartCardError.CryptographicError("Mock failure"));

        public Result<bool, SmartCardError> VerifyCryptogram(byte[] received, byte[] expected) =>
            new Result<bool, SmartCardError>.Failure(SmartCardError.CryptographicError("Mock failure"));

        public Result<SessionKeys, SmartCardError> DeriveSessionKeys(
            IKeySet masterKeys,
            byte[] hostChallenge,
            byte[] cardChallenge,
            byte scpVersion) =>
            new Result<SessionKeys, SmartCardError>.Failure(SmartCardError.CryptographicError("Mock failure"));
    }
}