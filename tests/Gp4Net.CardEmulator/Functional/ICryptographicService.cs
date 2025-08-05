using System;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;

namespace Gp4Net.CardEmulator.Functional;

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
    /// Generates a pseudo-random challenge using KDF as specified in SCP03 section 6.2.2.1.
    /// For SCP03 i=70 mode, the challenge is derived using Key-ENC with derivation constant 0x02.
    /// </summary>
    /// <param name="keyEnc">The static Key-ENC for derivation.</param>
    /// <param name="sequenceCounter">The 3-byte sequence counter.</param>
    /// <param name="aid">The application identifier (AID).</param>
    /// <param name="length">The length of the challenge in bytes (typically 8).</param>
    /// <returns>A pseudo-random challenge derived using KDF.</returns>
    Result<byte[], SmartCardError> GeneratePseudoRandomChallenge(
        byte[] keyEnc,
        byte[] sequenceCounter,
        byte[] aid,
        int length);

    /// <summary>
    /// Calculates a card cryptogram for INITIALIZE UPDATE response.
    /// </summary>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="cardChallenge">The card challenge (6 bytes for SCP02, 8 bytes for SCP03).</param>
    /// <param name="keys">The key set to use.</param>
    /// <param name="scpVersion">The SCP version.</param>
    /// <param name="implementationParameter">The SCP implementation parameter (for SCP02).</param>
    /// <param name="sequenceCounter">The sequence counter for SCP02 (2 bytes), empty for SCP03.</param>
    /// <returns>The calculated cryptogram.</returns>
    Result<byte[], SmartCardError> CalculateCardCryptogram(
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet keys,
        byte scpVersion,
        byte implementationParameter,
        Maybe<byte[]> sequenceCounter);

    /// <summary>
    /// Calculates a host cryptogram for EXTERNAL AUTHENTICATE verification.
    /// </summary>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="cardChallenge">The card challenge (6 bytes for SCP02, 8 bytes for SCP03).</param>
    /// <param name="keys">The key set to use.</param>
    /// <param name="scpVersion">The SCP version.</param>
    /// <param name="implementationParameter">The SCP implementation parameter (for SCP02).</param>
    /// <param name="sequenceCounter">The sequence counter for SCP02 (2 bytes), empty for SCP03.</param>
    /// <returns>The calculated cryptogram.</returns>
    Result<byte[], SmartCardError> CalculateHostCryptogram(
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet keys,
        byte scpVersion,
        byte implementationParameter,
        Maybe<byte[]> sequenceCounter);

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
    Result<Gp4Net.Domain.Keys.SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet masterKeys,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte scpVersion);

    /// <summary>
    /// Applies response security (R-MAC and/or R-ENCRYPTION) to a response.
    /// </summary>
    /// <param name="responseData">The response data including status word.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="macChainingValue">The current MAC chaining value.</param>
    /// <param name="encryptionCounter">The current encryption counter.</param>
    /// <param name="scpVersion">The SCP version.</param>
    /// <param name="securityLevel">The security level specifying which security to apply.</param>
    /// <returns>The secured response data and updated state.</returns>
    Result<(byte[] securedData, CardState newState), SmartCardError> ApplyResponseSecurity(
        byte[] responseData,
        Gp4Net.Domain.Keys.SessionKeys sessionKeys,
        byte[] macChainingValue,
        uint encryptionCounter,
        byte scpVersion,
        byte securityLevel,
        CardState currentState);

    /// <summary>
    /// Calculates AES-CMAC over the provided data.
    /// </summary>
    /// <param name="key">The AES key to use for MAC calculation.</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <returns>The calculated 16-byte AES-CMAC.</returns>
    Result<byte[], SmartCardError> CalculateAesCmac(byte[] key, byte[] data);
}

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
        return Result.Success<byte[], SmartCardError>(challenge);
    }

    public Result<byte[], SmartCardError> GeneratePseudoRandomChallenge(
        byte[] keyEnc,
        byte[] sequenceCounter,
        byte[] aid,
        int length)
    {
        try
        {
            // SCP03 pseudo-random challenge generation as per section 6.2.2.1
            // Context = sequenceCounter || AID
            var context = new byte[sequenceCounter.Length + aid.Length];
            Array.Copy(sequenceCounter, 0, context, 0, sequenceCounter.Length);
            Array.Copy(aid, 0, context, sequenceCounter.Length, aid.Length);

            // Build the "fixed input data" for KDF
            var fixedInputBeforeCounter = new byte[11 + 1 + 1 + 2]; // Label + derivation + separator + L
            var offset = 0;

            // Label (11 bytes of 0x00 followed by derivation constant)
            Array.Copy(DerivationConstants.Scp03Label, 0, fixedInputBeforeCounter, offset, 11);
            offset += 11;
            fixedInputBeforeCounter[offset++] = DerivationConstants.CardChallenge; // 0x02

            // Separator
            fixedInputBeforeCounter[offset++] = 0x00;

            // L (length in bits as 2-byte big-endian)
            var lengthBits = length * 8;
            fixedInputBeforeCounter[offset++] = (byte)(lengthBits >> 8);
            fixedInputBeforeCounter[offset++] = (byte)lengthBits;

            // Determine PRF type based on key length
            var prfType = keyEnc.Length switch
            {
                16 => PrfType.CmacAes128,
                24 => PrfType.CmacAes192,
                32 => PrfType.CmacAes256,
                _ => throw new ArgumentException($"Unsupported key length: {keyEnc.Length} bytes"),
            };

            // Configure KDF options for SCP03
            var options = new KdfOptions(
                prfType: prfType,
                counterLengthBits: 8, // SCP03 uses 8-bit counter
                useCounter: true,
                counterLocation: CounterLocation.MiddleFixed // Counter in the middle of fixed input
            );

            var kdf = new CounterModeKdf();
                
            // Use DeriveWithSplitFixedInput:
            // - fixedInputBeforeCounter goes before the counter
            // - context goes after the counter
            var challenge = kdf.DeriveWithSplitFixedInput(
                keyEnc,
                fixedInputBeforeCounter, // Label + derivation + separator + L
                context, // sequenceCounter || AID
                lengthBits,
                options
            );

            return Result.Success<byte[], SmartCardError>(challenge);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"Failed to generate pseudo-random challenge: {ex.Message}"));
        }
    }

    public Result<byte[], SmartCardError> CalculateCardCryptogram(
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet keys,
        byte scpVersion,
        byte implementationParameter,
        Maybe<byte[]> sequenceCounter)
    {
        // Simplified test cryptogram - just XOR challenges
        var cryptogram = new byte[8];
        for (var i = 0; i < 8; i++)
        {
            cryptogram[i] = (byte)(hostChallenge[i] ^ cardChallenge[i % cardChallenge.Length]);
        }
        return Result.Success<byte[], SmartCardError>(cryptogram);
    }

    public Result<byte[], SmartCardError> CalculateHostCryptogram(
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet keys,
        byte scpVersion,
        byte implementationParameter,
        Maybe<byte[]> sequenceCounter)
    {
        // Simplified test cryptogram - reverse XOR
        var cryptogram = new byte[8];
        for (var i = 0; i < 8; i++)
        {
            cryptogram[i] = (byte)(cardChallenge[i % cardChallenge.Length] ^ hostChallenge[i]);
        }
        return Result.Success<byte[], SmartCardError>(cryptogram);
    }

    public Result<bool, SmartCardError> VerifyCryptogram(byte[] received, byte[] expected)
    {
        var matches = received.Length == expected.Length;
        if (matches)
        {
            for (var i = 0; i < received.Length; i++)
            {
                if (received[i] != expected[i])
                {
                    matches = false;
                    break;
                }
            }
        }
        return Result.Success<bool, SmartCardError>(matches);
    }

    public Result<Gp4Net.Domain.Keys.SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet masterKeys,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte scpVersion)
    {
        // Simplified test session keys
        var sessionKeys = new Gp4Net.Domain.Keys.SessionKeys(
            sEnc: new byte[16], // All zeros for testing
            sMac: new byte[16],
            sRMac: new byte[16],
            dek: new byte[16]
        );
        return Result.Success<Gp4Net.Domain.Keys.SessionKeys, SmartCardError>(sessionKeys);
    }

    public Result<(byte[] securedData, CardState newState), SmartCardError> ApplyResponseSecurity(
        byte[] responseData,
        Gp4Net.Domain.Keys.SessionKeys sessionKeys,
        byte[] macChainingValue,
        uint encryptionCounter,
        byte scpVersion,
        byte securityLevel,
        CardState currentState)
    {
        // Test implementation - just return the original data
        // Real implementation would apply R-MAC and R-ENCRYPTION
        return Result.Success<(byte[] securedData, CardState newState), SmartCardError>(
            (responseData, currentState));
    }

    public Result<byte[], SmartCardError> CalculateAesCmac(byte[] key, byte[] data)
    {
        // Test implementation - return fake MAC
        var mac = new byte[16];
        for (var i = 0; i < 16; i++)
        {
            mac[i] = (byte)(i ^ key[i % key.Length] ^ data[i % data.Length]);
        }
        return Result.Success<byte[], SmartCardError>(mac);
    }
}

/// <summary>
/// Mock implementation that always fails for testing error conditions.
/// </summary>
[PublicAPI]
public class FailingCryptographicService : ICryptographicService
{
    public Result<byte[], SmartCardError> GenerateChallenge(int length) =>
        Result.Failure<byte[], SmartCardError>(SmartCardError.CryptographicError("Mock failure"));

    public Result<byte[], SmartCardError> GeneratePseudoRandomChallenge(
        byte[] keyEnc,
        byte[] sequenceCounter,
        byte[] aid,
        int length) =>
        Result.Failure<byte[], SmartCardError>(SmartCardError.CryptographicError("Mock failure"));

    public Result<byte[], SmartCardError> CalculateCardCryptogram(
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet keys,
        byte scpVersion,
        byte implementationParameter,
        Maybe<byte[]> sequenceCounter) =>
        Result.Failure<byte[], SmartCardError>(SmartCardError.CryptographicError("Mock failure"));

    public Result<byte[], SmartCardError> CalculateHostCryptogram(
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet keys,
        byte scpVersion,
        byte implementationParameter,
        Maybe<byte[]> sequenceCounter) =>
        Result.Failure<byte[], SmartCardError>(SmartCardError.CryptographicError("Mock failure"));

    public Result<bool, SmartCardError> VerifyCryptogram(byte[] received, byte[] expected) =>
        Result.Failure<bool, SmartCardError>(SmartCardError.CryptographicError("Mock failure"));

    public Result<Gp4Net.Domain.Keys.SessionKeys, SmartCardError> DeriveSessionKeys(
        IKeySet masterKeys,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte scpVersion) =>
        Result.Failure<Gp4Net.Domain.Keys.SessionKeys, SmartCardError>(SmartCardError.CryptographicError("Mock failure"));

    public Result<(byte[] securedData, CardState newState), SmartCardError> ApplyResponseSecurity(
        byte[] responseData,
        Gp4Net.Domain.Keys.SessionKeys sessionKeys,
        byte[] macChainingValue,
        uint encryptionCounter,
        byte scpVersion,
        byte securityLevel,
        CardState currentState) =>
        Result.Failure<(byte[] securedData, CardState newState), SmartCardError>(
            SmartCardError.CryptographicError("Mock failure"));

    public Result<byte[], SmartCardError> CalculateAesCmac(byte[] key, byte[] data) =>
        Result.Failure<byte[], SmartCardError>(SmartCardError.CryptographicError("Mock failure"));
}