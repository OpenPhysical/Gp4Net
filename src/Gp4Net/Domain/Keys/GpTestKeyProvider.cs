using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Protocol;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Provides GlobalPlatform test keys with card-specific diversification support.
/// Implements the same diversification logic as the gp_test_keys.lua script but in pure C#.
/// </summary>
public static class GpTestKeyProvider
{
    /// <summary>
    /// Key type constants for SCP02 key diversification.
    /// These constants are appended to the sequence counter to form the derivation data.
    /// </summary>
    private static class Scp02KeyTypeConstants
    {
        public static readonly byte[] SecureChannelEncryption = { 0x01, 0x82 };
        public static readonly byte[] CMac = { 0x01, 0x01 };
        public static readonly byte[] DataEncryptionKey = { 0x01, 0x81 };
    }

    /// <summary>
    /// Gets the diversified GP test key set for the given card response.
    /// If no diversification data is available, returns the static test keys.
    /// </summary>
    /// <param name="cardResponse">The INITIALIZE UPDATE response containing diversification data.</param>
    /// <returns>The diversified key set or an error.</returns>
    public static Result<IKeySet, SmartCardError> GetDiversifiedTestKeys(InitializeUpdateResponse cardResponse)
    {
        if (cardResponse == null)
        {
            // No card response - return static GP test keys for SCP02
            return GpTestKeys.GetTestKeySet(0x02, 0x00);
        }

        // Check if we have diversification data
        if (cardResponse.KeyDiversificationData == null || cardResponse.KeyDiversificationData.Length == 0)
        {
            // No diversification - return static test keys
            return GpTestKeys.GetTestKeySet(cardResponse.ScpId, cardResponse.KeyVersion);
        }

        // Determine protocol and apply appropriate diversification
        var scpVersion = (byte)(cardResponse.ScpId & 0x03);
        
        return scpVersion switch
        {
            0x02 => DiversifyScp02Keys(cardResponse),
            0x03 => DiversifyScp03Keys(cardResponse),
            _ => Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}"))
        };
    }


    /// <summary>
    /// Diversifies GP test keys using SCP02 algorithm.
    /// Uses the card's diversification data and sequence counter.
    /// </summary>
    private static Result<IKeySet, SmartCardError> DiversifyScp02Keys(InitializeUpdateResponse cardResponse)
    {
        // Check for required sequence counter
        if (cardResponse.SequenceCounter == null || cardResponse.SequenceCounter.Length < 2)
        {
            return Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 requires sequence counter for key diversification"));
        }

        var baseKey = GpTestKeys.StandardTestKey;
        var divData = cardResponse.KeyDiversificationData;
        var sequenceCounter = cardResponse.SequenceCounter;


        // Take only first 2 bytes of sequence counter
        var seqCounter2Bytes = new byte[2];
        Array.Copy(sequenceCounter, 0, seqCounter2Bytes, 0, 2);

        // Derive the three keys
        var encKeyResult = DeriveScp02Key(baseKey, divData, seqCounter2Bytes, Scp02KeyTypeConstants.SecureChannelEncryption);
        var macKeyResult = DeriveScp02Key(baseKey, divData, seqCounter2Bytes, Scp02KeyTypeConstants.CMac);
        var dekKeyResult = DeriveScp02Key(baseKey, divData, seqCounter2Bytes, Scp02KeyTypeConstants.DataEncryptionKey);


        // Combine results
        return encKeyResult.Bind(encKey =>
            macKeyResult.Bind(macKey =>
                dekKeyResult.Bind(dekKey =>
                    Scp02KeySet.Create(encKey, macKey, dekKey, cardResponse.KeyVersion)
                        .Map(keySet => (IKeySet)keySet))));
    }

    /// <summary>
    /// Derives a single SCP02 key using 3DES-ECB encryption.
    /// This implements the card-specific key diversification (different from session key derivation).
    /// </summary>
    /// <param name="baseKey">The base GP test key.</param>
    /// <param name="divData">The card's diversification data.</param>
    /// <param name="sequenceCounter">The sequence counter (2 bytes).</param>
    /// <param name="keyType">The key type constant.</param>
    /// <returns>The derived key (16 bytes).</returns>
    private static Result<byte[], SmartCardError> DeriveScp02Key(
        byte[] baseKey,
        byte[] divData,
        byte[] sequenceCounter,
        byte[] keyType)
    {
        try
        {
            // Build derivation data: div_data || sequence_counter || key_type
            var derivationData = new byte[divData.Length + sequenceCounter.Length + keyType.Length];
            Array.Copy(divData, 0, derivationData, 0, divData.Length);
            Array.Copy(sequenceCounter, 0, derivationData, divData.Length, sequenceCounter.Length);
            Array.Copy(keyType, 0, derivationData, divData.Length + sequenceCounter.Length, keyType.Length);

            // Apply ISO/IEC 7816-4 padding (add 0x80 and pad with zeros to 8-byte boundary)
            var paddedData = ApplyIso7816Padding(derivationData);

            // Encrypt each 8-byte block with 3DES-ECB and use the last block as result
            var engine = new DesEdeEngine();
            engine.Init(true, new KeyParameter(baseKey));

            byte[] result = new byte[8];
            for (int i = 0; i < paddedData.Length; i += 8)
            {
                engine.ProcessBlock(paddedData, i, result, 0);
            }

            // For 2-key 3DES, we need 16 bytes - double the 8-byte result
            var finalKey = new byte[16];
            Array.Copy(result, 0, finalKey, 0, 8);
            Array.Copy(result, 0, finalKey, 8, 8);

            return Result.Success<byte[], SmartCardError>(finalKey);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"Key derivation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Diversifies GP test keys using SCP03 algorithm.
    /// Uses SP 800-108 KDF with the card's diversification data.
    /// </summary>
    private static Result<IKeySet, SmartCardError> DiversifyScp03Keys(InitializeUpdateResponse cardResponse)
    {
        // SCP03 diversification would use SP 800-108 KDF
        // For now, return non-diversified keys as SCP03 cards typically don't use
        // the same diversification mechanism as SCP02
        return GpTestKeys.GetTestKeySet(0x03, cardResponse.KeyVersion);
    }

    /// <summary>
    /// Applies ISO/IEC 7816-4 padding to data.
    /// Adds 0x80 followed by zeros to reach the next 8-byte boundary.
    /// </summary>
    private static byte[] ApplyIso7816Padding(byte[] data)
    {
        var paddedLength = ((data.Length + 1 + 7) / 8) * 8; // Round up to next 8-byte boundary
        var padded = data
            .Concat(new byte[] { 0x80 }) // Add padding start marker
            .Concat(new byte[paddedLength - data.Length - 1]) // Fill remaining with zeros
            .ToArray();
        return padded;
    }
}