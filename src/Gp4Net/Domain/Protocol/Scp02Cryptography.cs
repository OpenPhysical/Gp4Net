using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Pure functional SCP02 cryptographic operations.
/// All functions are stateless and deterministic for testing with known values.
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E.4 "SCP02".
/// </summary>
public static class Scp02Cryptography
{
    /// <summary>
    /// Derives a SCP02 session key using 3DES-CBC encryption.
    /// Per GP Card Spec v2.3.1 Section E.4.1 and Figure E-2.
    /// </summary>
    /// <param name="baseKey">The static base key (16 bytes).</param>
    /// <param name="derivationConstant">The derivation constant (2 bytes).</param>
    /// <param name="sequenceCounter">The sequence counter (2 bytes).</param>
    /// <returns>The derived session key (16 bytes).</returns>
    public static Result<byte[], SmartCardError> DeriveScp02SessionKey(
        byte[] baseKey,
        byte[] derivationConstant,
        byte[] sequenceCounter)
    {
        // Validate inputs per GP specification
        if (baseKey.Length != 16)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("baseKey", 16, baseKey.Length));

        if (derivationConstant.Length != 2)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("derivationConstant", 2, derivationConstant.Length));

        if (sequenceCounter.Length != 2)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("sequenceCounter", 2, sequenceCounter.Length));

        try
        {
            // Build derivation data per Figure E-2:
            // Constant (2) || Sequence Counter (2) || Padding (12 zeros)
            var derivationData = new byte[16];
            Array.Copy(derivationConstant, 0, derivationData, 0, 2);
            Array.Copy(sequenceCounter, 0, derivationData, 2, 2);
            // Remaining 12 bytes are already zeros
            

            // Encrypt using 3DES-CBC with zero IV
            var zeroIv = new byte[8];
            var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(baseKey), zeroIv));

            // Process the entire 16 bytes
            var sessionKey = new byte[cipher.GetOutputSize(derivationData.Length)];
            var len = cipher.ProcessBytes(derivationData, 0, derivationData.Length, sessionKey, 0);
            _ = cipher.DoFinal(sessionKey, len);


            return Result.Success<byte[], SmartCardError>(sessionKey);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                new CryptographicError("SCP02 session key derivation", ex.Message));
        }
    }

    /// <summary>
    /// Builds SCP02 card cryptogram data.
    /// Per GP Card Spec v2.3.1 Section E.4.2.1.
    /// </summary>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="sequenceCounter">The sequence counter (2 bytes).</param>
    /// <param name="cardChallenge">The card challenge (6 bytes for SCP02).</param>
    /// <returns>The card cryptogram data with ISO padding (24 bytes).</returns>
    public static Result<byte[], SmartCardError> BuildScp02CardCryptogramData(
        byte[] hostChallenge,
        byte[] sequenceCounter,
        byte[] cardChallenge)
    {
        if (hostChallenge?.Length != 8)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("hostChallenge", 8, hostChallenge?.Length ?? 0));

        if (sequenceCounter?.Length != 2)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("sequenceCounter", 2, sequenceCounter?.Length ?? 0));

        if (cardChallenge?.Length != 6)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("cardChallenge", 6, cardChallenge?.Length ?? 0));

        // Build data: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6)
        var data = new byte[24]; // Pre-sized for padding
        Array.Copy(hostChallenge, 0, data, 0, 8);
        Array.Copy(sequenceCounter, 0, data, 8, 2);
        Array.Copy(cardChallenge, 0, data, 10, 6);
        
        // Apply ISO 7816-4 padding
        data[16] = 0x80;
        // Remaining bytes are already zeros

        return Result.Success<byte[], SmartCardError>(data);
    }

    /// <summary>
    /// Builds SCP02 host cryptogram data.
    /// Per GP Card Spec v2.3.1 Section E.4.2.2.
    /// </summary>
    /// <param name="sequenceCounter">The sequence counter (2 bytes).</param>
    /// <param name="cardChallenge">The card challenge (6 bytes for SCP02).</param>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <returns>The host cryptogram data with ISO padding (24 bytes).</returns>
    public static Result<byte[], SmartCardError> BuildScp02HostCryptogramData(
        byte[] sequenceCounter,
        byte[] cardChallenge,
        byte[] hostChallenge)
    {
        if (sequenceCounter?.Length != 2)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("sequenceCounter", 2, sequenceCounter?.Length ?? 0));

        if (cardChallenge?.Length != 6)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("cardChallenge", 6, cardChallenge?.Length ?? 0));

        if (hostChallenge?.Length != 8)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("hostChallenge", 8, hostChallenge?.Length ?? 0));

        // Build data: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8)
        var data = new byte[24]; // Pre-sized for padding
        Array.Copy(sequenceCounter, 0, data, 0, 2);
        Array.Copy(cardChallenge, 0, data, 2, 6);
        Array.Copy(hostChallenge, 0, data, 8, 8);
        
        // Apply ISO 7816-4 padding
        data[16] = 0x80;
        // Remaining bytes are already zeros


        return Result.Success<byte[], SmartCardError>(data);
    }

    /// <summary>
    /// Calculates Full 3DES MAC for SCP02 cryptograms.
    /// Per GP Card Spec v2.3.1 Section B.1.2.1 "Full Triple DES".
    /// Used only for card/host cryptogram calculation with S-ENC key.
    /// </summary>
    /// <param name="key">The S-ENC session key (16 bytes).</param>
    /// <param name="data">The cryptogram data (24 bytes, already includes padding).</param>
    /// <returns>The cryptogram value (8 bytes).</returns>
    public static Result<byte[], SmartCardError> CalculateScp02Cryptogram(
        byte[] key,
        byte[] data)
    {
        if (key?.Length != 16)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("key", 16, key?.Length ?? 0));

        if (data?.Length != 24)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("data", 24, data?.Length ?? 0));

        try
        {
            // Full 3DES CBC-MAC with zero IV
            var zeroIv = new byte[8];
            var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), zeroIv));

            var result = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, result, 0);
            _ = cipher.DoFinal(result, len);

            // Return last 8 bytes as cryptogram
            var cryptogram = new byte[8];
            Array.Copy(result, result.Length - 8, cryptogram, 0, 8);
            
            
            return Result.Success<byte[], SmartCardError>(cryptogram);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                new CryptographicError("SCP02 cryptogram calculation", ex.Message));
        }
    }

    /// <summary>
    /// Calculates Retail MAC (Single DES + Final Triple DES) for SCP02.
    /// Per GP Card Spec v2.3.1 Section B.1.2.2 "Single DES Plus Final Triple DES".
    /// Used for C-MAC and R-MAC calculation.
    /// </summary>
    /// <param name="key">The MAC key (16 bytes).</param>
    /// <param name="data">The data to MAC (will be padded internally).</param>
    /// <returns>The MAC value (8 bytes).</returns>
    public static Result<byte[], SmartCardError> CalculateScp02Mac(
        byte[] key,
        byte[] data)
    {
        if (key.Length != 16)
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("key", 16, key.Length));

        if (data.Length == 0)
            return Result.Failure<byte[], SmartCardError>(
                new EmptyDataError("data"));

        try
        {
            // Apply ISO 7816-4 padding
            var paddedDataResult = ApplyIso7816Padding(data, 8);
            if (paddedDataResult.IsFailure)
                return paddedDataResult;
            
            var paddedData = paddedDataResult.Value;
            
            // Extract key components for 2-key 3DES
            var k1 = new byte[8];
            var k2 = new byte[8];
            Array.Copy(key, 0, k1, 0, 8);
            Array.Copy(key, 8, k2, 0, 8);
            
            // Single DES CBC for all blocks using functional aggregation
            var desEngine = new DesEngine();
            
            // Process all blocks with single DES using functional fold
            var blockCount = paddedData.Length / 8;
            var mac = Enumerable.Range(0, blockCount)
                .Aggregate(new byte[8], (currentMac, blockIndex) =>
                {
                    var blockStart = blockIndex * 8;
                    var block = new byte[8];
                    Array.Copy(paddedData, blockStart, block, 0, 8);
                    
                    // XOR block with current MAC (CBC mode) - functional transformation
                    var xorBlock = block.Select((b, i) => (byte)(b ^ currentMac[i])).ToArray();
                    
                    // Encrypt with K1
                    desEngine.Init(true, new KeyParameter(k1));
                    var result = new byte[8];
                    _ = desEngine.ProcessBlock(xorBlock, 0, result, 0);
                    return result;
                });
            
            // Final transformation: Decrypt with K2, then encrypt with K1
            desEngine.Init(false, new KeyParameter(k2));
            var temp = new byte[8];
            _ = desEngine.ProcessBlock(mac, 0, temp, 0);
            
            desEngine.Init(true, new KeyParameter(k1));
            _ = desEngine.ProcessBlock(temp, 0, mac, 0);
            
            return Result.Success<byte[], SmartCardError>(mac);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                new CryptographicError("SCP02 MAC calculation", ex.Message));
        }
    }

    /// <summary>
    /// Applies ISO 7816-4 padding to data.
    /// Adds 0x80 followed by zeros to reach the target block size.
    /// </summary>
    /// <param name="data">The data to pad.</param>
    /// <param name="blockSize">The block size (typically 8 for 3DES).</param>
    /// <returns>The padded data.</returns>
    public static Result<byte[], SmartCardError> ApplyIso7816Padding(byte[] data, int blockSize)
    {
        if (blockSize <= 0) 
            return Result.Failure<byte[], SmartCardError>(
                new InvalidLengthError("blockSize", 1, blockSize));

        var paddedLength = ((data.Length + blockSize) / blockSize) * blockSize;
        var padded = new byte[paddedLength];
        Array.Copy(data, padded, data.Length);
        padded[data.Length] = 0x80;
        // Remaining bytes are already zeros
        
        return Result.Success<byte[], SmartCardError>(padded);
    }

}