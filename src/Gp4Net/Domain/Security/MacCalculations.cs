// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Validation;
using Gp4Net.Domain.Protocol;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Pure static MAC calculation functions implementing GlobalPlatform Secure Channel Protocol specifications.
/// Each method directly implements its specific algorithm with BouncyCastle - no abstraction layers.
/// All functions are stateless and side-effect free for maximum performance and functional purity.
/// Based on GlobalPlatform Card Specification v2.3.1 and SCP03 v1.1.1.
/// </summary>
[PublicAPI]
public static class MacCalculations
{

    /// <summary>
    /// Calculates SCP02 Command MAC using ISO 9797-1 Algorithm 3 (Retail MAC).
    /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.2 "Single DES Plus Final Triple DES MAC".
    /// </summary>
    /// <param name="sMacKey">The S-MAC session key (16 or 24 bytes).</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>8-byte MAC or error.</returns>
    public static Result<byte[], SmartCardError> CalculateScp02CommandMac(byte[] sMacKey, byte[] data)
    {

        return ValidateInputs(sMacKey, data, "S-MAC key and data cannot be null")
            .Bind(() => ValidateKeyLength(sMacKey, [16, 24], "SCP02 S-MAC key must be 16 or 24 bytes"))
            .Bind(() => Result.Try(() =>
            {
                // Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.2 "Single DES Plus Final Triple DES MAC":
                // "This is also known as the Retail MAC. It is as defined in [ISO 9797-1] as MAC Algorithm 3,
                // with initial transformation 1 and output transformation 3, without truncation, and with DES
                // taking the place of the block cipher."

                ISO9797Alg3Mac mac = new ISO9797Alg3Mac(new DesEngine(), new ISO7816d4Padding());
                mac.Init(new KeyParameter(sMacKey));
                mac.BlockUpdate(data, 0, data.Length);

                byte[] result = new byte[8];
                _ = mac.DoFinal(result, 0);

                return result;
            }, ex => SmartCardError.CryptographicError($"SCP02 Command MAC calculation failed: {ex.Message}")));
    }

    /// <summary>
    /// Calculates SCP02 Response MAC using ISO 9797-1 Algorithm 3 (Retail MAC).
    /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.2 - same algorithm as Command MAC.
    /// </summary>
    /// <param name="sMacKey">The S-MAC session key (16 or 24 bytes).</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>8-byte MAC or error.</returns>
    public static Result<byte[], SmartCardError> CalculateScp02ResponseMac(byte[] sMacKey, byte[] data)
    {

        return ValidateInputs(sMacKey, data, "S-MAC key and data cannot be null")
            .Bind(() => ValidateKeyLength(sMacKey, [16, 24], "SCP02 S-MAC key must be 16 or 24 bytes"))
            .Bind(() => Result.Try(() =>
            {
                // Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.2 "Single DES Plus Final Triple DES MAC":
                // Same algorithm as Command MAC - both use Retail MAC (ISO 9797-1 Algorithm 3)

                ISO9797Alg3Mac mac = new ISO9797Alg3Mac(new DesEngine(), new ISO7816d4Padding());
                mac.Init(new KeyParameter(sMacKey));
                mac.BlockUpdate(data, 0, data.Length);

                byte[] result = new byte[8];
                _ = mac.DoFinal(result, 0);

                return result;
            }, ex => SmartCardError.CryptographicError($"SCP02 Response MAC calculation failed: {ex.Message}")));
    }

    /// <summary>
    /// Calculates SCP02 Cryptogram using Full 3DES MAC (ISO 9797-1 Algorithm 1).
    /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.1 and E.4.2.
    /// </summary>
    /// <param name="sEncKey">The S-ENC session key (16 or 24 bytes).</param>
    /// <param name="data">The padded cryptogram data (must be multiple of 8 bytes).</param>
    /// <returns>8-byte cryptogram or error.</returns>
    public static Result<byte[], SmartCardError> CalculateScp02Cryptogram(byte[] sEncKey, byte[] data)
    {

        return ValidateInputs(sEncKey, data, "S-ENC key and data cannot be null")
            .Bind(() => ValidateKeyLength(sEncKey, [16, 24], "SCP02 S-ENC key must be 16 or 24 bytes"))
            .Bind(() => ValidateDataPadding(data, 8, "Cryptogram data must be padded to 8-byte blocks"))
            .Bind(() => CryptographicOperations.ExpandTripleDesKey(sEncKey)
                .Bind(expandedKey => Result.Try(() =>
                {
                    // Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.1 "Full Triple DES MAC":
                    // "The full triple DES MAC is as defined in [ISO 9797-1] as MAC Algorithm 1, with initial
                    // transformation 1 and output transformation 1, without truncation, and with Triple DES
                    // taking the place of the block cipher."

                    // Full 3DES CBC-MAC with zero IV per ISO 9797-1 Algorithm 1
                    byte[] zeroIv = new byte[8];
                    DesEdeEngine engine = new DesEdeEngine();
                    CbcBlockCipher blockCipher = new CbcBlockCipher(engine);
                    blockCipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), zeroIv));

                    // Process all blocks - CbcBlockCipher handles CBC chaining internally
                    int blockCount = data.Length / 8;
                    byte[] mac = Enumerable.Range(0, blockCount)
                        .Aggregate(new byte[8], (currentBlock, blockIndex) =>
                        {
                            byte[] result = new byte[8];
                            _ = blockCipher.ProcessBlock(data, blockIndex * 8, result, 0);
                            return result;
                        });

                    return mac;
                }, ex => SmartCardError.CryptographicError($"SCP02 Cryptogram calculation failed: {ex.Message}"))));
    }

    /// <summary>
    /// Calculates SCP03 Command MAC using AES-CMAC truncated to 8 bytes.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 and 6.2.4.
    /// </summary>
    /// <param name="sMacKey">The S-MAC session key (16, 24, or 32 bytes).</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>8-byte truncated MAC or error.</returns>
    public static Result<byte[], SmartCardError> CalculateScp03CommandMac(byte[] sMacKey, byte[] data)
    {

        return ValidateInputs(sMacKey, data, "S-MAC key and data cannot be null")
            .Bind(() => ValidateKeyLength(sMacKey, [16, 24, 32], "SCP03 S-MAC key must be 16, 24, or 32 bytes"))
            .Bind(() => Result.Try(() =>
            {
                // Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 "MACing":
                // "CMAC as specified in [NIST 800-38B] is used for MAC calculations."
                // Section 6.2.4: "A C-MAC is generated...uses the S-MAC key"
                // For SCP03, the MAC is truncated to 8 bytes for APDUs.

                CMac cmac = new CMac(new AesEngine(), 128); // AES block size in bits
                cmac.Init(new KeyParameter(sMacKey));
                cmac.BlockUpdate(data, 0, data.Length);

                byte[] fullMac = new byte[16]; // AES-CMAC produces 16 bytes
                _ = cmac.DoFinal(fullMac, 0);

                // Return first 8 bytes for command MAC
                byte[] truncatedMac = fullMac.Take(8).ToArray();
                return truncatedMac;
            }, ex => SmartCardError.CryptographicError($"SCP03 Command MAC calculation failed: {ex.Message}")));
    }

    /// <summary>
    /// Calculates SCP03 Response MAC using AES-CMAC truncated to 8 bytes.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 and 6.2.5.
    /// </summary>
    /// <param name="sMacKey">The S-MAC session key (16, 24, or 32 bytes).</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>8-byte truncated MAC or error.</returns>
    public static Result<byte[], SmartCardError> CalculateScp03ResponseMac(byte[] sMacKey, byte[] data)
    {

        return ValidateInputs(sMacKey, data, "S-MAC key and data cannot be null")
            .Bind(() => ValidateKeyLength(sMacKey, [16, 24, 32], "SCP03 S-MAC key must be 16, 24, or 32 bytes"))
            .Bind(() => Result.Try(() =>
            {
                // Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 "MACing":
                // "CMAC as specified in [NIST 800-38B] is used for MAC calculations."
                // Section 6.2.5: "An R-MAC is generated...uses the S-MAC key"
                // Same algorithm as Command MAC - both use AES-CMAC truncated to 8 bytes.

                CMac cmac = new CMac(new AesEngine(), 128); // AES block size in bits
                cmac.Init(new KeyParameter(sMacKey));
                cmac.BlockUpdate(data, 0, data.Length);

                byte[] fullMac = new byte[16]; // AES-CMAC produces 16 bytes
                _ = cmac.DoFinal(fullMac, 0);

                // Return first 8 bytes for response MAC
                byte[] truncatedMac = fullMac.Take(8).ToArray();
                return truncatedMac;
            }, ex => SmartCardError.CryptographicError($"SCP03 Response MAC calculation failed: {ex.Message}")));
    }

    /// <summary>
    /// Calculates SCP03 Cryptogram using full 16-byte AES-CMAC.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 - used for authentication cryptograms.
    /// </summary>
    /// <param name="sEncKey">The S-ENC session key (16, 24, or 32 bytes).</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>16-byte full MAC or error.</returns>
    public static Result<byte[], SmartCardError> CalculateScp03Cryptogram(byte[] sEncKey, byte[] data)
    {

        return ValidateInputs(sEncKey, data, "S-ENC key and data cannot be null")
            .Bind(() => ValidateKeyLength(sEncKey, [16, 24, 32], "SCP03 S-ENC key must be 16, 24, or 32 bytes"))
            .Bind(() => Result.Try(() =>
            {
                // Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 "MACing":
                // "CMAC as specified in [NIST 800-38B] is used for MAC calculations."
                // For cryptograms, the full 16-byte output is typically used.

                CMac cmac = new CMac(new AesEngine(), 128); // AES block size in bits
                cmac.Init(new KeyParameter(sEncKey));
                cmac.BlockUpdate(data, 0, data.Length);

                byte[] fullMac = new byte[16]; // Return full 16-byte MAC for cryptogram
                _ = cmac.DoFinal(fullMac, 0);

                return fullMac;
            }, ex => SmartCardError.CryptographicError($"SCP03 Cryptogram calculation failed: {ex.Message}")));
    }

    /// <summary>
    /// Calculates SCP03 Full MAC using complete 16-byte AES-CMAC for chaining.
    /// Per GlobalPlatform SCP03 v1.1.1 Section 6.2.4 - used for MAC chaining values.
    /// </summary>
    /// <param name="sMacKey">The S-MAC session key (16, 24, or 32 bytes).</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>16-byte full MAC for chaining or error.</returns>
    public static Result<byte[], SmartCardError> CalculateScp03FullMac(byte[] sMacKey, byte[] data)
    {

        return ValidateInputs(sMacKey, data, "S-MAC key and data cannot be null")
            .Bind(() => ValidateKeyLength(sMacKey, [16, 24, 32], "SCP03 S-MAC key must be 16, 24, or 32 bytes"))
            .Bind(() => Result.Try(() =>
            {
                // Per GlobalPlatform SCP03 v1.1.1 Section 6.2.4:
                // MAC chaining uses the full 16-byte AES-CMAC output as the next chaining value.
                // Per Section 4.1.3: "CMAC as specified in [NIST 800-38B] is used for MAC calculations."

                CMac cmac = new CMac(new AesEngine(), 128); // AES block size in bits
                cmac.Init(new KeyParameter(sMacKey));
                cmac.BlockUpdate(data, 0, data.Length);

                byte[] fullMac = new byte[16]; // Return full 16-byte MAC for chaining
                _ = cmac.DoFinal(fullMac, 0);

                return fullMac;
            }, ex => SmartCardError.CryptographicError($"SCP03 Full MAC calculation failed: {ex.Message}")));
    }

    /// <summary>
    /// Validates that both key and data are non-null using functional approach.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateInputs(byte[] key, byte[] data, string errorMessage)
        => CryptographicValidation.ValidateInputs(key, data, errorMessage);

    /// <summary>
    /// Validates that the key length matches one of the allowed values.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateKeyLength(byte[] key, int[] validLengths, string errorMessage)
        => CryptographicValidation.ValidateKeyLength(key, validLengths, errorMessage);

    /// <summary>
    /// Validates that data is padded to the specified block size.
    /// </summary>
    private static UnitResult<SmartCardError> ValidateDataPadding(byte[] data, int blockSize, string errorMessage)
        => CryptographicValidation.ValidateDataPadding(data, blockSize, errorMessage);

    // ExpandTripleDesKey moved to CryptographicOperations - using shared implementation

    // AID MAC calculation functions (consolidated from AidMacCalculationService)

    /// <summary>
    /// Calculates the Initial Chaining Vector (ICV) from MAC over AID for implicit mode implementations.
    /// Per GP Section E.3.3: "When using implicit Secure Channel Session initiation, the ICV shall be
    /// a MAC computed on the AID of the selected Application."
    /// </summary>
    /// <param name="selectedAid">The AID of the selected application</param>
    /// <param name="cMacSessionKey">The 16-byte C-MAC session key</param>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <returns>Result containing the 8-byte ICV calculated from AID MAC</returns>
    public static Result<byte[], SmartCardError> CalculateIcvFromAidMac(
        byte[] selectedAid,
        byte[] cMacSessionKey,
        ScpImplementation implementation)
    {
        return Maybe<byte[]>.From(selectedAid)
            .ToResult(SmartCardError.InvalidArgument("Selected AID required"))
            .Bind(_ => Maybe<byte[]>.From(cMacSessionKey)
                .ToResult(SmartCardError.InvalidArgument("C-MAC session key required")))
            .Bind(_ => cMacSessionKey.Length == 16
                ? Result.Success<byte[], SmartCardError>(cMacSessionKey)
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("C-MAC session key must be 16 bytes for SCP02")))
            .Bind(_ => implementation.IsScp02()
                ? Result.Success<ScpImplementation, SmartCardError>(implementation)
                : Result.Failure<ScpImplementation, SmartCardError>(
                    SmartCardError.InvalidArgument("AID MAC calculation only applies to SCP02 implementations")))
            .Bind(_ => implementation.HasMacOverAid()
                ? Result.Success<ScpImplementation, SmartCardError>(implementation)
                : Result.Failure<ScpImplementation, SmartCardError>(
                    SmartCardError.InvalidArgument("Implementation does not support MAC over AID")))
            .Bind(_ => ApplyGpPadding(selectedAid))
            .Bind(paddedAid => CalculateMacOverPaddedData(paddedAid, cMacSessionKey));
    }

    /// <summary>
    /// Determines whether the initial ICV should be calculated from AID MAC.
    /// Pure function that encapsulates the GP specification rules.
    /// </summary>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <returns>True if ICV should be calculated from AID MAC, false for zero ICV</returns>
    public static bool ShouldCalculateIcvFromAid(ScpImplementation implementation)
    {
        // GP Table E-1: bit b4 (0x08) indicates ICV set to MAC over AID
        // Only applies to implicit mode implementations
        return implementation.IsScp02() &&
               !implementation.IsExplicitMode() &&
               implementation.HasMacOverAid();
    }

    /// <summary>
    /// Validates that the implementation, AID, and session keys are compatible with AID MAC requirements.
    /// </summary>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <param name="selectedAid">The selected AID</param>
    /// <param name="cMacSessionKey">The C-MAC session key</param>
    /// <returns>Result indicating validation success or specific error</returns>
    public static Result ValidateAidMacRequirements(
        ScpImplementation implementation,
        byte[] selectedAid,
        byte[] cMacSessionKey)
    {
        if (!implementation.IsScp02())
        {
            return Result.Failure("AID MAC calculation only applies to SCP02 implementations");
        }

        if (ShouldCalculateIcvFromAid(implementation))
        {
            return Maybe<byte[]>.From(selectedAid)
                .Match(
                    aid => aid.Length > 0 && aid.Length <= 16
                        ? Maybe<byte[]>.From(cMacSessionKey)
                            .Match(
                                key => key.Length == 16
                                    ? Result.Success()
                                    : Result.Failure("MAC over AID implementations require 16-byte C-MAC session key"),
                                () => Result.Failure("MAC over AID implementations require 16-byte C-MAC session key"))
                        : Result.Failure("Selected AID must be 1-16 bytes per ISO 7816-4"),
                    () => Result.Failure("Selected AID is required for implicit mode implementations with MAC over AID"));
        }

        return Result.Success();
    }

    /// <summary>
    /// Applies GP padding to the AID per Section E.3.3.
    /// Pads with 0x80 followed by zeros to reach a multiple of 8 bytes.
    /// </summary>
    private static Result<byte[], SmartCardError> ApplyGpPadding(byte[] data)
    {
        if (data.Length == 0)
        {
            return SmartCardError.InvalidArgument("Data cannot be empty for GP padding");
        }

        return Result.Try(() =>
        {
            int paddingNeeded = data.Length % 8 == 0 ? 0 : 8 - (data.Length % 8);

            if (paddingNeeded == 0)
            {
                // Already multiple of 8, no padding needed
                return data;
            }

            // Apply GP padding: 0x80 followed by zeros
            byte[] paddedData = data
                .Concat([(byte)0x80])
                .Concat(Enumerable.Repeat((byte)0x00, paddingNeeded - 1))
                .ToArray();

            return paddedData;
        }, ex => SmartCardError.CryptographicError($"GP padding failed: {ex.Message}"));
    }

    /// <summary>
    /// Calculates 3DES MAC over the padded AID using ISO 9797-1 Algorithm 3.
    /// Uses zero ICV for the MAC calculation per GP specification.
    /// </summary>
    private static Result<byte[], SmartCardError> CalculateMacOverPaddedData(
        byte[] paddedData,
        byte[] macKey)
    {
        return Result.Try(() =>
        {
            // Use 3DES MAC with zero ICV per GP Section E.3.3
            DesEngine engine = new DesEngine();
            ISO9797Alg3Mac desMac = new ISO9797Alg3Mac(engine);
            desMac.Init(new KeyParameter(macKey));

            // Calculate MAC with zero ICV (implicit by BouncyCastle implementation)
            desMac.BlockUpdate(paddedData, 0, paddedData.Length);

            byte[] mac = new byte[8];
            _ = desMac.DoFinal(mac, 0);

            return mac;
        }, ex => SmartCardError.CryptographicError($"AID MAC calculation failed: {ex.Message}"));
    }

}
