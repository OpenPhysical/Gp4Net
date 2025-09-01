using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Kdf108.Domain.Kdf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    /// <summary>
    /// Key derivation operations for SCP02 and SCP03 session keys.
    /// Consolidates all key derivation methods from multiple classes.
    /// Provides SCP-specific session key derivation using BouncyCastle exclusively.
    /// </summary>
    public static class KeyDerivation
    {
        /// <summary>
        /// Derives SCP02 session keys using 3DES-ECB with specific derivation constants.
        /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.1.
        /// </summary>
        /// <param name="baseKey">The base static key (16 or 24 bytes).</param>
        /// <param name="sequenceCounter">The sequence counter from INITIALIZE UPDATE response.</param>
        /// <param name="derivationConstant">The key-specific derivation constant (MAC=01, ENC=02, KEK=03).</param>
        /// <returns>The derived session key or error.</returns>
        public static Result<byte[], SmartCardError> DeriveScp02SessionKey(
            byte[] baseKey,
            byte[] sequenceCounter,
            byte derivationConstant
        )
        {// @TODO NO NULLS!
            return Validation.ValidateInputs(baseKey, sequenceCounter)
                .Bind(() => Validation.ValidateKeyLength(baseKey, [16, 24], "SCP02 base key must be 16 or 24 bytes"))
                .Bind(() => ValidateSequenceCounterLength(sequenceCounter, 2))
                .Bind(() => ValidateDerivationConstant(derivationConstant))
                .Bind(() => Utils.ExpandTripleDesKey(baseKey))
                .Bind(expandedKey => DeriveUsing3DesEcb(expandedKey, sequenceCounter, derivationConstant));
        }

        /// <summary>
        /// Derives SCP03 session keys using AES-CMAC with specific derivation data.
        /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.5.
        /// </summary>
        /// <param name="baseKey">The base static key (16, 24, or 32 bytes).</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <param name="cardChallenge">The card challenge (8 bytes).</param>
        /// <param name="derivationConstant">The key-specific derivation constant (MAC=01, ENC=02, RMAC=03).</param>
        /// <returns>The derived session key or error.</returns>
        public static Result<byte[], SmartCardError> DeriveScp03SessionKey(
            byte[] baseKey,
            byte[] hostChallenge,
            byte[] cardChallenge,
            byte derivationConstant
        )
        {// @TODO NO NULLS!
            return Validation.ValidateInputs(baseKey, hostChallenge)
                .Bind(() => Validation.ValidateKeyLength(baseKey, [16, 24, 32], "SCP03 base key must be 16, 24, or 32 bytes"))
                .Bind(() => ValidateChallengeLength(hostChallenge, 8, "Host challenge"))
                .Bind(() => ValidateChallengeLength(cardChallenge, 8, "Card challenge"))
                .Bind(() => ValidateDerivationConstant(derivationConstant))
                .Bind(() => BuildScp03DerivationData(hostChallenge, cardChallenge, derivationConstant))
                .Bind(derivationData => DeriveUsingAesCmac(baseKey, derivationData));
        }

        /// <summary>
        /// Derives SCP03 receipt key using AES-CMAC for secure messaging validation.
        /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.5 - used for response MAC validation.
        /// </summary>
        /// <param name="baseKey">The base static key (16, 24, or 32 bytes).</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <param name="cardChallenge">The card challenge (8 bytes).</param>
        /// <returns>The derived receipt key or error.</returns>
        public static Result<byte[], SmartCardError> DeriveScp03ReceiptKey(
            byte[] baseKey,
            byte[] hostChallenge,
            byte[] cardChallenge
        )
        {
            return DeriveScp03SessionKey(baseKey, hostChallenge, cardChallenge, 0x04);
        }

        /// <summary>
        /// Validates sequence counter length for SCP02.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateSequenceCounterLength(
            byte[] sequenceCounter,
            int expectedLength
        )
        {
            return sequenceCounter.Length >= expectedLength
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(SmartCardError.InvalidArgument(
                    $"Sequence counter must be at least {expectedLength} bytes, got {sequenceCounter.Length}"
                ));
        }

        /// <summary>
        /// Validates challenge length for SCP03.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateChallengeLength(
            byte[] challenge,
            int expectedLength,
            string challengeType
        )
        {
            return challenge.Length == expectedLength
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(SmartCardError.InvalidArgument(
                    $"{challengeType} must be {expectedLength} bytes, got {challenge.Length}"
                ));
        }

        /// <summary>
        /// Validates derivation constant is within valid range.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateDerivationConstant(byte derivationConstant)
        {
            return derivationConstant is >= 0x01 and <= 0x04
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(SmartCardError.InvalidArgument(
                    $"Derivation constant must be 0x01-0x04, got 0x{derivationConstant:X2}"
                ));
        }

        /// <summary>
        /// Performs SCP02 key derivation using 3DES-ECB.
        /// </summary>
        private static Result<byte[], SmartCardError> DeriveUsing3DesEcb(
            byte[] expandedKey,
            byte[] sequenceCounter,
            byte derivationConstant
        )
        {
            return Result.Try(
                () =>
                {
                    byte[] derivationData = new byte[16];
                    derivationData[0] = derivationConstant;
                    derivationData[1] = derivationConstant;
                    Array.Copy(sequenceCounter, 0, derivationData, 2, 2);
                    Array.Copy(sequenceCounter, 0, derivationData, 4, 2);
                    Array.Copy(sequenceCounter, 0, derivationData, 6, 2);
                    Array.Copy(sequenceCounter, 0, derivationData, 8, 2);

                    BufferedBlockCipher cipher = new BufferedBlockCipher(new DesEdeEngine());
                    cipher.Init(true, new KeyParameter(expandedKey));

                    byte[] sessionKey = new byte[16];
                    int len = cipher.ProcessBytes(derivationData, 0, derivationData.Length, sessionKey, 0);
                    cipher.DoFinal(sessionKey, len);

                    return sessionKey;
                },
                ex => SmartCardError.CryptographicError($"SCP02 key derivation failed: {ex.Message}")
            );
        }

        /// <summary>
        /// Builds SCP03 derivation data per specification.
        /// </summary>
        private static Result<byte[], SmartCardError> BuildScp03DerivationData(
            byte[] hostChallenge,
            byte[] cardChallenge,
            byte derivationConstant
        )
        {
            return Result.Try(
                () =>
                {
                    byte[] derivationData = new byte[32];
                    derivationData[0] = 0x00;
                    derivationData[1] = 0x00;
                    derivationData[2] = 0x00;
                    derivationData[3] = 0x01;
                    derivationData[4] = derivationConstant;
                    derivationData[5] = 0x00;
                    Array.Copy(hostChallenge, 0, derivationData, 6, 8);
                    Array.Copy(cardChallenge, 0, derivationData, 14, 8);
                    derivationData[22] = 0x00;
                    derivationData[23] = 0x80;

                    return derivationData;
                },
                ex => SmartCardError.CryptographicError($"SCP03 derivation data construction failed: {ex.Message}")
            );
        }

        /// <summary>
        /// Performs SCP03 key derivation using AES-CMAC.
        /// </summary>
        private static Result<byte[], SmartCardError> DeriveUsingAesCmac(
            byte[] baseKey,
            byte[] derivationData
        )
        {
            return Result.Try(
                () =>
                {
                    CMac cmac = new CMac(new AesEngine(), 128);
                    cmac.Init(new KeyParameter(baseKey));
                    cmac.BlockUpdate(derivationData, 0, derivationData.Length);

                    byte[] sessionKey = new byte[baseKey.Length];
                    cmac.DoFinal(sessionKey, 0);

                    return sessionKey;
                },
                ex => SmartCardError.CryptographicError($"SCP03 key derivation failed: {ex.Message}")
            );
        }

        /// <summary>
        /// Derives SCP03 data using KDF108 (NIST SP 800-108) in counter mode.
        /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.5 "Data Derivation Scheme".
        /// Uses NIST SP 800-108 KDF in counter mode with AES-CMAC as the PRF.
        /// </summary>
        /// <param name="key">The key to use for derivation (KDK).</param>
        /// <param name="derivationConstant">The derivation constant from Table 4-1.</param>
        /// <param name="context">The context data (typically challenges concatenated).</param>
        /// <param name="outputLengthBits">The desired output length in bits.</param>
        /// <returns>The derived data or error.</returns>
        public static Result<byte[], SmartCardError> DeriveScp03Data(
            byte[] key,
            byte derivationConstant,
            byte[] context,
            int outputLengthBits
        )
        {
            return Validation.ValidateInputs(key, context)
                .Bind(() => Validation.ValidateKeyLength(key, [16, 24, 32], "KDK must be 16, 24, or 32 bytes"))
                .Bind(() => ValidateOutputLength(outputLengthBits))
                .Bind(() => BuildScp03DerivationInputs(derivationConstant, context, outputLengthBits))
                .Bind(inputs => PerformKdf108Derivation(key, inputs.dataBeforeCounter, inputs.dataAfterCounter, outputLengthBits));
        }

        /// <summary>
        /// Derives session keys from the given context.
        /// Delegates to protocol-specific derivation based on context.
        /// </summary>
        /// <param name="context">The key derivation context containing all necessary parameters.</param>
        /// <returns>The derived session keys or an error.</returns>
        public static Result<SessionKeys, SmartCardError> DeriveSessionKeys(IKeyDerivationContext context)
        {
            return context.Protocol switch
            {
                ScpVersion.Scp02 => DeriveScp02SessionKeysFromContext(context),
                ScpVersion.Scp03 => DeriveScp03SessionKeysFromContext(context),
                _ => Result.Failure<SessionKeys, SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported SCP version: {context.Protocol}")
                ),
            };
        }

        /// <summary>
        /// Validates output length for KDF operations.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateOutputLength(int outputLengthBits)
        {
            return outputLengthBits % 8 == 0 && outputLengthBits > 0 && outputLengthBits <= 256
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(SmartCardError.InvalidArgument(
                    $"Output length must be multiple of 8, positive, and <= 256 bits, got {outputLengthBits}"
                ));
        }

        /// <summary>
        /// Builds SCP03 derivation inputs for KDF108.
        /// </summary>
        private static Result<(byte[] dataBeforeCounter, byte[] dataAfterCounter), SmartCardError> BuildScp03DerivationInputs(
            byte derivationConstant,
            byte[] context,
            int outputLengthBits
        )
        {
            try
            {
                // Build fixed input data before counter per GP SCP03 v1.1.1 Section 4.1.5
                byte[] dataBeforeCounter = new byte[15]; // Label (12) + Separator (1) + L (2)
                int offset = 0;

                // Label (11 bytes of 0x00 + derivation constant)
                Constants.Constants.Cryptography.KeyDerivation.Scp03Constants.Label.CopyTo(dataBeforeCounter, offset);
                offset += 11;
                dataBeforeCounter[offset++] = derivationConstant;

                // Separator (1 byte)
                dataBeforeCounter[offset++] = 0x00;

                // L (length in bits as 2-byte big-endian)
                dataBeforeCounter[offset++] = (byte)(outputLengthBits >> 8);
                dataBeforeCounter[offset++] = (byte)outputLengthBits;

                // Context data comes after counter (16 bytes max)
                byte[] dataAfterCounter = new byte[16];
                context.CopyTo(dataAfterCounter, 0);

                return Result.Success<(byte[], byte[]), SmartCardError>((dataBeforeCounter, dataAfterCounter));
            }
            catch (Exception ex)
            {
                return SmartCardError.CryptographicError($"SCP03 derivation input construction failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Performs KDF108 derivation using the Kdf108 library.
        /// </summary>
        private static Result<byte[], SmartCardError> PerformKdf108Derivation(
            byte[] kdk,
            byte[] dataBeforeCounter,
            byte[] dataAfterCounter,
            int outputLengthBits
        )
        {
            // Determine PRF type based on key length with functional approach
            Result<PrfType, SmartCardError> prfTypeResult = kdk.Length switch
            {
                16 => Result.Success<PrfType, SmartCardError>(PrfType.CmacAes128),
                24 => Result.Success<PrfType, SmartCardError>(PrfType.CmacAes192),
                32 => Result.Success<PrfType, SmartCardError>(PrfType.CmacAes256),
                _ => Result.Failure<PrfType, SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported key length: {kdk.Length} bytes")
                )
            };

            return prfTypeResult.Bind(prfType =>
            {
                KdfOptions options = new KdfOptions(
                    prfType: prfType,
                    counterLengthBits: 8, // SCP03 uses 8-bit counter
                    useCounter: true,
                    counterLocation: Kdf108.Domain.Kdf.CounterLocation.MiddleFixed
                );

                return Result.Try(
                    () =>
                    {
                        Kdf108.Domain.Kdf.Modes.CounterModeKdf kdf = new Kdf108.Domain.Kdf.Modes.CounterModeKdf();
                        return kdf.DeriveWithSplitFixedInput(
                            kdk,
                            dataBeforeCounter,
                            dataAfterCounter,
                            outputLengthBits,
                            options
                        );
                    },
                    ex => SmartCardError.CryptographicError($"KDF108 derivation failed: {ex.Message}")
                );
            });
        }

        /// <summary>
        /// Derives SCP02 session keys from context.
        /// </summary>
        private static Result<SessionKeys, SmartCardError> DeriveScp02SessionKeysFromContext(IKeyDerivationContext context)
        {
            return context.SequenceCounter.ToResult(SmartCardError.InvalidArgument("SCP02 requires sequence counter"))
                .Bind(seqCounter => ValidateSequenceCounterLength(seqCounter, 2)
                    .Map(() => seqCounter))
                .Bind(seqCounter =>
                {
                    // Use the existing SCP02 session key derivation methods
                    Scp02KeySet keySet = (Scp02KeySet)context.BaseKeySet;
                    Result<byte[], SmartCardError> sMacResult = DeriveScp02SessionKey(
                        keySet.MacKey,
                        seqCounter,
                        0x01 // MAC derivation constant
                    );

                    Result<byte[], SmartCardError> sEncResult = DeriveScp02SessionKey(
                        keySet.EncKey,
                        seqCounter,
                        0x02 // ENC derivation constant
                    );

                    Result<byte[], SmartCardError> sDekResult = DeriveScp02SessionKey(
                        keySet.DekKey,
                        seqCounter,
                        0x03 // KEK derivation constant
                    );

                    return sMacResult.Bind(sMac =>
                        sEncResult.Bind(sEnc =>
                            sDekResult.Map(sDek =>
                                new SessionKeys(sMac, sEnc, sDek))));
                });
        }

        /// <summary>
        /// Derives SCP03 session keys from context.
        /// </summary>
        private static Result<SessionKeys, SmartCardError> DeriveScp03SessionKeysFromContext(IKeyDerivationContext context)
        {
            Scp03KeySet keySet = (Scp03KeySet)context.BaseKeySet;

            // Derive S-MAC key
            Result<byte[], SmartCardError> sMacResult = DeriveScp03SessionKey(
                keySet.MacKey,
                context.HostChallenge,
                context.CardChallenge,
                0x01 // MAC derivation constant
            );

            // Derive S-ENC key
            Result<byte[], SmartCardError> sEncResult = DeriveScp03SessionKey(
                keySet.EncKey,
                context.HostChallenge,
                context.CardChallenge,
                0x02 // ENC derivation constant
            );

            // Derive S-RMAC key (receipt MAC)
            Result<byte[], SmartCardError> sRmacResult = DeriveScp03ReceiptKey(
                keySet.MacKey,
                context.HostChallenge,
                context.CardChallenge
            );

            return sMacResult.Bind(sMac =>
                sEncResult.Bind(sEnc =>
                    sRmacResult.Map(sRmac =>
                        new SessionKeys(sMac, sEnc, sRmac))));
        }
    }
}
