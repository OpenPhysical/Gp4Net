using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Kdf108.Domain.Kdf;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Cryptography;

public static partial class CryptoOperations
{
    /// <summary>
    /// Key derivation operations for SCP02 and SCP03 session keys.
    /// Consolidates all key derivation methods from multiple classes.
    /// Provides SCP-specific session key derivation using BouncyCastle exclusively.
    /// </summary>
    public static class KeyDerivation
    {
        /// <summary>
        /// Derives SCP02 session keys using 3DES-CBC with specific derivation constants.
        /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.1.
        /// </summary>
        /// <param name="baseKey">The base static key (16 or 24 bytes).</param>
        /// <param name="sequenceCounter">The sequence counter from INITIALIZE UPDATE response.</param>
        /// <param name="derivationConstant">The key-specific derivation constant (MAC=0101, ENC=0182, DEK=0181).</param>
        /// <returns>The derived session key or error.</returns>
        public static Result<byte[], SmartCardError> DeriveScp02SessionKey(
            byte[] baseKey,
            byte[] sequenceCounter,
            byte[] derivationConstant
        )
        {
            return Validation
                .ValidateInputs(baseKey, sequenceCounter)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            baseKey,
                            [16, 24],
                            "SCP02 base key must be 16 or 24 bytes"
                        )
                )
                .Bind(() => ValidateSequenceCounterLength(sequenceCounter, 2))
                .Bind(() => ValidateScp02DerivationConstant(derivationConstant))
                .Bind(() => Utils.ExpandTripleDesKey(baseKey))
                .Bind(expandedKey =>
                    DeriveUsing3DesCbc(expandedKey, sequenceCounter, derivationConstant)
                );
        }

        /// <summary>
        /// Derives SCP03 session keys using AES-CMAC with specific derivation data.
        /// SCP03 v1.1.2, §4.1.5 and Table 4-1: 00, 01, 02, 04, 06, and 07.
        /// </summary>
        /// <param name="baseKey">The base static key (16, 24, or 32 bytes).</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <param name="cardChallenge">The card challenge (8 bytes).</param>
        /// <param name="derivationConstant">A derivation constant from Table 4-1.</param>
        /// <returns>The derived session key or error.</returns>
        public static Result<byte[], SmartCardError> DeriveScp03SessionKey(
            byte[] baseKey,
            byte[] hostChallenge,
            byte[] cardChallenge,
            byte derivationConstant
        )
        {
            return Validation
                .ValidateInputs(baseKey, hostChallenge)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            baseKey,
                            [16, 24, 32],
                            "SCP03 base key must be 16, 24, or 32 bytes"
                        )
                )
                .Bind(() => ValidateChallengeLength(hostChallenge, 8, "Host challenge"))
                .Bind(() => ValidateChallengeLength(cardChallenge, 8, "Card challenge"))
                .Bind(() => ValidateDerivationConstant(derivationConstant))
                .Bind(() =>
                {
                    // Build context as host Challenge || card Challenge
                    var context = hostChallenge.Concat(cardChallenge).ToArray();
                    // Use KDF108 to derive session key with same length as base key
                    return DeriveScp03Data(
                        baseKey,
                        derivationConstant,
                        context,
                        baseKey.Length * 8
                    );
                });
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
            // GlobalPlatform SCP03: S-RMAC uses derivation constant 0x07
            return DeriveScp03SessionKey(baseKey, hostChallenge, cardChallenge, 0x07);
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
                : UnitResult.Failure(
                    SmartCardError.InvalidArgument(
                        $"Sequence counter must be at least {expectedLength} bytes, got {sequenceCounter.Length}"
                    )
                );
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
                : UnitResult.Failure(
                    SmartCardError.InvalidArgument(
                        $"{challengeType} must be {expectedLength} bytes, got {challenge.Length}"
                    )
                );
        }

        /// <summary>
        /// Validates derivation constant is within valid range for SCP03.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateDerivationConstant(
            byte derivationConstant
        )
        {
            // SCP03 v1.1.2, Table 4-1. All other values are RFU.
            return derivationConstant is 0x00 or 0x01 or 0x02 or 0x04 or 0x06 or 0x07
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(
                    SmartCardError.InvalidArgument(
                        $"Derivation constant 0x{derivationConstant:X2} not allowed (GP SCP03 Table 4-1)"
                    )
                );
        }

        /// <summary>
        /// Validates SCP02 derivation constant is 2 bytes.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateScp02DerivationConstant(
            byte[] derivationConstant
        )
        {
            return derivationConstant is { Length: 2 }
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(
                    SmartCardError.InvalidArgument("SCP02 derivation constant must be 2 bytes")
                );
        }

        /// <summary>
        /// Performs SCP02 key derivation using 3DES-CBC matching ScpVerification implementation.
        /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.1.
        /// </summary>
        private static Result<byte[], SmartCardError> DeriveUsing3DesCbc(
            byte[] expandedKey,
            byte[] sequenceCounter,
            byte[] derivationConstant
        )
        {
            return Result.Try(
                () =>
                {
                    // Build derivation data: constant || sequenceCounter || padding (12 bytes of zeros)
                    byte[] derivationData = new byte[16];
                    Array.Copy(derivationConstant, 0, derivationData, 0, 2);
                    Array.Copy(sequenceCounter, 0, derivationData, 2, 2);
                    // Remaining 12 bytes are zeros (already initialized)

                    // Set odd parity on the expanded key
                    DesParameters.SetOddParity(expandedKey);

                    // Use 3DES-CBC with IV = 0 to match ScpVerification
                    var cipher = new CbcBlockCipher(new DesEdeEngine());
                    var parameters = new ParametersWithIV(
                        new DesEdeParameters(expandedKey),
                        new byte[8]
                    );
                    cipher.Init(true, parameters);

                    // Process two blocks to get 16-byte output
                    byte[] sessionKey = new byte[16];
                    cipher.ProcessBlock(derivationData, 0, sessionKey, 0);
                    cipher.ProcessBlock(derivationData, 8, sessionKey, 8);

                    return sessionKey;
                },
                ex =>
                    SmartCardError.CryptographicError($"SCP02 key derivation failed: {ex.Message}")
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
            return Validation
                .ValidateInputs(key, context)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            key,
                            [16, 24, 32],
                            "KDK must be 16, 24, or 32 bytes"
                        )
                )
                .Bind(() => ValidateOutputLength(outputLengthBits))
                .Bind(
                    () => BuildScp03DerivationInputs(derivationConstant, context, outputLengthBits)
                )
                .Bind(inputs =>
                    PerformKdf108Derivation(
                        key,
                        inputs.dataBeforeCounter,
                        inputs.dataAfterCounter,
                        outputLengthBits
                    )
                );
        }

        /// <summary>
        /// Derives SCP03 data using raw block inputs for the fixed input structure.
        /// </summary>
        public static Result<byte[], SmartCardError> DeriveScp03Data(
            byte[] key,
            byte[] dataBeforeCounter,
            byte[] dataAfterCounter,
            int outputLengthBits
        )
        {
            var before = dataBeforeCounter ?? Array.Empty<byte>();
            var after = dataAfterCounter ?? Array.Empty<byte>();

            return Validation
                .ValidateInputs(key, after)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            key,
                            new[] { 16, 24, 32 },
                            "KDK must be 16, 24, or 32 bytes"
                        )
                )
                .Bind(() => ValidateOutputLength(outputLengthBits))
                .Bind(() => PerformKdf108Derivation(key, before, after, outputLengthBits));
        }

        /// <summary>
        /// Derives session keys from the given context.
        /// Delegates to protocol-specific derivation based on context.
        /// </summary>
        /// <param name="context">The key derivation context containing all necessary parameters.</param>
        /// <returns>The derived session keys or an error.</returns>
        public static Result<SessionKeys, SmartCardError> DeriveSessionKeys(
            KeyDerivationContext context
        )
        {
            return context.Protocol switch
            {
                ScpVersion.Scp02 => DeriveScp02SessionKeysFromContext(context),
                ScpVersion.Scp03 => DeriveScp03SessionKeysFromContext(context),
                _
                    => Result.Failure<SessionKeys, SmartCardError>(
                        SmartCardError.InvalidArgument(
                            $"Unsupported SCP version: {context.Protocol}"
                        )
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
                : UnitResult.Failure(
                    SmartCardError.InvalidArgument(
                        $"Output length must be multiple of 8, positive, and <= 256 bits, got {outputLengthBits}"
                    )
                );
        }

        /// <summary>
        /// Builds SCP03 derivation inputs for KDF108.
        /// </summary>
        private static Result<
            (byte[] dataBeforeCounter, byte[] dataAfterCounter),
            SmartCardError
        > BuildScp03DerivationInputs(byte derivationConstant, byte[] context, int outputLengthBits)
        {
            // Build fixed input data before counter per GP SCP03 v1.1.1 Section 4.1.5
            byte[] dataBeforeCounter = new byte[15]; // Label (12) + Separator (1) + L (2)
            int offset = 0;

            // Label (11 bytes of 0x00 + derivation constant)
            // Per GP Card Spec v2.3 Amendment D: Label is 11 zeros followed by the derivation constant
            var labelBytes = Enumerable
                .Repeat((byte)0x00, 11)
                .Concat([derivationConstant])
                .ToArray();
            labelBytes.CopyTo(dataBeforeCounter, offset);
            offset += 12;

            // Separator (1 byte)
            dataBeforeCounter[offset++] = 0x00;

            // L (length in bits as 2-byte big-endian)
            dataBeforeCounter[offset++] = (byte)(outputLengthBits >> 8);
            dataBeforeCounter[offset++] = (byte)outputLengthBits;

            // Context data comes after counter - use it directly
            byte[] dataAfterCounter = context;

            return Result.Success<(byte[], byte[]), SmartCardError>(
                (dataBeforeCounter, dataAfterCounter)
            );
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
            var prfTypeResult = kdk.Length switch
            {
                16 => Result.Success<PrfType, SmartCardError>(PrfType.CmacAes128),
                24 => Result.Success<PrfType, SmartCardError>(PrfType.CmacAes192),
                32 => Result.Success<PrfType, SmartCardError>(PrfType.CmacAes256),
                _
                    => Result.Failure<PrfType, SmartCardError>(
                        SmartCardError.InvalidArgument(
                            $"Unsupported key length: {kdk.Length} bytes"
                        )
                    ),
            };

            return prfTypeResult.Bind(prfType =>
            {
                var options = new KdfOptions(
                    prfType: prfType,
                    counterLengthBits: 8, // SCP03 uses 8-bit counter
                    useCounter: true,
                    counterLocation: CounterLocation.MiddleFixed
                );

                return Result.Try(
                    () =>
                    {
                        var kdf = new Kdf108.Domain.Kdf.Modes.CounterModeKdf();
                        return kdf.DeriveWithSplitFixedInput(
                            kdk,
                            dataBeforeCounter,
                            dataAfterCounter,
                            outputLengthBits,
                            options
                        );
                    },
                    ex =>
                        SmartCardError.CryptographicError($"KDF108 derivation failed: {ex.Message}")
                );
            });
        }

        /// <summary>
        /// Derives SCP02 session keys from context.
        /// </summary>
        private static Result<SessionKeys, SmartCardError> DeriveScp02SessionKeysFromContext(
            KeyDerivationContext context
        )
        {
            return context
                .SequenceCounter.ToResult(
                    SmartCardError.InvalidArgument("SCP02 requires sequence counter")
                )
                .Bind(seqCounter =>
                    ValidateSequenceCounterLength(seqCounter, 2).Map(() => seqCounter)
                )
                .Bind(seqCounter =>
                {
                    // Use the existing SCP02 session key derivation methods with proper constants
                    var keySet = (Scp02KeySet)context.BaseKeySet;
                    var sMacResult = DeriveScp02SessionKey(
                        keySet.MacKey,
                        seqCounter,
                        Constants.Constants.Scp.Scp02.KeyDerivationConstants.SMac
                    );

                    var sEncResult = DeriveScp02SessionKey(
                        keySet.EncKey,
                        seqCounter,
                        Constants.Constants.Scp.Scp02.KeyDerivationConstants.SEnc
                    );

                    var sDekResult = DeriveScp02SessionKey(
                        keySet.DekKey,
                        seqCounter,
                        Constants.Constants.Scp.Scp02.KeyDerivationConstants.SDek
                    );

                    // GP Card Spec 2.3.1, E.4.1: S-RMAC uses derivation constant 01 02
                    // and is distinct from S-MAC, whose derivation constant is 01 01.
                    var sRmacResult = DeriveScp02SessionKey(
                        keySet.MacKey,
                        seqCounter,
                        Constants.Constants.Scp.Scp02.KeyDerivationConstants.SrMac
                    );

                    return sMacResult.Bind(sMac =>
                        sEncResult.Bind(sEnc =>
                            sRmacResult.Bind(sRmac =>
                                sDekResult.Map(sDek => new SessionKeys(
                                    sEnc,
                                    sMac,
                                    sRmac,
                                    Maybe<byte[]>.From(sDek)
                                ))
                            )
                        )
                    );
                });
        }

        /// <summary>
        /// Derives SCP03 session keys from context.
        /// </summary>
        private static Result<SessionKeys, SmartCardError> DeriveScp03SessionKeysFromContext(
            KeyDerivationContext context
        )
        {
            var keySet = (Scp03KeySet)context.BaseKeySet;

            // Derive S-MAC key (GlobalPlatform SCP03: derivation constant 0x06)
            var sMacResult = DeriveScp03SessionKey(
                keySet.MacKey,
                context.HostChallenge,
                context.CardChallenge,
                0x06 // S-MAC derivation constant per GP spec
            );

            // Derive S-ENC key (GlobalPlatform SCP03: derivation constant 0x04)
            var sEncResult = DeriveScp03SessionKey(
                keySet.EncKey,
                context.HostChallenge,
                context.CardChallenge,
                0x04 // S-ENC derivation constant per GP spec
            );

            // Derive S-RMAC key (receipt MAC)
            var sRmacResult = DeriveScp03ReceiptKey(
                keySet.MacKey,
                context.HostChallenge,
                context.CardChallenge
            );

            return sEncResult.Bind(sEnc =>
                sMacResult.Bind(sMac =>
                    sRmacResult.Map(sRmac =>
                    // SCP03 1.1.2, 6.1 and 6.2.8: SCP03 derives no session
                    // key for sensitive-data encryption. PUT KEY uses static Key-DEK.
                    new SessionKeys(sEnc, sMac, sRmac, keySet.DekKey))
                )
            );
        }
    }
}
