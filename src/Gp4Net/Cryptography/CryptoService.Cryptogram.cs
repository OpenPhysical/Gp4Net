using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    /// <summary>
    /// Cryptogram operations for SCP02 and SCP03 authentication.
    /// Consolidates all cryptogram calculation methods from multiple classes.
    /// </summary>
    public static class Cryptogram
    {

        /// <summary>
        /// Calculates SCP02 Cryptogram using Full 3DES MAC (ISO 9797-1 Algorithm 1).
        /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.1 and E.4.2.
        /// </summary>
        /// <param name="sEncKey">The S-ENC session key (16 or 24 bytes).</param>
        /// <param name="data">The padded cryptogram data (must be multiple of 8 bytes).</param>
        /// <returns>8-byte cryptogram or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp02Cryptogram(
            byte[] sEncKey,
            byte[] data
        )
        {
            return Validation.ValidateInputs(sEncKey, data)
                .Bind(() => Validation.ValidateKeyLength(sEncKey, [16, 24], "SCP02 S-ENC key must be 16 or 24 bytes"))
                .Bind(() => Validation.ValidateDataPadding(data, 8, "Cryptogram data must be padded to 8-byte blocks"))
                .Bind(() => Utils.ExpandTripleDesKey(sEncKey))
                .Bind(expandedKey =>
                    Result.Try(
                        () =>
                        {
                            byte[] zeroIv = new byte[8];
                            DesEdeEngine engine = new DesEdeEngine();
                            CbcBlockCipher blockCipher = new CbcBlockCipher(engine);
                            blockCipher.Init(
                                true,
                                new ParametersWithIV(new KeyParameter(expandedKey), zeroIv)
                            );

                            int blockCount = data.Length / 8;
                            byte[] mac = Enumerable
                                .Range(0, blockCount)
                                .Aggregate(
                                    new byte[8],
                                    (currentBlock, blockIndex) =>
                                    {
                                        byte[] result = new byte[8];
                                        blockCipher.ProcessBlock(
                                            data,
                                            blockIndex * 8,
                                            result,
                                            0
                                        );
                                        return result;
                                    }
                                );

                            return mac;
                        }, static ex => SmartCardError.CryptographicError($"SCP02 Cryptogram calculation failed: {ex.Message}")
                    )
                );
        }

        /// <summary>
        /// Calculates SCP03 Cryptogram using full 16-byte AES-CMAC.
        /// Per GlobalPlatform SCP03 v1.1.1 Section 4.1.3 - used for authentication cryptograms.
        /// </summary>
        /// <param name="sEncKey">The S-ENC session key (16, 24, or 32 bytes).</param>
        /// <param name="data">The data to authenticate.</param>
        /// <returns>16-byte full MAC or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp03Cryptogram(
            byte[] sEncKey,
            byte[] data
        )
        {
            return Validation.ValidateInputs(sEncKey, data)
                .Bind(() => Validation.ValidateKeyLength(sEncKey, [16, 24, 32], "SCP03 S-ENC key must be 16, 24, or 32 bytes"))
                .Bind(() =>
                    Result.Try(
                        () =>
                        {
                            CMac cmac = new CMac(new AesEngine(), 128);
                            cmac.Init(new KeyParameter(sEncKey));
                            cmac.BlockUpdate(data, 0, data.Length);

                            byte[] fullMac = new byte[16];
                            cmac.DoFinal(fullMac, 0);

                            return fullMac;
                        }, static ex => SmartCardError.CryptographicError($"SCP03 Cryptogram calculation failed: {ex.Message}")
                    )
                );
        }

        /// <summary>
        /// Builds SCP02-specific card cryptogram data.
        /// Per GP Card Specification Appendix E.4.2.1: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6)
        /// with ISO 7816-4 padding to 24 bytes total.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <returns>The SCP02 card cryptogram data.</returns>
        public static Result<byte[], SmartCardError> BuildScp02CardCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            return ValidateHostChallenge(hostChallenge)
                .Bind(_ => ValidateCardChallenge(response.CardChallenge, 6))
                .Bind(_ => ExtractScp02SequenceCounter(response))
                .Bind(sequenceCounter =>
                {
                    byte[] seqCounterBytes = sequenceCounter[..2];
                    byte[] data = Utils.ConcatenateArrays(
                        hostChallenge,
                        seqCounterBytes,
                        response.CardChallenge
                    );
                    return Utils.PadToLength(data, 24);
                });
        }

        /// <summary>
        /// Builds SCP02-specific host cryptogram data.
        /// Per GP Card Specification Appendix E.4.2.2: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8)
        /// with ISO 7816-4 padding to 24 bytes total.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <returns>The SCP02 host cryptogram data.</returns>
        public static Result<byte[], SmartCardError> BuildScp02HostCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            return ValidateHostChallenge(hostChallenge)
                .Bind(_ => ValidateCardChallenge(response.CardChallenge, 6))
                .Bind(_ => ExtractScp02SequenceCounter(response))
                .Bind(sequenceCounter =>
                {
                    byte[] seqCounterBytes = sequenceCounter[..2];
                    byte[] data = Utils.ConcatenateArrays(
                        seqCounterBytes,
                        response.CardChallenge,
                        hostChallenge
                    );
                    return Utils.PadToLength(data, 24);
                });
        }

        /// <summary>
        /// Builds SCP03-specific card cryptogram data.
        /// Per GP SCP03 Specification: Host Challenge (8) || Card Challenge (8) (no padding required).
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <returns>The SCP03 card cryptogram data.</returns>
        public static Result<byte[], SmartCardError> BuildScp03CardCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            return ValidateHostChallenge(hostChallenge)
                .Bind(_ => ValidateCardChallenge(response.CardChallenge, 8))
                .Map(_ => Utils.ConcatenateArrays(hostChallenge, response.CardChallenge));
        }

        /// <summary>
        /// Builds SCP03-specific host cryptogram data.
        /// Per GP SCP03 Specification: Card Challenge (8) || Host Challenge (8) (no padding required).
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <returns>The SCP03 host cryptogram data.</returns>
        public static Result<byte[], SmartCardError> BuildScp03HostCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            return ValidateHostChallenge(hostChallenge)
                .Bind(_ => ValidateCardChallenge(response.CardChallenge, 8))
                .Map(_ => Utils.ConcatenateArrays(response.CardChallenge, hostChallenge));
        }

        /// <summary>
        /// Validates host challenge length and format.
        /// </summary>
        private static Result<byte[], SmartCardError> ValidateHostChallenge(byte[] hostChallenge)
        {
            return Maybe<byte[]>
                .From(hostChallenge)
                .ToResult(SmartCardError.InvalidArgument("Host challenge required"))
                .Bind(static challenge =>
                    challenge.Length == 8
                        ? Result.Success<byte[], SmartCardError>(challenge)
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.InvalidArgument($"Host challenge must be 8 bytes, got {challenge.Length}")
                        )
                );
        }

        /// <summary>
        /// Validates card challenge length and format.
        /// </summary>
        private static Result<byte[], SmartCardError> ValidateCardChallenge(
            byte[] cardChallenge,
            int expectedLength
        )
        {
            return Maybe<byte[]>
                .From(cardChallenge)
                .ToResult(SmartCardError.InvalidArgument("Card challenge required"))
                .Bind(challenge =>
                    challenge.Length == expectedLength
                        ? Result.Success<byte[], SmartCardError>(challenge)
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.InvalidArgument($"Card challenge must be {expectedLength} bytes, got {challenge.Length}")
                        )
                );
        }

        /// <summary>
        /// Extracts the 2-byte sequence counter from an SCP02 INITIALIZE UPDATE response.
        /// </summary>
        private static Result<byte[], SmartCardError> ExtractScp02SequenceCounter(
            InitializeUpdateResponse response
        )
        {
            return Maybe<byte[]>
                .From(response.SequenceCounter)
                .ToResult(SmartCardError.InvalidResponse("SequenceCounter required for SCP02"))
                .Bind(static counter =>
                    counter.Length >= 2
                        ? Result.Success<byte[], SmartCardError>(counter)
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.InvalidResponse($"SequenceCounter must be at least 2 bytes, got {counter.Length}")
                        )
                );
        }

        /// <summary>
        /// High-level card cryptogram calculation for card emulator.
        /// Dispatches to protocol-specific implementations based on SCP version.
        /// </summary>
        /// <param name="hostChallenge">8-byte host challenge.</param>
        /// <param name="cardChallenge">6 bytes for SCP02, 8 bytes for SCP03.</param>
        /// <param name="keys">Protocol-specific keyset (Scp02KeySet or Scp03KeySet).</param>
        /// <param name="scpVersion">0x02 for SCP02, 0x03 for SCP03.</param>
        /// <param name="implementation">SCP implementation parameter.</param>
        /// <param name="context">Sequence counter for SCP02 (2 bytes), None for SCP03.</param>
        /// <returns>8-byte cryptogram for SCP02, 8 or 16-byte for SCP03.</returns>
        public static Result<byte[], SmartCardError> CalculateCardCryptogram(
            byte[] hostChallenge,
            byte[] cardChallenge,
            IKeySet keys,
            byte scpVersion,
            byte implementation,
            Maybe<byte[]> context
        )
        {
            return scpVersion switch
            {
                0x02 => context
                    .ToResult(SmartCardError.InvalidArgument("SCP02 requires sequence counter in context"))
                    .Bind(sequenceCounter =>
                        Maybe<Scp02KeySet>.From(keys as Scp02KeySet)
                            .ToResult(SmartCardError.InvalidArgument("SCP02 requires Scp02KeySet"))
                            .Bind(scp02Keys =>
                                CryptogramParameters.ForScp02(
                                    hostChallenge,
                                    cardChallenge,
                                    sequenceCounter,
                                    scp02Keys
                                )
                            )
                    )
                    .Bind(CalculateCardCryptogram),

                0x03 => Maybe<Scp03KeySet>.From(keys as Scp03KeySet)
                    .ToResult(SmartCardError.InvalidArgument("SCP03 requires Scp03KeySet"))
                    .Bind(scp03Keys =>
                        CryptogramParameters.ForScp03(hostChallenge, cardChallenge, scp03Keys)
                    )
                    .Bind(CalculateCardCryptogram),

                _ => Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported SCP version: 0x{scpVersion:X2}")
                )
            };
        }

        /// <summary>
        /// High-level host cryptogram calculation for card emulator.
        /// Dispatches to protocol-specific implementations based on SCP version.
        /// </summary>
        /// <param name="hostChallenge">8-byte host challenge.</param>
        /// <param name="cardChallenge">6 bytes for SCP02, 8 bytes for SCP03.</param>
        /// <param name="keys">Protocol-specific keyset (Scp02KeySet or Scp03KeySet).</param>
        /// <param name="scpVersion">0x02 for SCP02, 0x03 for SCP03.</param>
        /// <param name="implementation">SCP implementation parameter.</param>
        /// <param name="context">Sequence counter for SCP02 (2 bytes), None for SCP03.</param>
        /// <returns>8-byte cryptogram for SCP02, 8 or 16-byte for SCP03.</returns>
        public static Result<byte[], SmartCardError> CalculateHostCryptogram(
            byte[] hostChallenge,
            byte[] cardChallenge,
            IKeySet keys,
            byte scpVersion,
            byte implementation,
            Maybe<byte[]> context
        )
        {
            return scpVersion switch
            {
                0x02 => context
                    .ToResult(SmartCardError.InvalidArgument("SCP02 requires sequence counter in context"))
                    .Bind(sequenceCounter =>
                        Maybe<Scp02KeySet>.From(keys as Scp02KeySet)
                            .ToResult(SmartCardError.InvalidArgument("SCP02 requires Scp02KeySet"))
                            .Bind(scp02Keys =>
                                CryptogramParameters.ForScp02(
                                    hostChallenge,
                                    cardChallenge,
                                    sequenceCounter,
                                    scp02Keys
                                )
                            )
                    )
                    .Bind(CalculateHostCryptogram),

                0x03 => Maybe<Scp03KeySet>.From(keys as Scp03KeySet)
                    .ToResult(SmartCardError.InvalidArgument("SCP03 requires Scp03KeySet"))
                    .Bind(scp03Keys =>
                        CryptogramParameters.ForScp03(hostChallenge, cardChallenge, scp03Keys)
                    )
                    .Bind(CalculateHostCryptogram),

                _ => Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported SCP version: 0x{scpVersion:X2}")
                )
            };
        }

        /// <summary>
        /// Calculates SCP02 card cryptogram using typed parameters.
        /// Per GP Card Specification v2.3.1 Section E.4.2.1.
        /// </summary>
        /// <param name="parameters">Validated SCP02 cryptogram parameters.</param>
        /// <returns>8-byte card cryptogram.</returns>
        public static Result<byte[], SmartCardError> CalculateCardCryptogram(
            Scp02CryptogramParameters parameters
        )
        {
            // Build card cryptogram data: Host Challenge || Sequence Counter || Card Challenge
            byte[] data = [.. parameters.HostChallenge , .. parameters.SequenceCounter, .. parameters.CardChallenge];

            // Add ISO 7816-4 padding to 24 bytes
            return Utils.PadToLength(data, 24)
                .Bind(paddedData => CalculateScp02Cryptogram(parameters.Keys.SEnc, paddedData));
        }

        /// <summary>
        /// Calculates SCP02 host cryptogram using typed parameters.
        /// Per GP Card Specification v2.3.1 Section E.4.2.2.
        /// </summary>
        /// <param name="parameters">Validated SCP02 cryptogram parameters.</param>
        /// <returns>8-byte host cryptogram.</returns>
        public static Result<byte[], SmartCardError> CalculateHostCryptogram(
            Scp02CryptogramParameters parameters
        )
        {
            // Build host cryptogram data: Sequence Counter || Card Challenge || Host Challenge
            byte[] data = [.. parameters.SequenceCounter
, .. parameters.CardChallenge, .. parameters.HostChallenge];

            // Add ISO 7816-4 padding to 24 bytes
            return Utils.PadToLength(data, 24)
                .Bind(paddedData => CalculateScp02Cryptogram(parameters.Keys.SEnc, paddedData));
        }

        /// <summary>
        /// Calculates SCP03 card cryptogram using typed parameters.
        /// Per GP SCP03 v1.1.1 Section 6.2.2.2.
        /// </summary>
        /// <param name="parameters">Validated SCP03 cryptogram parameters.</param>
        /// <returns>8-byte card cryptogram (truncated from 16-byte MAC).</returns>
        public static Result<byte[], SmartCardError> CalculateCardCryptogram(
            Scp03CryptogramParameters parameters
        )
        {
            // Build card cryptogram data with derivation constant '00'
            byte[] derivationConstant = new byte[11]; // 11 zero bytes for card cryptogram
            byte[] data = [.. derivationConstant, .. parameters.HostChallenge, .. parameters.CardChallenge];

            // Calculate AES-CMAC and truncate to 8 bytes
            return Mac.CalculateScp03FullMac(parameters.Keys.MacKey, data)
                .Map(static fullMac => fullMac.Take(8).ToArray());
        }

        /// <summary>
        /// Calculates SCP03 host cryptogram using typed parameters.
        /// Per GP SCP03 v1.1.1 Section 6.2.2.2.
        /// </summary>
        /// <param name="parameters">Validated SCP03 cryptogram parameters.</param>
        /// <returns>8-byte host cryptogram (truncated from 16-byte MAC).</returns>
        public static Result<byte[], SmartCardError> CalculateHostCryptogram(
            Scp03CryptogramParameters parameters
        )
        {
            // Build host cryptogram data with derivation constant '01'
            byte[] derivationConstant = new byte[11];
            derivationConstant[10] = 0x01; // Set last byte to 0x01 for host cryptogram
            byte[] data = [.. derivationConstant, .. parameters.HostChallenge, .. parameters.CardChallenge];

            // Calculate AES-CMAC and truncate to 8 bytes
            return Mac.CalculateScp03FullMac(parameters.Keys.MacKey, data)
                .Map(static fullMac => fullMac.Take(8).ToArray());
        }
    }
}
