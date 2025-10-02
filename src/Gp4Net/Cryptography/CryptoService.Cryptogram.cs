using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    /// <summary>
    /// Cryptogram operations for SCP02 and SCP03 authentication.
    /// Consolidates all cryptogram calculation methods from multiple classes.
    /// </summary>
    public static class Cryptogram
    {
        // --- SCP02 CORE ---

        /// <summary>
        /// Calculates SCP02 Cryptogram using Full 3DES MAC (ISO 9797-1 Algorithm 1).
        /// Per GlobalPlatform Card Specification v2.3.1 Section B.1.2.1 and E.4.2.
        /// </summary>
        /// <param name="sEncKey">The S-ENC session key (16 or 24 bytes).</param>
        /// <param name="data">The unpadded cryptogram data (typically 16 bytes).</param>
        /// <returns>8-byte cryptogram or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp02Cryptogram(
            byte[] sEncKey,
            byte[] data
        )
        {
            return Validation
                .ValidateInputs(sEncKey, data)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            sEncKey,
                            [16, 24],
                            "SCP02 S-ENC key must be 16 or 24 bytes"
                        )
                )
                .Bind(() => Utils.ExpandTripleDesKey(sEncKey))
                .Bind(expandedKey =>
                    Result.Try(
                        () =>
                        {
                            // SCP02 cryptograms use 3DES-CBC encryption with ISO7816-4 padding
                            // and take the second block (bytes 8-15) as the cryptogram
                            // This matches GlobalPlatformPro's mac_3des function
                            var cipher = new PaddedBufferedBlockCipher(
                                new CbcBlockCipher(new DesEdeEngine()),
                                new ISO7816d4Padding()
                            );
                            cipher.Init(
                                true,
                                new ParametersWithIV(new DesEdeParameters(expandedKey), new byte[8])
                            );
                            cipher.ProcessBytes(data);
                            var encrypted = cipher.DoFinal();
                            return encrypted;
                        },
                        ex =>
                            SmartCardError.CryptographicError(
                                $"SCP02 Cryptogram calculation failed: {ex.Message}"
                            )
                    )
                )
                .Bind(ValidateAndExtractScp02Cryptogram);
        }

        /// <summary>
        /// Validates encrypted data length and extracts SCP02 cryptogram safely.
        /// Per GP specification and GlobalPlatformPro, cryptogram uses bytes [8..16] of encrypted result.
        /// </summary>
        /// <param name="encrypted">The encrypted data from SCP02 calculation.</param>
        /// <returns>8-byte cryptogram or error.</returns>
        private static Result<byte[], SmartCardError> ValidateAndExtractScp02Cryptogram(
            byte[] encrypted
        )
        {
            var minLength =
                Scp.Common.CRYPTOGRAM_EXTRACTION_OFFSET + Scp.Common.CRYPTOGRAM_EXTRACTION_LENGTH;
            return encrypted.Length >= minLength
                ? Result.Success<byte[], SmartCardError>(
                    encrypted
                        .Skip(Scp.Common.CRYPTOGRAM_EXTRACTION_OFFSET)
                        .Take(Scp.Common.CRYPTOGRAM_EXTRACTION_LENGTH)
                        .ToArray()
                )
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.CryptographicError(
                        $"Encrypted data too short for cryptogram extraction. Expected at least {minLength} bytes, got {encrypted.Length}"
                    )
                );
        }

        // --- SCP02 CONTEXT BUILDERS ---

        /// <summary>
        /// Builds SCP02-specific card cryptogram data.
        /// Per GP Card Spec v2.3.1 Section E.4.2, card cryptogram input is: host_challenge || sequence_counter || card_challenge
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response containing card data.</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <returns>The concatenated cryptogram input data or error.</returns>
        public static Result<byte[], SmartCardError> BuildScp02CardCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            return ValidateHostChallenge(hostChallenge)
                .Bind(_ => ValidateCardChallenge(response.CardChallenge, 6))
                .Bind(_ => ExtractScp02SequenceCounter(response))
                .Bind(sequenceCounter =>
                    sequenceCounter.Length >= Scp.Scp02.SEQUENCE_COUNTER_SIZE
                        ? Result.Success<byte[], SmartCardError>(
                            Utils.ConcatenateArrays(
                                hostChallenge,
                                sequenceCounter.Take(Scp.Scp02.SEQUENCE_COUNTER_SIZE).ToArray(),
                                response.CardChallenge
                            )
                        )
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.InvalidResponse(
                                $"Sequence counter too short for extraction. Expected at least {Scp.Scp02.SEQUENCE_COUNTER_SIZE} bytes, got {sequenceCounter.Length}"
                            )
                        )
                );
        }

        /// <summary>
        /// Builds SCP02-specific host cryptogram data.
        /// Per GP Card Spec v2.3.1 Section E.4.2, host cryptogram input is: sequence_counter || card_challenge || host_challenge
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response containing card data.</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <returns>The concatenated cryptogram input data or error.</returns>
        public static Result<byte[], SmartCardError> BuildScp02HostCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        )
        {
            return ValidateHostChallenge(hostChallenge)
                .Bind(_ => ValidateCardChallenge(response.CardChallenge, 6))
                .Bind(_ => ExtractScp02SequenceCounter(response))
                .Bind(sequenceCounter =>
                    sequenceCounter.Length >= Scp.Scp02.SEQUENCE_COUNTER_SIZE
                        ? Result.Success<byte[], SmartCardError>(
                            Utils.ConcatenateArrays(
                                sequenceCounter.Take(Scp.Scp02.SEQUENCE_COUNTER_SIZE).ToArray(),
                                response.CardChallenge,
                                hostChallenge
                            )
                        )
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.InvalidResponse(
                                $"Sequence counter too short for host cryptogram. Expected at least {Scp.Scp02.SEQUENCE_COUNTER_SIZE} bytes, got {sequenceCounter.Length}"
                            )
                        )
                );
        }

        // --- SCP03 CONTEXT BUILDERS ---

        /// <summary>
        /// Builds SCP03-specific card cryptogram data.
        /// Per GP Card Spec v2.3.1 Amendment D Section 6.2.1, both cryptograms use: host_challenge || card_challenge
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response containing card data.</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <returns>The concatenated cryptogram input data or error.</returns>
        public static Result<byte[], SmartCardError> BuildScp03CardCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        ) =>
            ValidateHostChallenge(hostChallenge)
                .Bind(_ => ValidateCardChallenge(response.CardChallenge, 8))
                .Map(_ => Utils.ConcatenateArrays(hostChallenge, response.CardChallenge));

        /// <summary>
        /// Builds SCP03-specific host cryptogram data.
        /// Per GP Card Spec v2.3.1 Amendment D Section 6.2.1, both cryptograms use: host_challenge || card_challenge
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response containing card data.</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <returns>The concatenated cryptogram input data or error.</returns>
        public static Result<byte[], SmartCardError> BuildScp03HostCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        ) =>
            ValidateHostChallenge(hostChallenge)
                .Bind(_ => ValidateCardChallenge(response.CardChallenge, 8))
                .Map(_ => Utils.ConcatenateArrays(hostChallenge, response.CardChallenge));

        // --- COMMON VALIDATION ---

        /// <summary>
        /// Validates host challenge length and format.
        /// </summary>
        /// <param name="hostChallenge">The host challenge to validate.</param>
        /// <returns>The validated host challenge or error.</returns>
        private static Result<byte[], SmartCardError> ValidateHostChallenge(byte[] hostChallenge) =>
            Maybe<byte[]>
                .From(hostChallenge)
                .ToResult(SmartCardError.InvalidArgument("Host challenge cannot be null"))
                .Bind(ch =>
                    ch.Length == 8
                        ? Result.Success<byte[], SmartCardError>(ch)
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.InvalidArgument(
                                $"Host challenge must be 8 bytes, got {ch.Length}"
                            )
                        )
                );

        /// <summary>
        /// Validates card challenge length and format.
        /// </summary>
        /// <param name="cardChallenge">The card challenge to validate.</param>
        /// <param name="expectedLength">The expected length (6 for SCP02, 8 for SCP03).</param>
        /// <returns>The validated card challenge or error.</returns>
        private static Result<byte[], SmartCardError> ValidateCardChallenge(
            byte[] cardChallenge,
            int expectedLength
        ) =>
            Maybe<byte[]>
                .From(cardChallenge)
                .ToResult(SmartCardError.InvalidArgument("Card challenge cannot be null"))
                .Bind(ch =>
                    ch.Length == expectedLength
                        ? Result.Success<byte[], SmartCardError>(ch)
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.InvalidArgument(
                                $"Card challenge must be {expectedLength} bytes, got {ch.Length}"
                            )
                        )
                );

        /// <summary>
        /// Extracts the 2-byte sequence counter from an SCP02 INITIALIZE UPDATE response.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <returns>The extracted sequence counter or error.</returns>
        private static Result<byte[], SmartCardError> ExtractScp02SequenceCounter(
            InitializeUpdateResponse response
        ) =>
            Maybe<byte[]>
                .From(response.SequenceCounter)
                .ToResult(SmartCardError.InvalidResponse("SequenceCounter cannot be null"))
                .Bind(counter =>
                    counter.Length >= 2
                        ? Result.Success<byte[], SmartCardError>(counter)
                        : Result.Failure<byte[], SmartCardError>(
                            SmartCardError.InvalidResponse(
                                $"SequenceCounter must be at least 2 bytes, got {counter.Length}"
                            )
                        )
                );

        // --- HIGH LEVEL DISPATCH (CARD CRYPTOGRAM) ---

        /// <summary>
        /// High-level card cryptogram calculation for card emulator.
        /// Dispatches to appropriate SCP version-specific implementation.
        /// </summary>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="cardChallenge">The card challenge.</param>
        /// <param name="keys">The key set for the SCP version.</param>
        /// <param name="scpVersion">The SCP version (0x02 or 0x03).</param>
        /// <param name="implementation">The SCP implementation parameter.</param>
        /// <param name="context">Additional context (sequence counter for SCP02).</param>
        /// <returns>The calculated card cryptogram or error.</returns>
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
                0x02
                    => context
                        .ToResult(
                            SmartCardError.InvalidArgument(
                                "SCP02 requires sequence counter in context"
                            )
                        )
                        .Bind(sequenceCounter =>
                            Maybe<Scp02KeySet>
                                .From(keys as Scp02KeySet)
                                .ToResult(
                                    SmartCardError.InvalidArgument("SCP02 requires Scp02KeySet")
                                )
                                .Bind(scp02Keys =>
                                    CryptogramParameters.ForScp02(
                                        hostChallenge,
                                        cardChallenge,
                                        sequenceCounter,
                                        scp02Keys
                                    )
                                )
                                .Bind(parameters => CalculateCardCryptogram(parameters))
                        ),

                0x03
                    => Maybe<Scp03KeySet>
                        .From(keys as Scp03KeySet)
                        .ToResult(SmartCardError.InvalidArgument("SCP03 requires Scp03KeySet"))
                        .Bind(scp03Keys =>
                            CryptogramParameters.ForScp03(hostChallenge, cardChallenge, scp03Keys)
                        )
                        .Bind(parameters => CalculateCardCryptogram(parameters)),

                _
                    => Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument(
                            $"Unsupported SCP version: 0x{scpVersion:X2}"
                        )
                    )
            };
        }

        // --- HIGH LEVEL DISPATCH (HOST CRYPTOGRAM) ---

        /// <summary>
        /// High-level host cryptogram calculation for card emulator.
        /// Dispatches to appropriate SCP version-specific implementation.
        /// </summary>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="cardChallenge">The card challenge.</param>
        /// <param name="keys">The key set for the SCP version.</param>
        /// <param name="scpVersion">The SCP version (0x02 or 0x03).</param>
        /// <param name="implementation">The SCP implementation parameter.</param>
        /// <param name="context">Additional context (sequence counter for SCP02).</param>
        /// <returns>The calculated host cryptogram or error.</returns>
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
                0x02
                    => context
                        .ToResult(
                            SmartCardError.InvalidArgument(
                                "SCP02 requires sequence counter in context"
                            )
                        )
                        .Bind(sequenceCounter =>
                            Maybe<Scp02KeySet>
                                .From(keys as Scp02KeySet)
                                .ToResult(
                                    SmartCardError.InvalidArgument("SCP02 requires Scp02KeySet")
                                )
                                .Bind(scp02Keys =>
                                    CryptogramParameters.ForScp02(
                                        hostChallenge,
                                        cardChallenge,
                                        sequenceCounter,
                                        scp02Keys
                                    )
                                )
                                .Bind(parameters => CalculateHostCryptogram(parameters))
                        ),

                0x03
                    => Maybe<Scp03KeySet>
                        .From(keys as Scp03KeySet)
                        .ToResult(SmartCardError.InvalidArgument("SCP03 requires Scp03KeySet"))
                        .Bind(scp03Keys =>
                            CryptogramParameters.ForScp03(hostChallenge, cardChallenge, scp03Keys)
                        )
                        .Bind(parameters => CalculateHostCryptogram(parameters)),

                _
                    => Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument(
                            $"Unsupported SCP version: 0x{scpVersion:X2}"
                        )
                    )
            };
        }

        // --- SCP02 TYPED ---

        /// <summary>
        /// Calculates SCP02 card cryptogram using typed parameters.
        /// </summary>
        /// <param name="parameters">The SCP02 cryptogram parameters.</param>
        /// <returns>The calculated card cryptogram or error.</returns>
        public static Result<byte[], SmartCardError> CalculateCardCryptogram(
            Scp02CryptogramParameters parameters
        )
        {
            byte[] data =
            [
                .. parameters.HostChallenge,
                .. parameters.SequenceCounter,
                .. parameters.CardChallenge
            ];
            return CalculateScp02Cryptogram(parameters.Keys.EncKey, data);
        }

        /// <summary>
        /// Calculates SCP02 host cryptogram using typed parameters.
        /// </summary>
        /// <param name="parameters">The SCP02 cryptogram parameters.</param>
        /// <returns>The calculated host cryptogram or error.</returns>
        public static Result<byte[], SmartCardError> CalculateHostCryptogram(
            Scp02CryptogramParameters parameters
        )
        {
            byte[] data =
            [
                .. parameters.SequenceCounter,
                .. parameters.CardChallenge,
                .. parameters.HostChallenge
            ];
            return CalculateScp02Cryptogram(parameters.Keys.EncKey, data);
        }

        // --- SCP03 KDF HELPERS (SPEC COMPLIANT) ---

        /// <summary>
        /// Calculates SCP03 card cryptogram using KDF.
        /// Per GP Card Spec v2.3.1 Amendment D Section 6.2.1.
        /// </summary>
        /// <param name="sMacKey">The S-MAC session key (16, 24, or 32 bytes).</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <param name="cardChallenge">The card challenge (8 bytes).</param>
        /// <returns>The calculated card cryptogram (8 bytes) or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp03CardCryptogram(
            byte[] sMacKey,
            byte[] hostChallenge,
            byte[] cardChallenge
        )
        {
            return Validation
                .ValidateInputs(sMacKey, hostChallenge, cardChallenge)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            sMacKey,
                            new[] { 16, 24, 32 },
                            "SCP03 S-MAC key must be 16, 24, or 32 bytes"
                        )
                )
                .Bind(() => Validation.ValidateChallenges(hostChallenge, cardChallenge))
                .Map(() => Utils.ConcatenateArrays(hostChallenge, cardChallenge))
                .Bind(context =>
                    KeyDerivation.DeriveScp03Data(
                        sMacKey,
                        Scp.Scp03.CryptogramDerivation.CardCryptogram,
                        context,
                        64
                    )
                );
        }

        /// <summary>
        /// Calculates SCP03 host cryptogram using KDF.
        /// Per GP Card Spec v2.3.1 Amendment D Section 6.2.1.
        /// </summary>
        /// <param name="sMacKey">The S-MAC session key (16, 24, or 32 bytes).</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <param name="cardChallenge">The card challenge (8 bytes).</param>
        /// <returns>The calculated host cryptogram (8 bytes) or error.</returns>
        public static Result<byte[], SmartCardError> CalculateScp03HostCryptogram(
            byte[] sMacKey,
            byte[] hostChallenge,
            byte[] cardChallenge
        )
        {
            return Validation
                .ValidateInputs(sMacKey, hostChallenge, cardChallenge)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            sMacKey,
                            new[] { 16, 24, 32 },
                            "SCP03 S-MAC key must be 16, 24, or 32 bytes"
                        )
                )
                .Bind(() => Validation.ValidateChallenges(hostChallenge, cardChallenge))
                .Map(() => Utils.ConcatenateArrays(hostChallenge, cardChallenge))
                .Bind(context =>
                    KeyDerivation.DeriveScp03Data(
                        sMacKey,
                        Scp.Scp03.CryptogramDerivation.HostCryptogram,
                        context,
                        64
                    )
                );
        }

        // --- SCP03 TYPED ---

        /// <summary>
        /// Calculates SCP03 card cryptogram using typed parameters.
        /// </summary>
        /// <param name="parameters">The SCP03 cryptogram parameters.</param>
        /// <returns>The calculated card cryptogram or error.</returns>
        public static Result<byte[], SmartCardError> CalculateCardCryptogram(
            Scp03CryptogramParameters parameters
        )
        {
            byte[] context = Utils.ConcatenateArrays(
                parameters.HostChallenge,
                parameters.CardChallenge
            );
            return KeyDerivation.DeriveScp03Data(
                parameters.Keys.MacKey,
                Scp.Scp03.CryptogramDerivation.CardCryptogram,
                context,
                64
            );
        }

        /// <summary>
        /// Calculates SCP03 host cryptogram using typed parameters.
        /// </summary>
        /// <param name="parameters">The SCP03 cryptogram parameters.</param>
        /// <returns>The calculated host cryptogram or error.</returns>
        public static Result<byte[], SmartCardError> CalculateHostCryptogram(
            Scp03CryptogramParameters parameters
        )
        {
            byte[] context = Utils.ConcatenateArrays(
                parameters.HostChallenge,
                parameters.CardChallenge
            );
            return KeyDerivation.DeriveScp03Data(
                parameters.Keys.MacKey,
                Scp.Scp03.CryptogramDerivation.HostCryptogram,
                context,
                64
            );
        }
    }
}
