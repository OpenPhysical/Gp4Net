using System;
using Gp4Net.Constants;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Cryptography.Strategies
{
    /// <summary>
    /// Key derivation strategy for SCP03 protocol.
    /// Implements SP 800-108 KDF in counter mode using CMAC-AES.
    /// </summary>
    [PublicAPI]
    public class Scp03KeyDerivationStrategy : IKeyDerivationStrategy
    {
        private readonly ILogger<Scp03KeyDerivationStrategy> _logger;

        /// <summary>
        /// Initializes a new instance of Scp03KeyDerivationStrategy.
        /// </summary>
        /// <param name="logger">The logger.</param>
        public Scp03KeyDerivationStrategy(ILogger<Scp03KeyDerivationStrategy> logger)
        {
            ArgumentNullException.ThrowIfNull(logger);
            _logger = logger;
        }

        /// <inheritdoc />
        public bool Supports(IKeyDerivationContext context)
        {
            return context.ProtocolVersion == ProtocolIdentifiers.Scp03
                && context.KeySet is Scp03KeySet;
        }

        /// <inheritdoc />
        public SessionKeys DeriveSessionKeys(IKeyDerivationContext context)
        {
            if (!Supports(context))
            {
                throw new NotSupportedException(
                    $"SCP03 strategy does not support protocol {context.ProtocolVersion:X2}"
                );
            }

            var scp03KeySet = (Scp03KeySet)context.KeySet;

            _logger.LogDebug(
                "Deriving SCP03 session keys with {KeyLength}-bit keys",
                scp03KeySet.EncKey.Length * 8
            );

            // Context is concatenation of host challenge and card challenge
            var derivationContext = new byte[16];
            Array.Copy(context.HostChallenge, 0, derivationContext, 0, 8);
            Array.Copy(context.CardChallenge, 0, derivationContext, 8, 8);

            var keyLength = scp03KeySet.EncKey.Length * 8;

            // Derive session keys using SP 800-108 KDF
            var sEnc = DeriveScp03Key(
                scp03KeySet.EncKey,
                DerivationConstants.SEnc,
                derivationContext,
                keyLength
            );
            var sMac = DeriveScp03Key(
                scp03KeySet.MacKey,
                DerivationConstants.SMac,
                derivationContext,
                keyLength
            );
            var sRMac = DeriveScp03Key(
                scp03KeySet.MacKey,
                DerivationConstants.SRMac,
                derivationContext,
                keyLength
            );

            _logger.LogDebug("Successfully derived SCP03 session keys");

            return new SessionKeys(sEnc, sMac, sRMac, scp03KeySet.DekKey);
        }

        /// <summary>
        /// Derives a single SCP03 key using SP 800-108 KDF in counter mode.
        /// </summary>
        /// <param name="kdk">The key derivation key.</param>
        /// <param name="derivationConstant">The derivation constant (S-ENC, S-MAC, S-RMAC).</param>
        /// <param name="context">The derivation context (host + card challenge).</param>
        /// <param name="keyLengthBits">The desired key length in bits.</param>
        /// <returns>The derived key.</returns>
        private byte[] DeriveScp03Key(
            byte[] kdk,
            byte derivationConstant,
            byte[] context,
            int keyLengthBits
        )
        {
            // For SCP03, the KDF input structure is:
            // Counter || Label || 0x00 || Derivation Constant || 0x00 || L || Context
            //
            // Where:
            // - Counter (i) is 1 byte, managed by the KDF (not included in our fixed input)
            // - Label is 11 bytes of 0x00
            // - Derivation Constant is 1 byte (04 for S-ENC, 06 for S-MAC, 07 for S-RMAC)
            // - L is the output length in bits as 2 bytes big-endian
            // - Context is the concatenation of host challenge and card challenge (16 bytes)

            // Build fixed input (everything except the counter)
            var fixedInput = new byte[11 + 1 + 1 + 1 + 2 + context.Length]; // Total: 32 bytes
            var offset = 0;

            // Label (11 bytes of 0x00)
            Array.Copy(DerivationConstants.Scp03Label, 0, fixedInput, offset, 11);
            offset += 11;

            // Separator
            fixedInput[offset++] = 0x00;

            // Derivation constant
            fixedInput[offset++] = derivationConstant;

            // Separator
            fixedInput[offset++] = 0x00;

            // L (length in bits as 2-byte big-endian)
            fixedInput[offset++] = (byte)(keyLengthBits >> 8);
            fixedInput[offset++] = (byte)keyLengthBits;

            // Context
            Array.Copy(context, 0, fixedInput, offset, context.Length);

            // Determine PRF type based on key length
            var prfType = kdk.Length switch
            {
                16 => PrfType.CmacAes128,
                24 => PrfType.CmacAes192,
                32 => PrfType.CmacAes256,
                _ => throw new ArgumentException($"Unsupported key length: {kdk.Length} bytes"),
            };

            // Configure KDF options for SCP03
            var options = new KdfOptions(
                prfType: prfType,
                counterLengthBits: 8, // SCP03 uses 8-bit counter
                useCounter: true,
                counterLocation: CounterLocation.BeforeFixed // Counter comes before fixed input
            );

            var kdf = new CounterModeKdf();

            // Use DeriveWithSplitFixedInput with empty before array
            // This puts the counter at the beginning, followed by our fixed input
            var derivedKey = kdf.DeriveWithSplitFixedInput(
                kdk,
                new byte[0], // empty before array
                fixedInput, // all our fixed data goes in the after array
                keyLengthBits,
                options
            );

            _logger.LogDebug(
                "Derived SCP03 key with constant {Constant:X2}, length {Length} bits",
                derivationConstant,
                keyLengthBits
            );

            return derivedKey;
        }
    }
}
