using System;
using Gp4Net.Constants;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Cryptography.Strategies
{
    /// <summary>
    /// Key derivation strategy for SCP02 protocol.
    /// Implements 3DES-based key derivation for various SCP02 implementation options.
    /// </summary>
    [PublicAPI]
    public class Scp02KeyDerivationStrategy : IKeyDerivationStrategy
    {
        private readonly ILogger<Scp02KeyDerivationStrategy> _logger;

        /// <summary>
        /// Initializes a new instance of Scp02KeyDerivationStrategy.
        /// </summary>
        /// <param name="logger">The logger.</param>
        public Scp02KeyDerivationStrategy(ILogger<Scp02KeyDerivationStrategy> logger)
        {
            ArgumentNullException.ThrowIfNull(logger);
            _logger = logger;
        }

        /// <inheritdoc />
        public bool Supports(IKeyDerivationContext context)
        {
            return context.ProtocolVersion == ProtocolIdentifiers.Scp02
                && context.KeySet is Scp02KeySet;
        }

        /// <inheritdoc />
        public SessionKeys DeriveSessionKeys(IKeyDerivationContext context)
        {
            if (!Supports(context))
            {
                throw new NotSupportedException(
                    $"SCP02 strategy does not support protocol {context.ProtocolVersion:X2}"
                );
            }

            var scp02KeySet = (Scp02KeySet)context.KeySet;

            if (context.SequenceCounter == null)
            {
                throw new ArgumentException(
                    "SCP02 requires sequence counter in context",
                    nameof(context)
                );
            }

            _logger.LogDebug(
                "Deriving SCP02 session keys with sequence counter length {Length}",
                context.SequenceCounter.Length
            );

            // For SCP02, session key derivation depends on the implementation option
            // For i=15 (and most common variants):
            // - S-ENC is derived using derivation constant 0x82
            // - S-MAC and S-RMAC use the static MAC key (no derivation)
            // - DEK uses the static DEK key (no derivation)

            var sEnc = Derive3DesKey(
                scp02KeySet.EncKey,
                DerivationConstants.DataEncryption,
                context.SequenceCounter
            );
            var sMac = scp02KeySet.MacKey; // Static for i=15
            var sRMac = scp02KeySet.MacKey; // Static for i=15
            var dek = scp02KeySet.DekKey; // Always static for SCP02

            _logger.LogDebug("Successfully derived SCP02 session keys");

            return new SessionKeys(sEnc, sMac, sRMac, dek);
        }

        /// <summary>
        /// Derives a 3DES key for SCP02 using the specified derivation constant and sequence counter.
        /// Implements the SCP02 key derivation scheme as defined in GlobalPlatform Card Specification.
        /// </summary>
        /// <param name="baseKey">The base key to derive from (16 or 24 bytes for 3DES).</param>
        /// <param name="derivationConstant">The derivation constant (e.g., 0x82 for data encryption).</param>
        /// <param name="sequenceCounter">The sequence counter (2 or 3 bytes).</param>
        /// <returns>The derived 3DES key.</returns>
        private byte[] Derive3DesKey(
            byte[] baseKey,
            byte derivationConstant,
            byte[] sequenceCounter
        )
        {
            ArgumentNullException.ThrowIfNull(baseKey);

            ArgumentNullException.ThrowIfNull(sequenceCounter);

            if (baseKey.Length != 16 && baseKey.Length != 24)
            {
                throw new ArgumentException(
                    "Base key must be 16 or 24 bytes for 3DES.",
                    nameof(baseKey)
                );
            }

            if (sequenceCounter.Length != 2 && sequenceCounter.Length != 3)
            {
                throw new ArgumentException(
                    "Sequence counter must be 2 or 3 bytes.",
                    nameof(sequenceCounter)
                );
            }

            _logger.LogDebug(
                "Deriving 3DES key with constant {Constant:X2}, sequence counter length {Length}",
                derivationConstant,
                sequenceCounter.Length
            );

            // SCP02 key derivation data construction:
            // For 2-byte sequence counter: derivation_constant || sequence_counter || 0x00 || 0x00 || 0x00 || 0x00 || 0x00 || 0x00
            // For 3-byte sequence counter: derivation_constant || sequence_counter || 0x00 || 0x00 || 0x00 || 0x00 || 0x00

            var derivationData = new byte[8];
            derivationData[0] = derivationConstant;

            // Copy sequence counter
            Array.Copy(sequenceCounter, 0, derivationData, 1, sequenceCounter.Length);

            // Remaining bytes are already 0x00 from array initialization

            // Encrypt the derivation data using 3DES-ECB with the base key
            var cipher = new BufferedBlockCipher(new DesEdeEngine());
            cipher.Init(true, new KeyParameter(baseKey));

            var output = new byte[cipher.GetOutputSize(derivationData.Length)];
            var len = cipher.ProcessBytes(derivationData, 0, derivationData.Length, output, 0);
            _ = cipher.DoFinal(output, len);

            // For 3DES, we need to return the appropriate key length
            // If the base key is 16 bytes, return 16 bytes
            // If the base key is 24 bytes, return 24 bytes
            if (baseKey.Length == 16)
            {
                var result = new byte[16];
                Array.Copy(output, 0, result, 0, 8);
                Array.Copy(output, 0, result, 8, 8); // Duplicate first 8 bytes

                _logger.LogDebug("Derived 16-byte 3DES key");
                return result;
            }
            else
            {
                // For 24-byte keys, we need to derive two 8-byte blocks
                var result = new byte[24];
                Array.Copy(output, 0, result, 0, 8);

                // Derive second block by incrementing the last byte of derivation data
                derivationData[7] = 0x01;
                len = cipher.ProcessBytes(derivationData, 0, derivationData.Length, output, 0);
                _ = cipher.DoFinal(output, len);
                Array.Copy(output, 0, result, 8, 8);

                // Third block is first block XORed with second block
                for (int i = 0; i < 8; i++)
                {
                    result[16 + i] = (byte)(result[i] ^ result[8 + i]);
                }

                _logger.LogDebug("Derived 24-byte 3DES key");
                return result;
            }
        }
    }
}
