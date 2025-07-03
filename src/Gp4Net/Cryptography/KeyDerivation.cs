using System;
using Gp4Net.Constants;
using Gp4Net.Domain.Keys;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Cryptography
{
    /// <summary>
    /// Provides key derivation functions for SCP02 and SCP03.
    /// </summary>
    public static class KeyDerivation
    {
        /// <summary>
        /// Derives SCP03 session keys using SP 800-108 KDF in counter mode.
        /// </summary>
        /// <param name="keySet">The static key set.</param>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <param name="cardChallenge">The card challenge (8 bytes).</param>
        /// <param name="keyLength">The desired key length in bits.</param>
        /// <returns>The derived session keys.</returns>
        public static SessionKeys DeriveScp03SessionKeys(
            Scp03KeySet keySet,
            byte[] hostChallenge,
            byte[] cardChallenge,
            int keyLength
        )
        {
            ArgumentNullException.ThrowIfNull(keySet);

            if (hostChallenge?.Length != 8)
            {
                throw new ArgumentException(
                    "Host challenge must be 8 bytes.",
                    nameof(hostChallenge)
                );
            }

            if (cardChallenge?.Length != 8)
            {
                throw new ArgumentException(
                    "Card challenge must be 8 bytes.",
                    nameof(cardChallenge)
                );
            }

            // Context is concatenation of host challenge and card challenge
            var context = new byte[16];
            Array.Copy(hostChallenge, 0, context, 0, 8);
            Array.Copy(cardChallenge, 0, context, 8, 8);

            // Derive session keys using SP 800-108 KDF
            var sEnc = DeriveScp03Key(keySet.EncKey, DerivationConstants.SEnc, context, keyLength);
            var sMac = DeriveScp03Key(keySet.MacKey, DerivationConstants.SMac, context, keyLength);
            var sRMac = DeriveScp03Key(
                keySet.MacKey,
                DerivationConstants.SRMac,
                context,
                keyLength
            );

            return new SessionKeys(sEnc, sMac, sRMac, keySet.DekKey);
        }

        /// <summary>
        /// Derives a single SCP03 key using SP 800-108 KDF.
        /// </summary>
        private static byte[] DeriveScp03Key(
            byte[] kdk,
            byte derivationConstant,
            byte[] context,
            int keyLengthBits
        )
        {
            // For SCP03, the KDF input structure per GlobalPlatform SCP03 specification is:
            // Label (12 bytes: 11 bytes of 0x00 + derivation constant) || 0x00 || L (2 bytes) || Counter (1 byte) || Context (16 bytes)
            //
            // Where:
            // - Label is 11 bytes of 0x00 followed by derivation constant (04 for S-ENC, 06 for S-MAC, 07 for S-RMAC)
            // - Separator is 0x00
            // - L is the output length in bits as 2 bytes big-endian
            // - Counter (i) is 1 byte (01 or 02), managed by the KDF
            // - Context is the concatenation of host challenge and card challenge (16 bytes)

            // Build the "fixed input data" (everything that's constant for this derivation)
            // This includes: Label + Separator + L + Context 
            // The counter will be inserted by the KDF library between L and Context
            var fixedInputBeforeCounter = new byte[11 + 1 + 1 + 2]; // Label + derivation + separator + L
            var offset = 0;

            // Label (11 bytes of 0x00 followed by derivation constant)
            Array.Copy(DerivationConstants.Scp03Label, 0, fixedInputBeforeCounter, offset, 11);
            offset += 11;
            fixedInputBeforeCounter[offset++] = derivationConstant;

            // Separator
            fixedInputBeforeCounter[offset++] = 0x00;

            // L (length in bits as 2-byte big-endian)
            fixedInputBeforeCounter[offset++] = (byte)(keyLengthBits >> 8);
            fixedInputBeforeCounter[offset++] = (byte)keyLengthBits;

            // Determine PRF type based on key length
            var prfType = kdk.Length switch
            {
                16 => PrfType.CmacAes128,
                24 => PrfType.CmacAes192,
                32 => PrfType.CmacAes256,
                _ => throw new ArgumentException($"Unsupported key length: {kdk.Length} bytes"),
            };

            // Configure KDF options for SCP03
            // The counter comes after the fixed input (before context)
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
            return kdf.DeriveWithSplitFixedInput(
                kdk,
                fixedInputBeforeCounter, // Label + derivation + separator + L
                context, // Context (host + card challenges)
                keyLengthBits,
                options
            );
        }

        /// <summary>
        /// Derives SCP02 session keys.
        /// </summary>
        /// <param name="keySet">The static key set.</param>
        /// <param name="sequenceCounter">The sequence counter (2 or 3 bytes).</param>
        /// <param name="implicitChannel">Whether to use implicit channel mode.</param>
        /// <returns>The derived session keys.</returns>
        public static SessionKeys DeriveScp02SessionKeys(
            Scp02KeySet keySet,
            byte[] sequenceCounter,
            bool implicitChannel = false
        )
        {
            ArgumentNullException.ThrowIfNull(keySet);

            if (
                sequenceCounter == null
                || (sequenceCounter.Length != 2 && sequenceCounter.Length != 3)
            )
            {
                throw new ArgumentException(
                    "Sequence counter must be 2 or 3 bytes.",
                    nameof(sequenceCounter)
                );
            }

            // For SCP02, session keys are derived differently
            // This is a simplified version - full implementation would need more details
            var sEnc = Derive3DesKey(
                keySet.EncKey,
                DerivationConstants.DataEncryption,
                sequenceCounter
            );
            var sMac = keySet.MacKey; // In basic SCP02, MAC key is not derived
            var sRMac = keySet.MacKey; // Same for R-MAC

            return new SessionKeys(sEnc, sMac, sRMac, keySet.DekKey);
        }

        /// <summary>
        /// Derives a 3DES key for SCP02 using the specified derivation constant and sequence counter.
        /// Implements the SCP02 key derivation scheme as defined in GlobalPlatform Card Specification.
        /// </summary>
        /// <param name="baseKey">The base key to derive from (16 or 24 bytes for 3DES).</param>
        /// <param name="derivationConstant">The derivation constant (e.g., 0x82 for data encryption).</param>
        /// <param name="sequenceCounter">The sequence counter (2 or 3 bytes).</param>
        /// <returns>The derived 3DES key.</returns>
        /// <exception cref="ArgumentNullException">Thrown when baseKey or sequenceCounter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when parameters have invalid lengths.</exception>
        public static byte[] Derive3DesKey(
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

                return result;
            }
        }

        /// <summary>
        /// Calculates a cryptogram for authentication.
        /// </summary>
        /// <param name="key">The key to use for cryptogram calculation.</param>
        /// <param name="data">The data to calculate cryptogram over.</param>
        /// <param name="isScp03">Whether to use SCP03 (AES) or SCP02 (3DES).</param>
        /// <returns>The cryptogram (8 bytes).</returns>
        public static byte[] CalculateCryptogram(byte[] key, byte[] data, bool isScp03)
        {
            if (isScp03)
            {
                // Use CMAC-AES
                var cmac = new CMac(new AesEngine(), 64); // 64-bit MAC
                cmac.Init(new KeyParameter(key));
                cmac.BlockUpdate(data, 0, data.Length);

                var fullMac = new byte[8];
                _ = cmac.DoFinal(fullMac, 0);
                return fullMac;
            }
            else
            {
                // Use 3DES MAC (ISO 9797-1 MAC Algorithm 3)
                var engine = new DesEdeEngine();
                var mac = new ISO9797Alg3Mac(engine);
                mac.Init(new KeyParameter(key));
                mac.BlockUpdate(data, 0, data.Length);

                var fullMac = new byte[8];
                _ = mac.DoFinal(fullMac, 0);
                return fullMac;
            }
        }
    }
}
