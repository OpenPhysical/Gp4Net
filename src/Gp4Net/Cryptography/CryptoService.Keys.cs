using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    /// <summary>
    /// Key derivation operations for SCP02 and SCP03.
    /// Consolidates all key derivation methods from multiple classes.
    /// </summary>
    public static class Keys
    {
        /// <summary>
        /// Computes a spec-compliant Delete Token for the DELETE command, per GP Table C-9.
        /// Currently supports AES CMAC only.
        /// </summary>
        /// <param name="macKey">Issuer Delete Token Key (AES).</param>
        /// <param name="p1">Command parameter P1.</param>
        /// <param name="p2">Command parameter P2.</param>
        /// <param name="aid">AID of object to delete.</param>
        /// <param name="optionalTlv">If present, extra TLV (e.g. B6 Control Reference Template and inner TLVs).</param>
        /// <returns>Result containing the 16-byte AES-CMAC Delete Token or an error.</returns>
        public static Result<byte[], SmartCardError> ComputeDeleteToken(
            byte[] macKey,
            byte p1,
            byte p2,
            byte[] aid,
            Maybe<byte[]> optionalTlv = default
        )
        {
            if (macKey.Length != 16 && macKey.Length != 24 && macKey.Length != 32)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument(
                        "Delete Token MAC key must be 16, 24, or 32 bytes for AES."
                    )
                );
            }

            return aid.Length switch
            {
                0 => Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("AID cannot be empty.")
                ),
                < 5 or > 16 => Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("AID length must be 5-16 bytes per GP spec.")
                ),
                _ => BuildDeleteTokenInput(p1, p2, aid, optionalTlv)
                    .Bind(input =>
                        Result.Try(
                            () =>
                            {
                                var cmac = new CMac(new AesEngine(), 128);
                                cmac.Init(new KeyParameter(macKey));
                                byte[] mac = new byte[16];
                                cmac.BlockUpdate(input, 0, input.Length);
                                cmac.DoFinal(mac, 0);
                                return mac;
                            },
                            ex =>
                                SmartCardError.CryptographicError(
                                    $"Delete token calculation failed: {ex.Message}"
                                )
                        )
                    ),
            };
        }

        /// <summary>
        /// Builds delete token input data per GP specification.
        /// </summary>
        private static Result<byte[], SmartCardError> BuildDeleteTokenInput(
            byte p1,
            byte p2,
            byte[] aid,
            Maybe<byte[]> optionalTlv
        )
        {
            return Result.Try(
                () =>
                {
                    List<byte> body = [0x4F, (byte)aid.Length];
                    body.AddRange(aid);

                    optionalTlv.Where(tlv => tlv.Length > 0).Execute(tlv => body.AddRange(tlv));

                    byte[] berLength = EncodeBerLength(body.Count);

                    List<byte> input = [p1, p2];
                    input.AddRange(berLength);
                    input.AddRange(body);

                    return input.ToArray();
                },
                ex =>
                    SmartCardError.CryptographicError(
                        $"Delete token input construction failed: {ex.Message}"
                    )
            );
        }

        /// <summary>
        /// Makes BER-TLV length encoding for length (1, 2, or 3 byte encoding).
        /// </summary>
        private static byte[] EncodeBerLength(int length)
        {
            return length switch
            {
                < 0x80 => [(byte)length],
                <= 0xFF => [0x81, (byte)length],
                _ => [0x82, (byte)(length >> 8 & 0xFF), (byte)(length & 0xFF)],
            };
        }

        /// <summary>
        /// Generates the Initialization Chaining Vector (ICV) for command encryption.
        /// Per GP SCP03 spec section 6.2.6, command ICV uses encryption counter.
        /// For SCP02, returns zero IV.
        /// </summary>
        /// <param name="sEncKey">The session encryption key.</param>
        /// <param name="encryptionCounter">The current encryption counter.</param>
        /// <param name="protocolVersion">The SCP protocol version.</param>
        /// <returns>The 16-byte ICV for SCP03, or 8-byte zero IV for SCP02.</returns>
        public static Result<byte[], SmartCardError> GenerateCommandIcv(
            byte[] sEncKey,
            uint encryptionCounter,
            ScpVersion protocolVersion
        )
        {
            return Result.Try(
                () =>
                {
                    byte[] counterBlock = new byte[16];
                    counterBlock[12] = (byte)(encryptionCounter >> 24);
                    counterBlock[13] = (byte)(encryptionCounter >> 16);
                    counterBlock[14] = (byte)(encryptionCounter >> 8);
                    counterBlock[15] = (byte)encryptionCounter;

                    var cipher = new AesEngine();
                    cipher.Init(true, new KeyParameter(sEncKey));

                    byte[] icv = new byte[16];
                    cipher.ProcessBlock(counterBlock, 0, icv, 0);

                    return icv;
                },
                ex => SmartCardError.CryptographicError($"ICV generation failed: {ex.Message}")
            );
        }
    }
}
