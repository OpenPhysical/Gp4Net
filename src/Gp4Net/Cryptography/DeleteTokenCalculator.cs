using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;

namespace Gp4Net.Cryptography
{
    /// <summary>
    /// Implements Delete Token calculation per GP spec C.4.6 and Table 11-23.
    /// Currently supports AES CMAC only (adapt/extend for 3DES as needed).
    /// </summary>
    public static class DeleteTokenCalculator
    {
        /// <summary>
        /// Compute a spec-compliant Delete Token for the DELETE command, per GP Table C-9.
        /// </summary>
        /// <param name="macKey">Issuer Delete Token Key (AES).</param>
        /// <param name="p1">Command parameter P1.</param>
        /// <param name="p2">Command parameter P2.</param>
        /// <param name="aid">AID of object to delete.</param>
        /// <param name="optionalTlv">If present, extra TLV (e.g. B6 Control Reference Template and inner TLVs).</param>
        /// <returns>16-byte AES-CMAC Delete Token, per GP spec structure.</returns>
        public static byte[] ComputeDeleteToken(
            byte[] macKey,
            byte p1,
            byte p2,
            byte[] aid,
            byte[]? optionalTlv = null)
        {
            if (macKey == null || (macKey.Length != 16 && macKey.Length != 24 && macKey.Length != 32))
                throw new ArgumentException("Delete Token MAC key must be 16, 24, or 32 bytes for AES.");
            ArgumentNullException.ThrowIfNull(aid);
            if (aid.Length < 5 || aid.Length > 16) throw new ArgumentException("AID length must be 5-16 bytes per GP spec.");

            // Step 1: build TLV for object to delete (AID)
            var body = new List<byte>();
            body.Add(0x4F); // tag for AID
            body.Add((byte)aid.Length);
            body.AddRange(aid);
            // Add optional TLV (B6 etc) if present
            if (optionalTlv != null && optionalTlv.Length > 0)
                body.AddRange(optionalTlv);

            // Step 2: build BER-TLV length for body (L or 0x81 L or 0x82 LL)
            byte[] berLength = EncodeBerLength(body.Count);

            // Step 3: input buffer: P1||P2||length(BER) || TLV [4F... aid] [more TLVs]
            var input = new List<byte>();
            input.Add(p1); // DELETE P1
            input.Add(p2); // DELETE P2
            input.AddRange(berLength); // Length of body
            input.AddRange(body); // TLVs

            // Step 4: CMAC use
            var cmac = new Org.BouncyCastle.Crypto.Macs.CMac(new Org.BouncyCastle.Crypto.Engines.AesEngine(), 128);
            cmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(macKey));
            var mac = new byte[16];
            cmac.BlockUpdate(input.ToArray(), 0, input.Count);
            cmac.DoFinal(mac, 0);
            return mac;
        }

        /// <summary>
        /// Makes BER-TLV length encoding for length (1, 2, or 3 byte encoding).
        /// </summary>
        private static byte[] EncodeBerLength(int length)
        {
            if (length < 0x80)
                return new byte[] { (byte)length };
            if (length <= 0xFF)
                return new byte[] { 0x81, (byte)length };
            // Larger not expected for GP, but included for completeness
            return new byte[] { 0x82, (byte)((length >> 8) & 0xFF), (byte)(length & 0xFF) };
        }
    }
}