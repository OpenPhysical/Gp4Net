using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Org.BouncyCastle.Crypto.Macs;

namespace Gp4Net.Cryptography;

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
    /// <returns>Result containing the 16-byte AES-CMAC Delete Token or an error.</returns>
    public static Result<byte[], SmartCardError> ComputeDeleteToken(
        byte[] macKey,
        byte p1,
        byte p2,
        byte[] aid,
        Maybe<byte[]> optionalTlv = default)
    {
        if (macKey.Length != 16 && macKey.Length != 24 && macKey.Length != 32)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Delete Token MAC key must be 16, 24, or 32 bytes for AES."));
        }

        switch (aid.Length)
        {
            case 0:
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("AID cannot be empty."));
            case < 5:
            case > 16:
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("AID length must be 5-16 bytes per GP spec."));
        }

        // Step 1: build TLV for object to delete (AID)
        List<byte> body =
        [
            0x4F, // tag for AID
            (byte)aid.Length
        ];
        body.AddRange(aid);
        // Add optional TLV (B6 etc) if present
        if (optionalTlv.HasValue && optionalTlv.Value.Length > 0)
        {
            body.AddRange(optionalTlv.Value);
        }

        // Step 2: build BER-TLV length for body (L or 0x81 L or 0x82 LL)
        byte[] berLength = EncodeBerLength(body.Count);

        // Step 3: input buffer: P1||P2||length(BER) || TLV [4F... aid] [more TLVs]
        List<byte> input =
        [
            p1, // DELETE P1
            p2 // DELETE P2
        ];
        input.AddRange(berLength); // Length of body
        input.AddRange(body); // TLVs

        // Step 4: CMAC use
        CMac cmac = new Org.BouncyCastle.Crypto.Macs.CMac(new Org.BouncyCastle.Crypto.Engines.AesEngine(), 128);
        cmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(macKey));
        byte[] mac = new byte[16];
        cmac.BlockUpdate(input.ToArray(), 0, input.Count);
        _ = cmac.DoFinal(mac, 0);
        return Result.Success<byte[], SmartCardError>(mac);
    }

    /// <summary>
    /// Makes BER-TLV length encoding for length (1, 2, or 3 byte encoding).
    /// </summary>
    private static byte[] EncodeBerLength(int length)
    {
        switch (length)
        {
            case < 0x80:
                return [(byte)length];
            case <= 0xFF:
                return [0x81, (byte)length];
            default:
                // Larger not expected for GP, but included for completeness
                return [0x82, (byte)((length >> 8) & 0xFF), (byte)(length & 0xFF)];
        }

    }
}
