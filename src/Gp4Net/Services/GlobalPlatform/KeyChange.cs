using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using static Gp4Net.Cryptography.CryptoOperations;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>Creates and executes GP 2.3.1 PUT KEY operations for SCP02 and SCP03 keysets.</summary>
public static class KeyChange
{
    public static Result<
        (byte ReplacedVersion, byte NewVersion),
        SmartCardError
    > GetDefaultVersions(byte activeVersion)
    {
        if (activeVersion == 0x00)
            return SmartCardError.InvalidArgument("Active key version cannot be 00.");

        // GP Card Spec 2.3.1, 11.8.2.1 and 11.8.2.3: P1=00 adds keys;
        // a new Key Version Number is encoded from 01 through 7F.
        return activeVersion == 0xFF
            ? (ReplacedVersion: (byte)0x00, NewVersion: (byte)0x01)
            : (
                ReplacedVersion: activeVersion,
                NewVersion: activeVersion == 0x7F ? (byte)0x01 : (byte)(activeVersion + 1)
            );
    }

    public static Result<PutKeyCommand, SmartCardError> CreateCommand(
        IKeySet newKeys,
        SecureChannelState secureChannel,
        byte replacedKeyVersion,
        byte? firstKeyIdentifier = null
    )
    {
        return secureChannel
            .SessionKeys.Dek.ToResult(
                SmartCardError.InvalidArgument("The secure channel has no data-encryption key.")
            )
            .Bind(dek => CreateBlocks(newKeys, secureChannel.ProtocolVersion, dek))
            .Bind(blocks =>
                PutKeyCommand.CreateReplacement(
                    replacedKeyVersion,
                    newKeys.KeyVersion,
                    firstKeyIdentifier ?? newKeys.KeyId,
                    blocks
                )
            );
    }

    public static async Task<Result<PutKeyResponse, SmartCardError>> ExecuteAsync(
        Func<
            WSCT.ISO7816.CommandAPDU,
            bool,
            CancellationToken,
            Task<Result<Gp4Net.Pipeline.CommandResponse, SmartCardError>>
        > execute,
        SecureChannelState secureChannel,
        IKeySet newKeys,
        byte replacedKeyVersion,
        byte? firstKeyIdentifier = null,
        CancellationToken cancellationToken = default
    )
    {
        var commandResult = CreateCommand(
            newKeys,
            secureChannel,
            replacedKeyVersion,
            firstKeyIdentifier
        );
        if (commandResult.IsFailure)
            return commandResult.Error;

        var response = await execute(commandResult.Value.ToApdu(), true, cancellationToken);
        return response
            .Bind(Responses.ParsePutKeyResponse)
            .Bind(parsed => VerifyResponse(parsed, newKeys));
    }

    private static Result<IList<KeyDataBlock>, SmartCardError> CreateBlocks(
        IKeySet keys,
        ScpVersion protocol,
        byte[] dek
    )
    {
        var values = new[] { keys.EncKey, keys.MacKey, keys.DekKey };
        var blocks = new List<KeyDataBlock>(3);
        foreach (var key in values)
        {
            var prepared = PrepareBlock(key, protocol, dek);
            if (prepared.IsFailure)
                return prepared.Error;
            blocks.Add(prepared.Value);
        }
        return blocks;
    }

    private static Result<KeyDataBlock, SmartCardError> PrepareBlock(
        byte[] key,
        ScpVersion protocol,
        byte[] dek
    )
    {
        return Result.Try(
            () =>
            {
                bool aes = protocol == ScpVersion.Scp03;
                byte[] padded = PadRight(key, aes ? 16 : 8);
                // SCP03 1.1.2, 6.2.8: encrypt key-sensitive data with static
                // Key-DEK using AES-CBC and an all-zero ICV. GP 2.3.1,
                // 11.8.2.3.2 and Tables 11-70/71 define component padding/format.
                byte[] encrypted = aes
                    ? Transform(
                        new CbcBlockCipher(new AesEngine()),
                        dek,
                        new byte[16],
                        padded,
                        true
                    )
                    : Transform(new DesEdeEngine(), NormalizeDesEdeKey(dek), null, padded, true);
                byte[] component =
                    aes || padded.Length != key.Length
                        ? new[] { (byte)key.Length }.Concat(encrypted).ToArray()
                        : encrypted;
                byte[] kcv = CalculateKcv(key, aes);
                var type = aes
                    ? KeyDataBlock.KeyType.Aes128
                    : key.Length == 24
                        ? KeyDataBlock.KeyType.TripleDes3Key
                        : KeyDataBlock.KeyType.TripleDes2Key;
                return KeyDataBlock.CreatePrepared(type, component, kcv).Value;
            },
            ex => SmartCardError.CryptographicError($"PUT KEY preparation failed: {ex.Message}")
        );
    }

    private static Result<PutKeyResponse, SmartCardError> VerifyResponse(
        PutKeyResponse response,
        IKeySet newKeys
    )
    {
        bool aes = newKeys is Scp03KeySet;
        var expected = new[]
        {
            CalculateKcv(newKeys.EncKey, aes),
            CalculateKcv(newKeys.MacKey, aes),
            CalculateKcv(newKeys.DekKey, aes),
        };
        return
            response.KeyVersion == newKeys.KeyVersion
            && response.KeyCheckValues.Count == expected.Length
            && response
                .KeyCheckValues.Zip(expected)
                .All(pair => pair.First.SequenceEqual(pair.Second))
            ? response
            : SmartCardError.InvalidResponse(
                "Card returned a different key version or key check value."
            );
    }

    public static byte[] CalculateKcv(byte[] key, bool aes)
    {
        // GP Card Spec 2.3.1, B.6: DES encrypts 8 zero bytes; AES encrypts
        // 16 bytes of 01, retaining the three most-significant result bytes.
        byte[] input = Enumerable.Repeat(aes ? (byte)0x01 : (byte)0x00, aes ? 16 : 8).ToArray();
        byte[] output = aes
            ? Transform(new AesEngine(), key, null, input, true)
            : Transform(new DesEdeEngine(), NormalizeDesEdeKey(key), null, input, true);
        return output.Take(3).ToArray();
    }

    public static byte[] Unwrap(byte[] component, int clearLength, ScpVersion protocol, byte[] dek)
    {
        bool aes = protocol == ScpVersion.Scp03;
        byte[] clear = aes
            ? Transform(new CbcBlockCipher(new AesEngine()), dek, new byte[16], component, false)
            : Transform(new DesEdeEngine(), NormalizeDesEdeKey(dek), null, component, false);
        return clear.Take(clearLength).ToArray();
    }

    private static byte[] Transform(
        IBlockCipher cipher,
        byte[] key,
        byte[]? iv,
        byte[] data,
        bool encrypt
    )
    {
        ICipherParameters parameters = new KeyParameter(key);
        if (iv is not null)
            parameters = new ParametersWithIV(parameters, iv);
        cipher.Init(encrypt, parameters);
        byte[] output = new byte[data.Length];
        for (int offset = 0; offset < data.Length; offset += cipher.GetBlockSize())
            cipher.ProcessBlock(data, offset, output, offset);
        return output;
    }

    private static byte[] PadRight(byte[] value, int blockSize)
    {
        int length = ((value.Length + blockSize - 1) / blockSize) * blockSize;
        var result = new byte[length];
        Array.Copy(value, result, value.Length);
        return result;
    }

    private static byte[] NormalizeDesEdeKey(byte[] key) =>
        key.Length == 16 ? key.Concat(key.Take(8)).ToArray() : (byte[])key.Clone();
}
