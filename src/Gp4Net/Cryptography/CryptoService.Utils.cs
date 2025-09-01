using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Security;
using Org.BouncyCastle.Crypto.Paddings;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    /// <summary>
    /// Utility operations: padding, comparison, array operations.
    /// Consolidates all utility crypto methods from multiple classes.
    /// Uses the unified RNG abstraction for all random generation.
    /// </summary>
    public static class Utils
    {
        /// <summary>
        /// Expands a 16-byte (2-key) 3DES key to 24 bytes (3-key) by setting K3 = K1.
        /// </summary>
        /// <param name="key">The key to expand (16 or 24 bytes).</param>
        /// <returns>The expanded 24-byte key or error.</returns>
        public static Result<byte[], SmartCardError> ExpandTripleDesKey(byte[] key)
        {
            return key.Length switch
            {
                16 => Result.Success<byte[], SmartCardError>(
                    ConcatenateArrays(key, key[..8])
                ),
                24 => Result.Success<byte[], SmartCardError>(key),
                _ => Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"3DES key must be 16 or 24 bytes, got {key.Length}")
                )
            };
        }

        /// <summary>
        /// Applies ISO 7816-4 padding to data.
        /// Uses BouncyCastle's ISO7816d4Padding class.
        /// </summary>
        /// <param name="data">The data to pad.</param>
        /// <param name="blockSize">The block size (8 for 3DES, 16 for AES).</param>
        /// <returns>The padded data.</returns>
        public static Result<byte[], SmartCardError> ApplyIso7816Padding(byte[] data, int blockSize)
        {
            UnitResult<SmartCardError> validation = ValidateBlockSize(blockSize);
            return validation.IsSuccess
                ? ApplyPadding(data, blockSize)
                : Result.Failure<byte[], SmartCardError>(validation.Error);
        }

        /// <summary>
        /// Internal padding implementation.
        /// </summary>
        private static Result<byte[], SmartCardError> ApplyPadding(byte[] data, int blockSize)
        {
            ISO7816d4Padding padding = new ISO7816d4Padding();
            int paddingLength = blockSize - data.Length % blockSize;
            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);

            padding.AddPadding(paddedData, data.Length);

            return Result.Success<byte[], SmartCardError>(paddedData);
        }

        /// <summary>
        /// Removes ISO 7816-4 padding from data.
        /// Uses BouncyCastle's ISO7816d4Padding class.
        /// </summary>
        /// <param name="paddedData">The padded data.</param>
        /// <returns>The unpadded data.</returns>
        public static Result<byte[], SmartCardError> RemoveIso7816Padding(byte[] paddedData)
        {
            if (paddedData.Length == 0)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Padded data cannot be empty")
                );
            }

            return RemovePadding(paddedData);
        }

        /// <summary>
        /// Internal padding removal implementation.
        /// </summary>
        private static Result<byte[], SmartCardError> RemovePadding(byte[] paddedData)
        {
            ISO7816d4Padding padding = new ISO7816d4Padding();
            int padCount = padding.PadCount(paddedData);

            if (padCount < 0 || padCount >= paddedData.Length)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Invalid padding in response data")
                );
            }

            byte[] unpaddedData = new byte[paddedData.Length - padCount];
            Array.Copy(paddedData, 0, unpaddedData, 0, unpaddedData.Length);

            return Result.Success<byte[], SmartCardError>(unpaddedData);
        }

        /// <summary>
        /// Applies PKCS#7 padding to data.
        /// Uses BouncyCastle's Pkcs7Padding class.
        /// </summary>
        /// <param name="data">The data to pad.</param>
        /// <param name="blockSize">The block size (8 for 3DES, 16 for AES).</param>
        /// <returns>The padded data.</returns>
        public static Result<byte[], SmartCardError> ApplyPkcs7Padding(byte[] data, int blockSize)
        {
            return ValidateBlockSize(blockSize)
                .Match(
                    () =>
                    {
                        Pkcs7Padding padding = new Pkcs7Padding();
                        int paddingLength = blockSize - data.Length % blockSize;
                        byte[] paddedData = new byte[data.Length + paddingLength];
                        Array.Copy(data, 0, paddedData, 0, data.Length);

                        padding.AddPadding(paddedData, data.Length);

                        return Result.Success<byte[], SmartCardError>(paddedData);
                    },
                    error => Result.Failure<byte[], SmartCardError>(error));
        }

        /// <summary>
        /// Removes PKCS#7 padding from data.
        /// Uses BouncyCastle's Pkcs7Padding class.
        /// </summary>
        /// <param name="paddedData">The padded data.</param>
        /// <returns>The unpadded data.</returns>
        public static Result<byte[], SmartCardError> RemovePkcs7Padding(byte[] paddedData)
        {
            if (paddedData.Length == 0)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Padded data cannot be empty")
                );
            }

            Pkcs7Padding padding = new Pkcs7Padding();
            int padCount = padding.PadCount(paddedData);

            if (padCount < 0 || padCount >= paddedData.Length)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Invalid PKCS#7 padding in response data")
                );
            }

            byte[] unpaddedData = new byte[paddedData.Length - padCount];
            Array.Copy(paddedData, 0, unpaddedData, 0, unpaddedData.Length);

            return Result.Success<byte[], SmartCardError>(unpaddedData);
        }

        /// <summary>
        /// Pads data to a specific length using ISO 7816-4 padding.
        /// Per GP Card Specification v2.3.1 Section E.4.2.1: data shall be padded with '80 00 00 00 00 00 00 00'.
        /// </summary>
        /// <param name="data">The data to pad.</param>
        /// <param name="targetLength">The target length.</param>
        /// <returns>The padded data with proper ISO 7816-4 padding.</returns>
        public static Result<byte[], SmartCardError> PadToLength(byte[] data, int targetLength)
        {
            if (targetLength < 0)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("Target length cannot be negative")
                );
            }

            if (data.Length >= targetLength)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"Data length {data.Length} must be less than target length {targetLength} to allow for padding"
                    )
                );
            }

            byte[] paddedData = new byte[targetLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);

            ISO7816d4Padding padding = new ISO7816d4Padding();
            padding.AddPadding(paddedData, data.Length);

            return Result.Success<byte[], SmartCardError>(paddedData);
        }

        /// <summary>
        /// Compares two byte arrays for equality.
        /// Uses constant-time comparison to prevent timing attacks.
        /// </summary>
        /// <param name="a">First array.</param>
        /// <param name="b">Second array.</param>
        /// <returns>True if arrays are equal, false otherwise.</returns>
        public static bool CompareBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            int result = a
                .Zip(b, (x, y) => x ^ y)
                .Aggregate(0, (acc, xor) => acc | xor);

            return result == 0;
        }

        /// <summary>
        /// Concatenates multiple byte arrays.
        /// </summary>
        /// <param name="arrays">Arrays to concatenate.</param>
        /// <returns>The concatenated array.</returns>
        public static byte[] ConcatenateArrays(params byte[][] arrays)
        {
            return [.. arrays.SelectMany(array => array)];
        }

        /// <summary>
        /// Generates random bytes using the configured RNG mode.
        /// Delegates to UnifiedCryptoService.Rng for consistent random generation.
        /// Supports both secure (production) and deterministic (testing) modes.
        /// </summary>
        /// <param name="length">Number of bytes to generate.</param>
        /// <returns>Array of random bytes or error.</returns>
        public static Result<byte[], SmartCardError> GenerateRandomBytes(int length) =>
            Rng.GenerateBytes(length);

        /// <summary>
        /// Generates an 8-byte host challenge for secure channel establishment.
        /// Per GP Card Specification, host challenge is always 8 bytes.
        /// </summary>
        /// <returns>8-byte host challenge or error.</returns>
        public static Result<byte[], SmartCardError> GenerateHostChallenge()
        {
            return GenerateRandomBytes(8);
        }

        /// <summary>
        /// Generates a 16-byte sequence counter for SCP03.
        /// Per GP SCP03 Specification, sequence counter is 16 bytes.
        /// </summary>
        /// <returns>16-byte sequence counter or error.</returns>
        public static Result<byte[], SmartCardError> GenerateSequenceCounter()
        {
            return GenerateRandomBytes(16);
        }

        /// <summary>
        /// Applies GP padding to the AID per Section E.3.3.
        /// Pads with 0x80 followed by zeros to reach a multiple of 8 bytes.
        /// </summary>
        public static Result<byte[], SmartCardError> ApplyGpPadding(byte[] data)
        {
            if (data.Length == 0)
            {
                return SmartCardError.InvalidArgument("Data cannot be empty for GP padding");
            }

            return Result.Try(
                () =>
                {
                    int paddingNeeded = data.Length % 8 == 0 ? 0 : 8 - data.Length % 8;

                    if (paddingNeeded == 0)
                    {
                        return data;
                    }

                    byte[] paddedData = [.. data, (byte)0x80, .. Enumerable.Repeat((byte)0x00, paddingNeeded - 1)];

                    return paddedData;
                },
                ex => SmartCardError.CryptographicError($"GP padding failed: {ex.Message}")
            );
        }

        /// <summary>
        /// Builds MAC input data for command MAC calculation.
        /// Formats input according to protocol-specific requirements per GP specification.
        /// </summary>
        /// <param name="cla">The class byte</param>
        /// <param name="ins">The instruction byte</param>
        /// <param name="p1">The P1 parameter byte</param>
        /// <param name="p2">The P2 parameter byte</param>
        /// <param name="data">The command data</param>
        /// <param name="protocolVersion">The SCP protocol version</param>
        /// <returns>The formatted MAC input data</returns>
        public static byte[] BuildMacInput(
            byte cla,
            byte ins,
            byte p1,
            byte p2,
            byte[] data,
            ScpVersion protocolVersion
        )
        {
            if (protocolVersion == ScpVersion.Scp03)
            {
                List<byte> macInput =
                [
                    0x84,
                    ins,
                    p1,
                    p2,
                    (byte)(data.Length + 8),
                ];
                macInput.AddRange(data);
                return [.. macInput];
            }
            else
            {
                List<byte> macInput = [cla, ins, p1, p2, (byte)(data.Length + 8)];
                macInput.AddRange(data);
                return [.. macInput];
            }
        }

        /// <summary>
        /// Builds MAC input data from a parsed secured command.
        /// Convenience overload for parsed commands.
        /// </summary>
        /// <param name="parsedCommand">The parsed secured command</param>
        /// <param name="protocolVersion">The SCP protocol version</param>
        /// <returns>The formatted MAC input data</returns>
        public static byte[] BuildMacInput(
            ParsedSecuredCommand parsedCommand,
            ScpVersion protocolVersion
        )
        {
            return BuildMacInput(
                parsedCommand.Cla,
                parsedCommand.Ins,
                parsedCommand.P1,
                parsedCommand.P2,
                parsedCommand.Data,
                protocolVersion
            );
        }

        private static UnitResult<SmartCardError> ValidateBlockSize(int blockSize)
        {
            return blockSize is <= 0 or > 255
                ? UnitResult.Failure(SmartCardError.InvalidArgument($"Invalid block size: {blockSize}"))
                : UnitResult.Success<SmartCardError>();
        }

    }
}
