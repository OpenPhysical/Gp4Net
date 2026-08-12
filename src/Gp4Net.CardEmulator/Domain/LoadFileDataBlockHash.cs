using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;

namespace Gp4Net.CardEmulator.Domain;

/// <summary>
/// Represents a Load File Data Block Hash (LFDBH) as defined in GlobalPlatform Card Specification v2.3.1.
/// GP Card Specification v2.3.1, Appendix C.2.
/// </summary>
public sealed record LoadFileDataBlockHash
{
    /// <summary>
    /// The hash value.
    /// </summary>
    public byte[] Value { get; }

    private LoadFileDataBlockHash(byte[] value) => Value = value;

    /// <summary>
    /// Creates a LoadFileDataBlockHash from raw hash bytes.
    /// Accepts the LFDBH lengths defined by Appendix C.2.
    /// </summary>
    /// <param name="hashBytes">The hash bytes.</param>
    /// <returns>LoadFileDataBlockHash or error.</returns>
    public static Result<LoadFileDataBlockHash, SmartCardError> Create(byte[] hashBytes)
    {
        return hashBytes.Length is 20 or 32 or 48 or 64
            ? Result.Success<LoadFileDataBlockHash, SmartCardError>(
                new LoadFileDataBlockHash(hashBytes)
            )
            : Result.Failure<LoadFileDataBlockHash, SmartCardError>(
                SmartCardError.InvalidData("LFDBH must be 20, 32, 48, or 64 bytes")
            );
    }

    /// <summary>
    /// Computes LFDBH using the algorithm identified by the expected hash length.
    /// GP Card Specification v2.3.1, Appendix C.2.
    /// </summary>
    /// <param name="capFileData">Complete CAP file data.</param>
    /// <param name="hashLength">Expected LFDBH length.</param>
    /// <returns>LoadFileDataBlockHash or error.</returns>
    public static Result<LoadFileDataBlockHash, SmartCardError> ComputeFromCapFile(
        byte[] capFileData,
        int hashLength
    )
    {
        return capFileData.Length > 0
            ? ComputeHash(capFileData, hashLength).Bind(Create)
            : Result.Failure<LoadFileDataBlockHash, SmartCardError>(
                SmartCardError.InvalidData("CAP file data cannot be empty")
            );
    }

    private static Result<byte[], SmartCardError> ComputeHash(byte[] data, int hashLength)
    {
        return hashLength switch
        {
            20 => CryptoOperations.Hash.Sha1(data),
            32 => CryptoOperations.Hash.Sha256(data),
            48 => CryptoOperations.Hash.Sha384(data),
            64 => CryptoOperations.Hash.Sha512(data),
            _
                => Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData($"Unsupported LFDBH length: {hashLength}")
                ),
        };
    }

    /// <summary>
    /// Verifies this LFDBH matches the expected hash.
    /// </summary>
    /// <param name="expected">Expected LFDBH.</param>
    /// <returns>True if match, false if mismatch, or error.</returns>
    public Result<bool, SmartCardError> VerifyMatch(LoadFileDataBlockHash expected)
    {
        return Maybe<LoadFileDataBlockHash>
            .From(expected)
            .ToResult(SmartCardError.InvalidArgument("Expected hash cannot be null"))
            .Map(exp => Value.SequenceEqual(exp.Value));
    }

    /// <summary>
    /// Returns hex representation of the hash for logging/debugging.
    /// </summary>
    public override string ToString() => Convert.ToHexString(Value).ToLowerInvariant();
}
