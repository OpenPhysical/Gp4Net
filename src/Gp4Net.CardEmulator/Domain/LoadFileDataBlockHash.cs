using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;

namespace Gp4Net.CardEmulator.Domain;

/// <summary>
/// Represents a Load File Data Block Hash (LFDBH) as defined in GlobalPlatform Card Specification v2.3.1.
/// LFDBH is computed as SHA-256 hash of the complete CAP file data for integrity verification.
/// </summary>
public sealed record LoadFileDataBlockHash
{
    /// <summary>
    /// The SHA-256 hash value.
    /// </summary>
    public byte[] Value { get; }

    private LoadFileDataBlockHash(byte[] value) => Value = value;

    /// <summary>
    /// Creates a LoadFileDataBlockHash from raw hash bytes.
    /// Validates that the hash is exactly 32 bytes (SHA-256).
    /// </summary>
    /// <param name="hashBytes">The hash bytes (must be 32 bytes).</param>
    /// <returns>LoadFileDataBlockHash or error.</returns>
    public static Result<LoadFileDataBlockHash, SmartCardError> Create(byte[] hashBytes)
    {
        return hashBytes.Length == 32
            ? Result.Success<LoadFileDataBlockHash, SmartCardError>(
                new LoadFileDataBlockHash(hashBytes)
            )
            : Result.Failure<LoadFileDataBlockHash, SmartCardError>(
                SmartCardError.InvalidData("LFDBH must be exactly 32 bytes (SHA-256)")
            );
    }

    /// <summary>
    /// Computes LFDBH from complete CAP file data using SHA-256.
    /// Per GP Card Specification v2.3.1 Section 11.5.2.1.
    /// </summary>
    /// <param name="capFileData">Complete CAP file data.</param>
    /// <returns>LoadFileDataBlockHash or error.</returns>
    public static Result<LoadFileDataBlockHash, SmartCardError> ComputeFromCapFile(
        byte[] capFileData
    )
    {
        return capFileData.Length > 0
            ? CryptoService.Hash.Sha256(capFileData).Bind(Create)
            : Result.Failure<LoadFileDataBlockHash, SmartCardError>(
                SmartCardError.InvalidData("CAP file data cannot be empty")
            );
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
