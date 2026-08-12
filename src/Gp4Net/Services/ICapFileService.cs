using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;

namespace Gp4Net.Services;

/// <summary>
/// Interface for CAP file processing operations.
/// Provides functional methods for parsing, validating, and extracting data from Java Card CAP files.
/// All operations follow functional programming principles using Result&lt;T, TError&gt; for error handling.
/// </summary>
public interface ICapFileService
{
    /// <summary>
    /// Parses a CAP file from byte data and returns the structured representation.
    /// Validates the CAP file format and extracts all components per Java Card specification.
    /// </summary>
    /// <param name="capFileData">The raw CAP file data bytes.</param>
    /// <returns>
    /// Result containing CapFileStructure if parsing succeeds,
    /// or SmartCardError if the data is invalid or parsing fails.
    /// </returns>
    Result<CapFileStructure, SmartCardError> ParseCapFile(byte[] capFileData);

    /// <summary>
    /// Validates the structure and integrity of a parsed CAP file.
    /// Performs comprehensive validation including component completeness,
    /// AID format validation, and GlobalPlatform compliance checks.
    /// </summary>
    /// <param name="capFileStructure">The parsed CAP file structure to validate.</param>
    /// <returns>
    /// Result containing true if validation passes,
    /// or SmartCardError describing the validation failure.
    /// </returns>
    Result<bool, SmartCardError> ValidateCapStructure(CapFileStructure capFileStructure);

    /// <summary>
    /// Extracts package AID from a validated CAP file structure.
    /// Returns the primary package AID for load file creation.
    /// </summary>
    /// <param name="capFileStructure">The validated CAP file structure.</param>
    /// <returns>
    /// Result containing package AID if extraction succeeds,
    /// or SmartCardError if extraction fails.
    /// </returns>
    Result<byte[], SmartCardError> ExtractPackageAid(CapFileStructure capFileStructure);

    /// <summary>
    /// Verifies the Data Authentication Pattern (DAP) signature for a CAP file.
    /// Requires the verifying Security Domain's DAP key and algorithm per Appendix C.3.
    /// </summary>
    /// <param name="capFileData">The complete CAP file data bytes.</param>
    /// <param name="dapSignature">The DAP signature bytes to verify.</param>
    /// <returns>
    /// Result containing true if signature verification succeeds,
    /// or SmartCardError if verification fails or signature is invalid.
    /// </returns>
    Result<bool, SmartCardError> VerifyDapSignature(byte[] capFileData, byte[] dapSignature);

    /// <summary>
    /// Verifies the Load File Data Block Hash (LFDBH) for integrity checking.
    /// Selects SHA-1, SHA-256, SHA-384, or SHA-512 from the expected hash length.
    /// </summary>
    /// <param name="capFileData">The complete CAP file data bytes.</param>
    /// <param name="expectedHash">The expected LFDBH bytes from INSTALL [for load] command.</param>
    /// <returns>
    /// Result containing true if hash verification succeeds,
    /// or SmartCardError if hash mismatch or computation fails.
    /// </returns>
    Result<bool, SmartCardError> VerifyLoadFileDataBlockHash(
        byte[] capFileData,
        byte[] expectedHash
    );
}
