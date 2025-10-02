using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Domain.CapFile;

/// <summary>
/// Provides a complete workflow for loading CAP files onto Java Card 3.0.4 compliant cards.
/// Follows the GlobalPlatform Card Specification v2.3.1 for CAP file loading procedures.
/// </summary>
[PublicAPI]
public class CapFileLoadingWorkflow
{
    /// <summary>
    /// Represents the result of a CAP file loading operation.
    /// </summary>
    public class LoadingResult
    {
        /// <summary>
        /// Gets a value indicating whether the operation was successful.
        /// </summary>
        public bool IsSuccessful { get; }

        /// <summary>
        /// Gets the error message if the operation failed.
        /// </summary>
        public Maybe<string> ErrorMessage { get; }

        /// <summary>
        /// Gets the list of executed commands.
        /// </summary>
        public IReadOnlyList<object> ExecutedCommands { get; }

        /// <summary>
        /// Gets the loaded package AID.
        /// </summary>
        public Maybe<byte[]> LoadedPackageAid { get; }

        /// <summary>
        /// Gets the list of installed applet AIDs.
        /// </summary>
        public IReadOnlyList<byte[]> InstalledAppletAids { get; }

        /// <summary>
        /// Initializes a new instance of the LoadingResult class.
        /// </summary>
        /// <param name="isSuccessful">Whether the operation was successful.</param>
        /// <param name="errorMessage">The error message if failed.</param>
        /// <param name="executedCommands">The list of executed commands.</param>
        /// <param name="loadedPackageAid">The loaded package AID.</param>
        /// <param name="installedAppletAids">The installed applet AIDs.</param>
        public LoadingResult(
            bool isSuccessful,
            Maybe<string> errorMessage = default,
            Maybe<IList<object>> executedCommands = default,
            Maybe<byte[]> loadedPackageAid = default,
            Maybe<IList<byte[]>> installedAppletAids = default
        )
        {
            IsSuccessful = isSuccessful;
            ErrorMessage = errorMessage;
            ExecutedCommands = executedCommands
                .Map(commands => (IReadOnlyList<object>)new List<object>(commands))
                .GetValueOrDefault([]);
            LoadedPackageAid = loadedPackageAid.Map(aid => (byte[])aid.Clone());
            InstalledAppletAids = installedAppletAids
                .Map(aids =>
                    (IReadOnlyList<byte[]>)new List<byte[]>(aids.Select(aid => (byte[])aid.Clone()))
                )
                .Match(value => value, () => new List<byte[]>());
        }
    }

    /// <summary>
    /// Creates the complete sequence of commands to load a CAP file.
    /// </summary>
    /// <param name="capFileData">The CAP file data.</param>
    /// <param name="securityDomainAid">The security domain AID (optional).</param>
    /// <param name="installApplets">Whether to install applets after loading.</param>
    /// <param name="makeSelectableAfterInstall">Whether to make applets selectable after installation.</param>
    /// <param name="maxLoadBlockSize">Maximum size for LOAD command blocks.</param>
    /// <returns>The sequence of commands to execute.</returns>
    public static Result<IList<CommandAPDU>, SmartCardError> CreateLoadingCommands(
        byte[] capFileData,
        Maybe<byte[]> securityDomainAid = default,
        bool installApplets = true,
        bool makeSelectableAfterInstall = true,
        int maxLoadBlockSize = Constants.Constants.GlobalPlatform.ApduLimits.DEFAULT_LOAD_BLOCK_SIZE
    )
    {
        return Result.Failure<IList<CommandAPDU>, SmartCardError>(
            SmartCardError.NotImplemented("This method requires refactoring after WSCT migration")
        );
    }

    /// <summary>
    /// Validates a CAP file and returns detailed information about it.
    /// </summary>
    /// <param name="capFileData">The CAP file data to validate.</param>
    /// <returns>The validation result with CAP file information.</returns>
    public static CapFileValidationResult ValidateCapFile(byte[] capFileData)
    {
        if (capFileData == null)
        {
            return new CapFileValidationResult(false, "CAP file data is null");
        }

        if (capFileData.Length == 0)
        {
            return new CapFileValidationResult(false, "CAP file data is empty");
        }

        var capFileResult = CapFileStructure.Parse(capFileData);

        if (capFileResult.IsFailure)
        {
            return new CapFileValidationResult(
                false,
                Maybe<string>.From($"Failed to parse CAP file: {capFileResult.Error.Message}")
            );
        }

        if (capFileResult.IsSuccess)
        {
            var capFile = capFileResult.Value;

            List<string> validationErrors = [];

            // Validate package AID
            if (
                capFile.PackageAid.Length
                is < Constants.Constants.JavaCard.AidConstraints.MIN_LENGTH
                    or > Constants.Constants.JavaCard.AidConstraints.MAX_LENGTH
            )
            {
                validationErrors.Add("Package AID must be between 5 and 16 bytes");
            }

            // Validate components
            if (capFile.Components.Count == 0)
            {
                validationErrors.Add("CAP file contains no components");
            }

            // Check for required components
            byte[] requiredComponents =
            [
                Constants.Constants.JavaCard.ComponentTags.HEADER,
                Constants.Constants.JavaCard.ComponentTags.DIRECTORY,
            ];

            HashSet<byte> presentTags = [.. capFile.Components.Select(c => c.Tag)];
            foreach (byte requiredTag in requiredComponents)
            {
                if (!presentTags.Contains(requiredTag))
                {
                    validationErrors.Add($"Missing required component: {requiredTag:X2}");
                }
            }

            // Validate applets
            foreach (var applet in capFile.Applets)
            {
                if (
                    applet.Aid.Length
                    is < Constants.Constants.JavaCard.AidConstraints.MIN_LENGTH
                        or > Constants.Constants.JavaCard.AidConstraints.MAX_LENGTH
                )
                {
                    validationErrors.Add(
                        $"Applet AID must be between 5 and 16 bytes: {Convert.ToHexString(applet.Aid)}"
                    );
                }
            }

            bool isValid = validationErrors.Count == 0;
            var errorMessage = isValid
                ? Maybe<string>.None
                : Maybe<string>.From(string.Join("; ", validationErrors));

            return new CapFileValidationResult(
                isValid,
                errorMessage,
                Maybe<CapFileStructure>.From(capFile)
            );
        }

        // If we get here without success, return failure
        return new CapFileValidationResult(
            false,
            Maybe<string>.From("Failed to parse CAP file: unexpected state")
        );
    }

    /// <summary>
    /// Creates a DELETE command to remove a loaded package and its applets.
    /// </summary>
    /// <param name="packageAid">The package AID to delete.</param>
    /// <param name="appletAids">The applet AIDs to delete (optional).</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    /// <returns>A Result containing either the DELETE command or an error.</returns>
    public static Result<DeleteCommand, SmartCardError> CreateDeleteCommand(
        byte[] packageAid,
        Maybe<IList<byte[]>> appletAids = default,
        bool deleteRelated = true
    )
    {
        if (packageAid == null)
        {
            return SmartCardError.InvalidArgument("Package AID cannot be null.");
        }

        if (packageAid.Length == 0)
        {
            return SmartCardError.InvalidArgument("Package AID cannot be empty.");
        }

        List<byte[]> aidsToDelete = [packageAid];

        if (appletAids.HasValue)
        {
            aidsToDelete.AddRange(appletAids.Value);
        }

        return DeleteCommand.CreateForApplications(aidsToDelete, deleteRelated);
    }

    /// <summary>
    /// Estimates the memory requirements for loading a CAP file.
    /// </summary>
    /// <param name="capFileData">The CAP file data.</param>
    /// <returns>The estimated memory requirements in bytes.</returns>
    public static MemoryRequirements EstimateMemoryRequirements(byte[] capFileData)
    {
        var capFileResult = CapFileStructure.Parse(capFileData);
        if (capFileResult.IsFailure)
        {
            // Return default requirements on parse failure
            return new MemoryRequirements(0, 0, capFileData.Length);
        }

        var capFile = capFileResult.Value;

        // Basic estimation - in practice this would be more sophisticated
        int codeSize = capFile
            .Components.Where(c =>
                c.Tag
                    is Constants.Constants.JavaCard.ComponentTags.METHOD
                        or Constants.Constants.JavaCard.ComponentTags.CLASS
            )
            .Sum(c => c.Size);

        int dataSize = capFile
            .Components.Where(c =>
                c.Tag
                    is Constants.Constants.JavaCard.ComponentTags.STATIC_FIELD
                        or Constants.Constants.JavaCard.ComponentTags.CONSTANT_POOL
            )
            .Sum(c => c.Size);

        int totalSize = capFile.TotalSize;

        return new MemoryRequirements(codeSize, dataSize, totalSize);
    }
}

/// <summary>
/// Represents the result of CAP file validation.
/// </summary>
[PublicAPI]
public class CapFileValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the CAP file is valid.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the validation error message (if any).
    /// </summary>
    public Maybe<string> ErrorMessage { get; }

    /// <summary>
    /// Gets the parsed CAP file structure (if valid).
    /// </summary>
    public Maybe<CapFileStructure> CapFile { get; }

    /// <summary>
    /// Initializes a new instance of the CapFileValidationResult class.
    /// </summary>
    /// <param name="isValid">Whether the CAP file is valid.</param>
    /// <param name="errorMessage">The error message (if invalid).</param>
    /// <param name="capFile">The parsed CAP file (if valid).</param>
    public CapFileValidationResult(
        bool isValid,
        Maybe<string> errorMessage = default,
        Maybe<CapFileStructure> capFile = default
    )
    {
        IsValid = isValid;
        ErrorMessage = errorMessage;
        CapFile = capFile;
    }
}

/// <summary>
/// Represents estimated memory requirements for a CAP file.
/// </summary>
[PublicAPI]
public class MemoryRequirements
{
    /// <summary>
    /// Gets the estimated code memory requirement in bytes.
    /// </summary>
    public int CodeMemory { get; }

    /// <summary>
    /// Gets the estimated data memory requirement in bytes.
    /// </summary>
    public int DataMemory { get; }

    /// <summary>
    /// Gets the total CAP file size in bytes.
    /// </summary>
    public int TotalSize { get; }

    /// <summary>
    /// Initializes a new instance of the MemoryRequirements class.
    /// </summary>
    /// <param name="codeMemory">The code memory requirement.</param>
    /// <param name="dataMemory">The data memory requirement.</param>
    /// <param name="totalSize">The total CAP file size.</param>
    public MemoryRequirements(int codeMemory, int dataMemory, int totalSize)
    {
        CodeMemory = codeMemory;
        DataMemory = dataMemory;
        TotalSize = totalSize;
    }
}
