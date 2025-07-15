using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.CapFile
{
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
            public string? ErrorMessage { get; }

            /// <summary>
            /// Gets the list of executed commands.
            /// </summary>
            public IReadOnlyList<object> ExecutedCommands { get; }

            /// <summary>
            /// Gets the loaded package AID.
            /// </summary>
            public byte[]? LoadedPackageAid { get; }

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
                string? errorMessage = null,
                IList<object>? executedCommands = null,
                byte[]? loadedPackageAid = null,
                IList<byte[]>? installedAppletAids = null
            )
            {
                IsSuccessful = isSuccessful;
                ErrorMessage = errorMessage;
                ExecutedCommands =
                    executedCommands != null
                        ? new List<object>(executedCommands)
                        : Array.Empty<object>();
                LoadedPackageAid = loadedPackageAid?.Clone() as byte[];
                InstalledAppletAids =
                    installedAppletAids != null
                        ? new List<byte[]>(installedAppletAids.Select(aid => (byte[])aid.Clone()))
                        : Array.Empty<byte[]>();
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
        public static Result<IList<IApduCommand>, SmartCardError> CreateLoadingCommands(
            byte[] capFileData,
            byte[]? securityDomainAid = null,
            bool installApplets = true,
            bool makeSelectableAfterInstall = true,
            int maxLoadBlockSize = 245
        )
        {
            ArgumentNullException.ThrowIfNull(capFileData);

            // Parse the CAP file to extract package and applet information
            var capFile = CapFileStructure.Parse(capFileData);
            var commands = new List<IApduCommand>();

            try
            {
                // Step 1: INSTALL [for load]
                // Per GP specification, Load File Data Block Hash is optional unless:
                // - A Token is present
                // - A DAP Block is present in the Load File
                // - The Load File Data Block is encrypted
                // Since we don't use tokens or DAP blocks, we'll omit the hash to avoid verification errors
                
                var installForLoadResult = InstallCommandBuilder.CreateForLoad(
                    capFile.PackageAid,
                    securityDomainAid,
                    hash: null,  // Omit hash as it's optional and may cause verification issues
                    maxDataBlockSize: (ushort)maxLoadBlockSize  // Pass max block size for load parameters
                );
                
                if (installForLoadResult.IsFailure)
                {
                    return Result<IList<IApduCommand>, SmartCardError>.Fail(installForLoadResult.Error);
                }
                commands.Add(installForLoadResult.Value);

                // Step 2: LOAD commands (split CAP file into blocks)
                // Use the CAP file structure directly to avoid double conversion
                var loadCommandsResult = LoadCommand.CreateFromCapFile(capFile, maxLoadBlockSize);
                if (loadCommandsResult.IsFailure)
                {
                    return Result<IList<IApduCommand>, SmartCardError>.Fail(loadCommandsResult.Error);
                }
                commands.AddRange(loadCommandsResult.Value);

                // Step 3: INSTALL [for install] commands for each applet (if requested)
                if (installApplets && capFile.Applets.Count > 0)
                {
                    foreach (var applet in capFile.Applets)
                    {
                        var installForInstallResult = makeSelectableAfterInstall
                            ? InstallCommandBuilder.CreateForInstallAndMakeSelectable(
                                capFile.PackageAid,
                                applet.Aid)
                            : InstallCommandBuilder.CreateForInstall(
                                capFile.PackageAid,
                                applet.Aid);
                        
                        if (installForInstallResult.IsFailure)
                        {
                            return Result<IList<IApduCommand>, SmartCardError>.Fail(installForInstallResult.Error);
                        }
                        commands.Add(installForInstallResult.Value);
                    }
                }

                return Result<IList<IApduCommand>, SmartCardError>.Ok(commands);
            }
            catch (Exception ex)
            {
                return Result<IList<IApduCommand>, SmartCardError>.Fail(
                    SmartCardError.InvalidData($"Failed to create loading commands: {ex.Message}"));
            }
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

            try
            {
                var capFile = CapFileStructure.Parse(capFileData);

                var validationErrors = new List<string>();

                // Validate package AID
                if (capFile.PackageAid.Length < 5 || capFile.PackageAid.Length > 16)
                {
                    validationErrors.Add("Package AID must be between 5 and 16 bytes");
                }

                // Validate components
                if (capFile.Components.Count == 0)
                {
                    validationErrors.Add("CAP file contains no components");
                }

                // Check for required components
                var requiredComponents = new[]
                {
                    CapFileStructure.ComponentTags.Header,
                    CapFileStructure.ComponentTags.Directory,
                };

                var presentTags = capFile.Components.Select(c => c.Tag).ToHashSet();
                foreach (var requiredTag in requiredComponents)
                {
                    if (!presentTags.Contains(requiredTag))
                    {
                        validationErrors.Add($"Missing required component: {requiredTag:X2}");
                    }
                }

                // Validate applets
                foreach (var applet in capFile.Applets)
                {
                    if (applet.Aid.Length < 5 || applet.Aid.Length > 16)
                    {
                        validationErrors.Add(
                            $"Applet AID must be between 5 and 16 bytes: {Convert.ToHexString(applet.Aid)}"
                        );
                    }
                }

                var isValid = validationErrors.Count == 0;
                var errorMessage = isValid ? null : string.Join("; ", validationErrors);

                return new CapFileValidationResult(isValid, errorMessage, capFile);
            }
            catch (Exception ex)
            {
                return new CapFileValidationResult(
                    false,
                    $"Failed to parse CAP file: {ex.Message}"
                );
            }
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
            IList<byte[]>? appletAids = null,
            bool deleteRelated = true
        )
        {
            if (packageAid == null)
                return SmartCardError.InvalidArgument("Package AID cannot be null.");

            if (packageAid.Length == 0)
                return SmartCardError.InvalidArgument("Package AID cannot be empty.");

            var aidsToDelete = new List<byte[]> { packageAid };

            if (appletAids != null)
            {
                aidsToDelete.AddRange(appletAids);
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
            ArgumentNullException.ThrowIfNull(capFileData);

            var capFile = CapFileStructure.Parse(capFileData);

            // Basic estimation - in practice this would be more sophisticated
            var codeSize = capFile
                .Components.Where(c =>
                    c.Tag == CapFileStructure.ComponentTags.Method
                    || c.Tag == CapFileStructure.ComponentTags.Class
                )
                .Sum(c => c.Size);

            var dataSize = capFile
                .Components.Where(c =>
                    c.Tag == CapFileStructure.ComponentTags.StaticField
                    || c.Tag == CapFileStructure.ComponentTags.ConstantPool
                )
                .Sum(c => c.Size);

            var totalSize = capFile.TotalSize;

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
        public string? ErrorMessage { get; }

        /// <summary>
        /// Gets the parsed CAP file structure (if valid).
        /// </summary>
        public CapFileStructure? CapFile { get; }

        /// <summary>
        /// Initializes a new instance of the CapFileValidationResult class.
        /// </summary>
        /// <param name="isValid">Whether the CAP file is valid.</param>
        /// <param name="errorMessage">The error message (if invalid).</param>
        /// <param name="capFile">The parsed CAP file (if valid).</param>
        public CapFileValidationResult(
            bool isValid,
            string? errorMessage = null,
            CapFileStructure? capFile = null
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
}
