using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Domain;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Services;

namespace Gp4Net.CardEmulator.Services;

/// <summary>
/// Adapter for CAP file processing operations specific to VirtualCard needs.
/// Wraps the core CapFileOperations to provide CardEmulator-specific functionality
/// including ExecutableModule creation and LoadFileDataBlockHash handling.
/// </summary>
public sealed class EmulatorCapFiles
{
    private readonly CapFileOperations _coreService;

    public EmulatorCapFiles()
    {
        _coreService = new CapFileOperations();
    }

    /// <summary>
    /// Parses and validates a complete CAP file for virtual card loading.
    /// Combines parsing, validation, and DAP verification into a single operation.
    /// </summary>
    /// <param name="capFileData">The complete CAP file data bytes.</param>
    /// <param name="expectedHash">Optional expected LFDBH for integrity verification.</param>
    /// <returns>
    /// Result containing ExecutableModule ready for load file creation,
    /// or SmartCardError if processing fails.
    /// </returns>
    public Result<ExecutableModule, SmartCardError> ProcessCapFileForLoading(
        byte[] capFileData,
        Maybe<LoadFileDataBlockHash> expectedHash = default
    )
    {
        return _coreService
            .ParseCapFile(capFileData)
            .Bind(capStructure =>
                _coreService.ValidateCapStructure(capStructure).Map(_ => capStructure)
            )
            .Bind(capStructure => VerifyLfdbhIfProvided(capFileData, expectedHash, capStructure))
            .Bind(capStructure => ExtractExecutableModuleFromStructure(capStructure));
    }

    /// <summary>
    /// Verifies DAP signature using the core service.
    /// </summary>
    /// <param name="capFileData">The complete CAP file data.</param>
    /// <param name="dapSignature">The DAP signature to verify.</param>
    /// <returns>Result indicating verification success or failure.</returns>
    public Result<bool, SmartCardError> VerifyDapSignature(byte[] capFileData, byte[] dapSignature)
    {
        return _coreService.VerifyDapSignature(capFileData, dapSignature);
    }

    /// <summary>
    /// Verifies LFDBH hash if provided, otherwise returns the structure unchanged.
    /// </summary>
    private Result<CapFileStructure, SmartCardError> VerifyLfdbhIfProvided(
        byte[] capFileData,
        Maybe<LoadFileDataBlockHash> expectedHash,
        CapFileStructure capStructure
    )
    {
        return expectedHash.Match(
            hash =>
                _coreService
                    .VerifyLoadFileDataBlockHash(capFileData, hash.Value)
                    .Map(_ => capStructure),
            () => Result.Success<CapFileStructure, SmartCardError>(capStructure)
        );
    }

    /// <summary>
    /// Extracts ExecutableModule from CAP file structure.
    /// Creates module from first applet or uses package AID if no applets.
    /// </summary>
    private static Result<ExecutableModule, SmartCardError> ExtractExecutableModuleFromStructure(
        CapFileStructure capStructure
    )
    {
        var loadFileAid = capStructure.PackageAid;
        var appletModules = capStructure
            .Applets.Select(applet => new ExecutableModule(applet.Aid, 0x03)) // SELECTABLE state
            .ToList();

        return appletModules.Any()
            ? Result.Success<ExecutableModule, SmartCardError>(appletModules.First())
            : Result.Success<ExecutableModule, SmartCardError>(
                new ExecutableModule(loadFileAid, 0x01) // LOADED state if no applets
            );
    }
}
