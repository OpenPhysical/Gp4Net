using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;

namespace Gp4Net.Domain.Modules;

/// <summary>
/// Pure functional module for creating GlobalPlatform commands.
/// All functions are static and side-effect free.
/// </summary>
public static class CommandFactory
{
    /// <summary>
    /// Creates a SELECT command for the Issuer Security Domain (empty AID).
    /// Per GlobalPlatform specification, SELECT with empty AID selects the ISD.
    /// </summary>
    public static Result<SelectCommand, SmartCardError> CreateSelectIsdCommand()
    {
        return SelectCommand.CreateForIssuerSecurityDomain();
    }

    /// <summary>
    /// Creates a SELECT command for the Issuer Security Domain with a specific response control.
    /// </summary>
    public static Result<SelectCommand, SmartCardError> CreateSelectIsdCommand(
        SelectCommand.FileControlInfo controlInfo)
    {
        return SelectCommand.CreateWith([], SelectCommand.SelectMode.First, controlInfo);
    }

    /// <summary>
    /// Creates a SELECT command for a specific AID.
    /// </summary>
    /// <param name="aid">The application identifier to select.</param>
    public static Result<SelectCommand, SmartCardError> CreateSelectCommand(byte[] aid)
    {
        return aid == null || aid.Length == 0
            ? CreateSelectIsdCommand()
            : SelectCommand.Create(aid);
    }

    /// <summary>
    /// Creates a SELECT command for a specific AID with explicit mode and response control.
    /// </summary>
    public static Result<SelectCommand, SmartCardError> CreateSelectCommand(
        byte[] aid,
        SelectCommand.SelectMode mode,
        SelectCommand.FileControlInfo controlInfo)
    {
        return SelectCommand.CreateWith(aid ?? [], mode, controlInfo);
    }

    /// <summary>
    /// Creates an INITIALIZE UPDATE command for secure channel establishment.
    /// </summary>
    /// <param name="keyVersion">The key version to use.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="hostChallenge">The 8-byte host challenge.</param>
    public static Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(
        byte keyVersion,
        byte keyId,
        byte[] hostChallenge)
    {
        return InitializeUpdateCommand.Create(keyVersion, keyId, hostChallenge);
    }

    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command.
    /// </summary>
    /// <param name="securityLevel">The security level for the session.</param>
    /// <param name="hostCryptogram">The host cryptogram.</param>
    /// <param name="mac">The MAC value (optional for some security levels).</param>
    public static Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommand(
        SecurityLevel securityLevel,
        byte[] hostCryptogram,
        byte[] mac = null)
    {
        return mac != null && mac.Length > 0
            ? ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac)
            : ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);
    }

    /// <summary>
    /// Creates a GET STATUS command.
    /// </summary>
    /// <param name="subset">The subset of entities to query.</param>
    /// <param name="searchCriteria">Optional search criteria.</param>
    public static Result<GetStatusCommand, SmartCardError> CreateGetStatusCommand(
        GetStatusCommand.StatusSubset subset,
        byte[] searchCriteria = null)
    {
        return GetStatusCommand.Create(subset, GetStatusCommand.ResponseFormat.Tlv, searchCriteria);
    }

    /// <summary>
    /// Creates a DELETE command for an application.
    /// </summary>
    /// <param name="aid">The AID of the application to delete.</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    public static Result<DeleteCommand, SmartCardError> CreateDeleteCommand(
        byte[] aid,
        bool deleteRelated = false)
    {
        return DeleteCommand.CreateForApplication(aid, deleteRelated);
    }

    /// <summary>
    /// Creates a GET DATA command.
    /// </summary>
    /// <param name="tag">The data object tag to retrieve.</param>
    public static Result<GetDataCommand, SmartCardError> CreateGetDataCommand(ushort tag)
    {
        return GetDataCommand.Create(tag);
    }

    /// <summary>
    /// Creates a PUT KEY command.
    /// </summary>
    /// <param name="keyVersion">The key version number.</param>
    /// <param name="keyDataBlocks">The key data blocks to install.</param>
    public static Result<PutKeyCommand, SmartCardError> CreatePutKeyCommand(
        byte keyVersion,
        KeyDataBlock[] keyDataBlocks)
    {
        return keyDataBlocks == null || keyDataBlocks.Length == 0
            ? Result.Failure<PutKeyCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Key data blocks cannot be null or empty"))
            : PutKeyCommand.Create(keyVersion, keyDataBlocks.ToList());
    }

    /// <summary>
    /// Creates a SET STATUS command for lifecycle state changes.
    /// </summary>
    /// <param name="aid">The AID of the target application (empty for card-level).</param>
    /// <param name="p1">The P1 parameter value.</param>
    public static Result<SetStatusCommand, SmartCardError> CreateSetStatusCommand(
        byte[] aid,
        byte p1)
    {
        return SetStatusCommand.Create(aid ?? [], p1);
    }

    /// <summary>
    /// Creates a LOAD command for CAP file installation.
    /// </summary>
    /// <param name="blockNumber">The block number (starting from 0).</param>
    /// <param name="isLastBlock">Whether this is the last block.</param>
    /// <param name="blockData">The block data to load.</param>
    public static Result<LoadCommand, SmartCardError> CreateLoadCommand(
        byte blockNumber,
        bool isLastBlock,
        byte[] blockData)
    {
        return LoadCommand.Create(blockNumber, blockData, isLastBlock);
    }

    /// <summary>
    /// Creates an INSTALL command.
    /// </summary>
    /// <param name="installType">The type of installation.</param>
    /// <param name="packageAid">The package AID.</param>
    /// <param name="appletAid">The applet AID (for INSTALL for INSTALL).</param>
    /// <param name="instanceAid">The instance AID (for INSTALL for INSTALL).</param>
    /// <param name="privileges">The privileges to grant.</param>
    /// <param name="installParameters">Installation parameters.</param>
    public static Result<InstallCommand, SmartCardError> CreateInstallCommand(
        InstallType installType,
        byte[] packageAid,
        byte[] appletAid = null,
        byte[] instanceAid = null,
        byte[] privileges = null,
        byte[] installParameters = null)
    {
        return installType switch
        {
            InstallType.ForLoad => InstallCommand.InstallForLoadCommand.Create(
                packageAid,
                null,  // maxDataBlockSize
                null,  // securityDomainAid  
                null,  // hash
                installParameters)
                .Map(cmd => (InstallCommand)cmd),
            InstallType.ForInstall => InstallCommand.InstallForInstallCommand.Create(
                packageAid,
                instanceAid ?? packageAid,  // moduleAid
                appletAid ?? packageAid,    // applicationAid
                privileges ?? [0x00],
                installParameters)
                .Map(cmd => (InstallCommand)cmd),
            InstallType.ForInstallAndMakeSelectable => InstallCommand.InstallForInstallCommand.CreateAndMakeSelectable(
                packageAid,
                instanceAid ?? packageAid,  // moduleAid
                appletAid ?? packageAid,    // applicationAid
                privileges ?? [0x00],
                installParameters)
                .Map(cmd => (InstallCommand)cmd),
            _ => Result.Failure<InstallCommand, SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported install type: {installType}"))
        };
    }
}
