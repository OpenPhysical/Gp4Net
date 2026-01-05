using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using JetBrains.Annotations;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// GlobalPlatform command builders and factories.
/// Creates properly formatted APDU commands per GP specifications.
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 11
/// </summary>
[PublicAPI]
public static class Commands
{
    /// <summary>
    /// Creates a SELECT command for the Issuer Security Domain (empty AID).
    /// Per GlobalPlatform specification, SELECT with empty AID selects the ISD.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.9
    /// </summary>
    public static Result<SelectCommand, SmartCardError> CreateSelectIsdCommand()
    {
        return SelectCommand.CreateForIssuerSecurityDomain();
    }

    /// <summary>
    /// Creates a SELECT command for the Issuer Security Domain with a specific response control.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.9
    /// </summary>
    public static Result<SelectCommand, SmartCardError> CreateSelectIsdCommand(
        SelectCommand.FileControlInfo controlInfo
    )
    {
        return SelectCommand.CreateWith([], SelectCommand.SelectMode.First, controlInfo);
    }

    /// <summary>
    /// Creates a SELECT command for a specific AID.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.9
    /// </summary>
    /// <param name="aid">The application identifier to select.</param>
    public static Result<SelectCommand, SmartCardError> CreateSelectCommand(byte[] aid)
    {
        return aid is not { Length: > 0 } ? CreateSelectIsdCommand() : SelectCommand.Create(aid);
    }

    /// <summary>
    /// Creates a SELECT command for a specific AID with explicit mode and response control.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.9
    /// </summary>
    public static Result<SelectCommand, SmartCardError> CreateSelectCommand(
        byte[] aid,
        SelectCommand.SelectMode mode,
        SelectCommand.FileControlInfo controlInfo
    )
    {
        return SelectCommand.CreateWith(aid ?? [], mode, controlInfo);
    }

    /// <summary>
    /// Creates an INITIALIZE UPDATE command for secure channel establishment.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.10
    /// </summary>
    /// <param name="keyVersion">The key version to use.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="hostChallenge">The 8-byte host challenge.</param>
    public static Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(
        byte keyVersion,
        byte keyId,
        byte[] hostChallenge
    )
    {
        return InitializeUpdateCommand.Create(keyVersion, keyId, hostChallenge);
    }

    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.11
    /// </summary>
    /// <param name="securityLevel">The security level for the session.</param>
    /// <param name="hostCryptogram">The host cryptogram.</param>
    /// <param name="mac">The MAC value (optional for some security levels).</param>
    public static Result<
        ExternalAuthenticateCommand,
        SmartCardError
    > CreateExternalAuthenticateCommand(
        SecurityLevel securityLevel,
        byte[] hostCryptogram,
        Maybe<byte[]> mac = default
    )
    {
        return mac.Match(
            macValue =>
                macValue.Length > 0
                    ? ExternalAuthenticateCommand.CreateWithMac(
                        securityLevel,
                        hostCryptogram,
                        macValue
                    )
                    : ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram),
            () => ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram)
        );
    }

    /// <summary>
    /// Creates a GET STATUS command.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5
    /// </summary>
    /// <param name="subset">The subset of entities to query.</param>
    /// <param name="searchCriteria">Optional search criteria.</param>
    public static Result<GetStatusCommand, SmartCardError> CreateGetStatusCommand(
        GetStatusCommand.StatusSubset subset,
        Maybe<byte[]> searchCriteria = default
    )
    {
        return GetStatusCommand.Create(subset, GetStatusCommand.ResponseFormat.Tlv, searchCriteria);
    }

    /// <summary>
    /// Creates a DELETE command for an application.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.8
    /// </summary>
    /// <param name="aid">The AID of the application to delete.</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    public static Result<DeleteCommand, SmartCardError> CreateDeleteCommand(
        byte[] aid,
        bool deleteRelated = false
    )
    {
        return DeleteCommand.CreateForApplication(aid, deleteRelated);
    }

    /// <summary>
    /// Creates a GET DATA command.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.3
    /// </summary>
    /// <param name="tag">The data object tag to retrieve.</param>
    public static Result<GetDataCommand, SmartCardError> CreateGetDataCommand(ushort tag)
    {
        return GetDataCommand.Create(tag);
    }

    /// <summary>
    /// Creates a PUT KEY command.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.7
    /// </summary>
    /// <param name="keyVersion">The key version number.</param>
    /// <param name="keyDataBlocks">The key data blocks to install.</param>
    public static Result<PutKeyCommand, SmartCardError> CreatePutKeyCommand(
        byte keyVersion,
        KeyDataBlock[] keyDataBlocks
    )
    {
        return keyDataBlocks is not { Length: > 0 }
            ? Result.Failure<PutKeyCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Key data blocks cannot be empty")
            )
            : PutKeyCommand.Create(keyVersion, keyDataBlocks.ToList());
    }

    /// <summary>
    /// Creates a SET STATUS command for lifecycle state changes.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
    /// </summary>
    /// <param name="aid">The AID of the target application (empty for card-level).</param>
    /// <param name="p1">The P1 parameter value.</param>
    public static Result<SetStatusCommand, SmartCardError> CreateSetStatusCommand(
        byte[] aid,
        byte p1
    )
    {
        return SetStatusCommand.Create(aid ?? [], p1);
    }

    /// <summary>
    /// Creates a LOAD command for CAP file installation.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.6
    /// </summary>
    /// <param name="blockNumber">The block number (starting from 0).</param>
    /// <param name="isLastBlock">Whether this is the last block.</param>
    /// <param name="blockData">The block data to load.</param>
    public static Result<LoadCommand, SmartCardError> CreateLoadCommand(
        byte blockNumber,
        bool isLastBlock,
        byte[] blockData
    )
    {
        return LoadCommand.Create(blockNumber, blockData, isLastBlock);
    }

    /// <summary>
    /// Creates an INSTALL command.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.6
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
        Maybe<byte[]> appletAid = default,
        Maybe<byte[]> instanceAid = default,
        Maybe<byte[]> privileges = default,
        Maybe<byte[]> installParameters = default
    )
    {
        return installType switch
        {
            InstallType.ForLoad
                => InstallCommand
                    .InstallForLoadCommand.Create(
                        packageAid,
                        maxDataBlockSize: Maybe<ushort>.None,
                        securityDomainAid: Maybe<byte[]>.None,
                        hash: Maybe<byte[]>.None,
                        installToken: Maybe<byte[]>.None
                    )
                    .Map(cmd => (InstallCommand)cmd),
            InstallType.ForInstall
                => InstallCommand
                    .InstallForInstallCommand.Create(
                        packageAid,
                        instanceAid.GetValueOrDefault(packageAid), // moduleAid
                        appletAid.GetValueOrDefault(packageAid), // applicationAid
                        privileges.GetValueOrDefault(new byte[] { 0x00 }),
                        installParameters
                    )
                    .Map(cmd => (InstallCommand)cmd),
            InstallType.ForInstallAndMakeSelectable
                => InstallCommand
                    .InstallForInstallCommand.CreateAndMakeSelectable(
                        packageAid,
                        instanceAid.GetValueOrDefault(packageAid), // moduleAid
                        appletAid.GetValueOrDefault(packageAid), // applicationAid
                        privileges.GetValueOrDefault(new byte[] { 0x00 }),
                        installParameters
                    )
                    .Map(cmd => (InstallCommand)cmd),
            _
                => Result.Failure<InstallCommand, SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported install type: {installType}")
                ),
        };
    }
}
