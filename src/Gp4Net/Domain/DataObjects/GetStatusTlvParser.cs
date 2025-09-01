using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using static Gp4Net.Services.TlvService;
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects;

/// <summary>
/// Provides TLV parsing functionality for GET STATUS command responses.
/// Implements parsing according to GP Card Specification v2.3.1 Tables 11-36 and 11-37.
/// This parser delegates to TlvService for all TLV operations.
/// </summary>
[PublicAPI]
public static class GetStatusTlvParser
{
    // TLV tags per GP Card Specification v2.3.1
    private const uint TAG_GP_REGISTRY_DATA = 0xE3; // GlobalPlatform Registry related data
    private const uint TAG_AID = 0x4F; // Application/Load File AID
    private const uint TAG_LIFECYCLE_STATE = 0x9F70; // Life Cycle State
    private const uint TAG_PRIVILEGES = 0xC5; // Application Privileges
    private const uint TAG_IMPLICIT_SELECTION = 0xCF; // Implicit Selection Parameters
    private const uint TAG_EXECUTABLE_LOAD_FILE_AID = 0xC4; // Application's Executable Load File AID
    private const uint TAG_ASSOCIATED_SECURITY_DOMAIN = 0xCC; // Associated Security Domain AID
    private const uint TAG_LOAD_FILE_VERSION = 0xCE; // Executable Load File Version Number
    private const uint TAG_EXECUTABLE_MODULE_AID = 0x84; // Executable Module AID

    /// <summary>
    /// Parses TLV-formatted GET STATUS response data for Applications and Security Domains.
    /// </summary>
    /// <param name="responseData">The TLV response data from GET STATUS command.</param>
    /// <returns>A Result containing the parsed applications or an error.</returns>
    public static Result<ImmutableList<ApplicationInfo>, SmartCardError> ParseApplicationsResponse(
        byte[] responseData
    )
    {
        if (responseData is null || responseData.Length == 0)
        {
            return Result.Success<ImmutableList<ApplicationInfo>, SmartCardError>(
                ImmutableList<ApplicationInfo>.Empty
            );
        }

        return TlvService.TlvParser.ParseMultiple(responseData.ToImmutableArray())
            .Bind(parseResult => {
                var applicationList = parseResult.Objects
                    .Where(tlv => tlv.Tag.ToNumber()
                        .Match(
                            success => success == TAG_GP_REGISTRY_DATA,
                            failure => false))
                    .Select(ParseApplicationFromRegistryData)
                    .Where(result => result.IsSuccess)
                    .Select(result => result.Value)
                    .ToImmutableList();
                
                return Result.Success<ImmutableList<ApplicationInfo>, SmartCardError>(applicationList);
            })
            .MapError(error => SmartCardError.InvalidData($"Failed to parse applications TLV response: {error}"));
    }

    /// <summary>
    /// Parses TLV-formatted GET STATUS response data for Executable Load Files.
    /// </summary>
    /// <param name="responseData">The TLV response data from GET STATUS command.</param>
    /// <returns>A Result containing the parsed load files or an error.</returns>
    public static Result<ImmutableList<ExecutableLoadFile>, SmartCardError> ParseLoadFilesResponse(
        byte[] responseData
    )
    {
        if (responseData is null || responseData.Length == 0)
        {
            return Result.Success<ImmutableList<ExecutableLoadFile>, SmartCardError>(
                ImmutableList<ExecutableLoadFile>.Empty
            );
        }

        return TlvService.TlvParser.ParseMultiple(responseData.ToImmutableArray())
            .Bind(parseResult => {
                var loadFileList = parseResult.Objects
                    .Where(tlv => tlv.Tag.ToNumber()
                        .Match(
                            success => success == TAG_GP_REGISTRY_DATA,
                            failure => false))
                    .Select(ParseLoadFileFromRegistryData)
                    .Where(result => result.IsSuccess)
                    .Select(result => result.Value)
                    .ToImmutableList();
                
                return Result.Success<ImmutableList<ExecutableLoadFile>, SmartCardError>(loadFileList);
            })
            .MapError(error => SmartCardError.InvalidData($"Failed to parse load files TLV response: {error}"));
    }

    /// <summary>
    /// Parses an application from GP Registry Data TLV (0xE3).
    /// </summary>
    private static Result<ApplicationInfo, SmartCardError> ParseApplicationFromRegistryData(
        TlvService.TlvObject registryTlv
    )
    {
        return TlvService.TlvParser.ParseMultiple(registryTlv.TlvData.Bytes)
            .Bind(nestedResult =>
            {
                var nestedTlvs = nestedResult.Objects;

                // Extract required fields using functional LINQ operations
                var aidTlvs = nestedTlvs
                    .Where(tlv => tlv.Tag.ToNumber().Map(tagNum => tagNum == TAG_AID).GetValueOrDefault(false))
                    .ToImmutableArray();

                var lifecycleTlvs = nestedTlvs
                    .Where(tlv => tlv.Tag.ToNumber().Map(tagNum => tagNum == TAG_LIFECYCLE_STATE).GetValueOrDefault(false))
                    .ToImmutableArray();

                var privilegesTlvs = nestedTlvs
                    .Where(tlv => tlv.Tag.ToNumber().Map(tagNum => tagNum == TAG_PRIVILEGES).GetValueOrDefault(false))
                    .ToImmutableArray();

                // Validate required fields exist
                if (aidTlvs.Length == 0)
                {
                    return Result.Failure<ApplicationInfo, SmartCardError>(
                        SmartCardError.InvalidData("Application AID (tag 4F) not found in registry data")
                    );
                }

                if (lifecycleTlvs.Length == 0)
                {
                    return Result.Failure<ApplicationInfo, SmartCardError>(
                        SmartCardError.InvalidData("Lifecycle state (tag 9F70) not found in registry data")
                    );
                }

                var aidTlv = aidTlvs[0];
                var lifecycleTlv = lifecycleTlvs[0];

                // Parse lifecycle state
                return ParseLifecycleState(lifecycleTlv.TlvData.Bytes.ToArray())
                    .Bind(lifecycleState =>
                    {
                        // Parse privileges - use empty array if not present
                        var privilegesData = privilegesTlvs.Length > 0 
                            ? privilegesTlvs[0].TlvData.Bytes.ToArray()
                            : Array.Empty<byte>();
                        var privileges = ParsePrivileges(privilegesData);

                        // Determine application type from privileges
                        var appType = DetermineApplicationType(privileges);

                        // Extract optional associated security domain
                        var associatedSecurityDomainTlvs = nestedTlvs
                            .Where(tlv => tlv.Tag.ToNumber()
                                .Map(tagNum => tagNum == TAG_ASSOCIATED_SECURITY_DOMAIN).GetValueOrDefault(false))
                            .ToImmutableArray();

                        var associatedSecurityDomain = associatedSecurityDomainTlvs.Length > 0
                            ? Maybe<byte[]>.From(associatedSecurityDomainTlvs[0].TlvData.Bytes.ToArray())
                            : Maybe<byte[]>.None;

                        return Result.Success<ApplicationInfo, SmartCardError>(
                            new ApplicationInfo(
                                Aid: aidTlv.TlvData.Bytes.ToArray(),
                                LifecycleState: lifecycleState,
                                Privileges: privileges,
                                Type: appType,
                                Version: Maybe<string>.None,
                                AssociatedSecurityDomain: associatedSecurityDomain
                            )
                        );
                    });
            });
    }

    /// <summary>
    /// Parses an executable load file from GP Registry Data TLV (0xE3).
    /// </summary>
    private static Result<ExecutableLoadFile, SmartCardError> ParseLoadFileFromRegistryData(
        TlvService.TlvObject registryTlv
    )
    {
        return TlvService.TlvParser.ParseMultiple(registryTlv.TlvData.Bytes)
            .Bind(nestedResult =>
            {
                var nestedTlvs = nestedResult.Objects;

                // Extract required fields using functional LINQ operations
                var aidTlvs = nestedTlvs
                    .Where(tlv => tlv.Tag.ToNumber().Map(tagNum => tagNum == TAG_AID).GetValueOrDefault(false))
                    .ToImmutableArray();

                var lifecycleTlvs = nestedTlvs
                    .Where(tlv => tlv.Tag.ToNumber().Map(tagNum => tagNum == TAG_LIFECYCLE_STATE).GetValueOrDefault(false))
                    .ToImmutableArray();

                // Validate required fields exist
                if (aidTlvs.Length == 0)
                {
                    return Result.Failure<ExecutableLoadFile, SmartCardError>(
                        SmartCardError.InvalidData("Load file AID (tag 4F) not found in registry data")
                    );
                }

                if (lifecycleTlvs.Length == 0)
                {
                    return Result.Failure<ExecutableLoadFile, SmartCardError>(
                        SmartCardError.InvalidData("Lifecycle state (tag 9F70) not found in registry data")
                    );
                }

                var aidTlv = aidTlvs[0];
                var lifecycleTlv = lifecycleTlvs[0];

                // Parse lifecycle state
                return ParseLifecycleState(lifecycleTlv.TlvData.Bytes.ToArray())
                    .Bind(lifecycleState =>
                    {
                        // Parse version if available
                        var versionTlvs = nestedTlvs
                            .Where(tlv => tlv.Tag.ToNumber()
                                .Map(tagNum => tagNum == TAG_LOAD_FILE_VERSION).GetValueOrDefault(false))
                            .ToImmutableArray();

                        var version = versionTlvs.Length > 0
                            ? Maybe<string>.From(ParseVersionString(versionTlvs[0].TlvData.Bytes.ToArray()))
                            : Maybe<string>.None;

                        // Parse executable modules using LINQ
                        var modules = nestedTlvs
                            .Where(tlv => tlv.Tag.ToNumber()
                                .Map(tagNum => tagNum == TAG_EXECUTABLE_MODULE_AID).GetValueOrDefault(false))
                            .Select(moduleTlv => new ExecutableModule(Aid: moduleTlv.TlvData.Bytes.ToArray()))
                            .ToImmutableList();

                        // Extract associated security domain
                        var associatedSdTlvs = nestedTlvs
                            .Where(tlv => tlv.Tag.ToNumber()
                                .Map(tagNum => tagNum == TAG_ASSOCIATED_SECURITY_DOMAIN).GetValueOrDefault(false))
                            .ToImmutableArray();

                        var associatedSecurityDomain = associatedSdTlvs.Length > 0
                            ? Maybe<byte[]>.From(associatedSdTlvs[0].TlvData.Bytes.ToArray())
                            : Maybe<byte[]>.None;

                        return Result.Success<ExecutableLoadFile, SmartCardError>(
                            new ExecutableLoadFile(
                                Aid: aidTlv.TlvData.Bytes.ToArray(),
                                LifecycleState: lifecycleState,
                                Version: version,
                                ExecutableModules: modules,
                                AssociatedSecurityDomainAid: associatedSecurityDomain
                            )
                        );
                    });
            });
    }

    /// <summary>
    /// Parses lifecycle state from TLV value bytes.
    /// </summary>
    private static Result<LifecycleState, SmartCardError> ParseLifecycleState(byte[] stateBytes)
    {
        if (stateBytes is null || stateBytes.Length == 0)
        {
            return Result.Failure<LifecycleState, SmartCardError>(
                SmartCardError.InvalidData("Lifecycle state value is empty")
            );
        }

        byte stateValue = stateBytes[0];
        LifecycleState lifecycleState = stateValue switch
        {
            0x01 => LifecycleState.Loaded,
            0x03 => LifecycleState.Installed,
            0x07 => LifecycleState.Selectable,
            0x0F => LifecycleState.Personalized,
            0x80 => LifecycleState.Terminated,
            0x83 => LifecycleState.Locked,
            0x87 => LifecycleState.Locked,
            _ => LifecycleState.Unknown,
        };

        return Result.Success<LifecycleState, SmartCardError>(lifecycleState);
    }

    /// <summary>
    /// Parses application privileges from TLV value bytes.
    /// </summary>
    private static ImmutableList<Privilege> ParsePrivileges(byte[] privilegeBytes)
    {
        if (privilegeBytes is null || privilegeBytes.Length == 0)
        {
            return ImmutableList<Privilege>.Empty;
        }

        ImmutableList<Privilege>.Builder privileges = ImmutableList.CreateBuilder<Privilege>();

        // Parse first byte of privileges per GP specification (byte 0 = bits 7-0)
        if (privilegeBytes.Length >= 1)
        {
            byte byte1 = privilegeBytes[0];

            if ((byte1 & 0x80) != 0)
                privileges.Add(Privilege.SecurityDomain);
            if ((byte1 & 0x40) != 0)
                privileges.Add(Privilege.DapVerification);
            if ((byte1 & 0x20) != 0)
                privileges.Add(Privilege.DelegatedManagement);
            if ((byte1 & 0x10) != 0)
                privileges.Add(Privilege.CardLock);
            if ((byte1 & 0x08) != 0)
                privileges.Add(Privilege.CardTerminate);
            if ((byte1 & 0x04) != 0)
                privileges.Add(Privilege.CardReset);
            if ((byte1 & 0x02) != 0)
                privileges.Add(Privilege.CvmManagement);
            if ((byte1 & 0x01) != 0)
                privileges.Add(Privilege.TrustedPath);
        }

        // Parse second byte if present (byte 1 = bits 15-8)
        if (privilegeBytes.Length >= 2)
        {
            byte byte2 = privilegeBytes[1];
            if ((byte2 & 0x80) != 0)
                privileges.Add(Privilege.AuthorizedManagement);
            if ((byte2 & 0x40) != 0)
                privileges.Add(Privilege.TokenVerification);
            if ((byte2 & 0x20) != 0)
                privileges.Add(Privilege.GlobalDelete);
            if ((byte2 & 0x10) != 0)
                privileges.Add(Privilege.GlobalLock);
            if ((byte2 & 0x08) != 0)
                privileges.Add(Privilege.GlobalRegistry);
            if ((byte2 & 0x04) != 0)
                privileges.Add(Privilege.FinalApplication);
            if ((byte2 & 0x02) != 0)
                privileges.Add(Privilege.GlobalService);
            if ((byte2 & 0x01) != 0)
                privileges.Add(Privilege.ReceiptGeneration);
        }

        // Third byte (byte 2 = bits 23-16) reserved for application-specific privileges
        if (privilegeBytes.Length >= 3)
        {
            byte byte3 = privilegeBytes[2];
            if ((byte3 & 0x01) != 0)
                privileges.Add(Privilege.MandatedDapVerification);
        }

        return privileges.ToImmutable();
    }

    /// <summary>
    /// Determines application type from privileges.
    /// </summary>
    private static ApplicationType DetermineApplicationType(ImmutableList<Privilege> privileges)
    {
        if (privileges.Contains(Privilege.SecurityDomain))
        {
            // Check if it's an ISD (has global registry privilege)
            if (privileges.Contains(Privilege.GlobalRegistry))
            {
                return ApplicationType.IssuerSecurityDomain;
            }
            return ApplicationType.SupplementarySecurityDomain;
        }

        return ApplicationType.Application;
    }

    /// <summary>
    /// Parses version string from version TLV value bytes.
    /// For Java Card CAP files, this is major.minor format.
    /// </summary>
    private static string ParseVersionString(byte[] versionBytes)
    {
        if (versionBytes is null || versionBytes.Length == 0)
        {
            return "Unknown";
        }

        switch (versionBytes.Length)
        {
            // For Java Card CAP files, version is 2 bytes: major.minor
            case >= 2:
                return $"{versionBytes[0]}.{versionBytes[1]}";

            // Single byte version
            case 1:
                return versionBytes[0].ToString();
            default:
                // Unknown format - return as hex
                return Convert.ToHexString(versionBytes);
        }
    }

}
