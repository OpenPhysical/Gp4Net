using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects;

/// <summary>
/// Provides TLV parsing functionality for GET STATUS command responses.
/// Implements parsing according to GP Card Specification v2.3.1 Tables 11-36 and 11-37.
/// </summary>
[PublicAPI]
public static class GetStatusTlvParser
{
    // TLV tags per GP Card Specification v2.3.1
    private const uint TAG_GP_REGISTRY_DATA = 0xE3;          // GlobalPlatform Registry related data
    private const uint TAG_AID = 0x4F;                       // Application/Load File AID
    private const uint TAG_LIFECYCLE_STATE = 0x9F70;         // Life Cycle State
    private const uint TAG_PRIVILEGES = 0xC5;                // Application Privileges
    private const uint TAG_IMPLICIT_SELECTION = 0xCF;        // Implicit Selection Parameters
    private const uint TAG_EXECUTABLE_LOAD_FILE_AID = 0xC4;  // Application's Executable Load File AID
    private const uint TAG_ASSOCIATED_SECURITY_DOMAIN = 0xCC; // Associated Security Domain AID
    private const uint TAG_LOAD_FILE_VERSION = 0xCE;         // Executable Load File Version Number
    private const uint TAG_EXECUTABLE_MODULE_AID = 0x84;     // Executable Module AID

    /// <summary>
    /// Parses TLV-formatted GET STATUS response data for Applications and Security Domains.
    /// </summary>
    /// <param name="responseData">The TLV response data from GET STATUS command.</param>
    /// <returns>A Result containing the parsed applications or an error.</returns>
    public static Result<ImmutableList<ApplicationInfo>, SmartCardError> ParseApplicationsResponse(
        byte[] responseData)
    {
        if (responseData is null || responseData.Length == 0)
        {
            return Result.Success<ImmutableList<ApplicationInfo>, SmartCardError>(
                ImmutableList<ApplicationInfo>.Empty);
        }

        try
        {
            var tlvObjects = TlvParser.ParseAll(responseData);
            var applications = ImmutableList.CreateBuilder<ApplicationInfo>();

            foreach (var tlv in tlvObjects)
            {
                if (tlv.TagNumber == TAG_GP_REGISTRY_DATA)
                {
                    var appResult = ParseApplicationFromRegistryData(tlv);
                    if (appResult.IsSuccess)
                    {
                        applications.Add(appResult.Value);
                    }
                }
            }

            return Result.Success<ImmutableList<ApplicationInfo>, SmartCardError>(
                applications.ToImmutable());
        }
        catch (Exception ex)
        {
            return Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(
                SmartCardError.InvalidData($"Failed to parse applications TLV response: {ex.Message}"));
        }
    }

    /// <summary>
    /// Parses TLV-formatted GET STATUS response data for Executable Load Files.
    /// </summary>
    /// <param name="responseData">The TLV response data from GET STATUS command.</param>
    /// <returns>A Result containing the parsed load files or an error.</returns>
    public static Result<ImmutableList<ExecutableLoadFile>, SmartCardError> ParseLoadFilesResponse(
        byte[] responseData)
    {
        if (responseData is null || responseData.Length == 0)
        {
            return Result.Success<ImmutableList<ExecutableLoadFile>, SmartCardError>(
                ImmutableList<ExecutableLoadFile>.Empty);
        }

        try
        {
            var tlvObjects = TlvParser.ParseAll(responseData);
            var loadFiles = ImmutableList.CreateBuilder<ExecutableLoadFile>();

            foreach (var tlv in tlvObjects)
            {
                if (tlv.TagNumber == TAG_GP_REGISTRY_DATA)
                {
                    var loadFileResult = ParseLoadFileFromRegistryData(tlv);
                    if (loadFileResult.IsSuccess)
                    {
                        loadFiles.Add(loadFileResult.Value);
                    }
                }
            }

            return Result.Success<ImmutableList<ExecutableLoadFile>, SmartCardError>(
                loadFiles.ToImmutable());
        }
        catch (Exception ex)
        {
            return Result.Failure<ImmutableList<ExecutableLoadFile>, SmartCardError>(
                SmartCardError.InvalidData($"Failed to parse load files TLV response: {ex.Message}"));
        }
    }

    /// <summary>
    /// Parses an application from GP Registry Data TLV (0xE3).
    /// </summary>
    private static Result<ApplicationInfo, SmartCardError> ParseApplicationFromRegistryData(TlvObject registryTlv)
    {
        var nestedTlvs = registryTlv.ParseNestedTlv();
        
        // Extract required fields
        var aidTlv = nestedTlvs.FirstOrDefault(t => t.TagNumber == TAG_AID);
        var lifecycleTlv = nestedTlvs.FirstOrDefault(t => t.TagNumber == TAG_LIFECYCLE_STATE);
        var privilegesTlv = nestedTlvs.FirstOrDefault(t => t.TagNumber == TAG_PRIVILEGES);

        if (aidTlv is null)
        {
            return Result.Failure<ApplicationInfo, SmartCardError>(
                SmartCardError.InvalidData("Application AID (tag 4F) not found in registry data"));
        }

        if (lifecycleTlv is null)
        {
            return Result.Failure<ApplicationInfo, SmartCardError>(
                SmartCardError.InvalidData("Lifecycle state (tag 9F70) not found in registry data"));
        }

        // Parse lifecycle state
        var lifecycleState = ParseLifecycleState(lifecycleTlv.Value);
        if (lifecycleState.IsFailure)
        {
            return Result.Failure<ApplicationInfo, SmartCardError>(lifecycleState.Error);
        }

        // Parse privileges
        var privileges = ParsePrivileges(privilegesTlv?.Value ?? new byte[0]);

        // Determine application type from privileges
        var appType = DetermineApplicationType(privileges);

        // Extract optional fields
        var associatedSdTlv = nestedTlvs.FirstOrDefault(t => t.TagNumber == TAG_ASSOCIATED_SECURITY_DOMAIN);
        var associatedSecurityDomain = associatedSdTlv != null 
            ? Maybe<byte[]>.From((byte[])associatedSdTlv.Value.Clone())
            : Maybe<byte[]>.None;

        return Result.Success<ApplicationInfo, SmartCardError>(
            new ApplicationInfo(
                Aid: (byte[])aidTlv.Value.Clone(),
                LifecycleState: lifecycleState.Value,
                Privileges: privileges,
                Type: appType,
                Version: Maybe<string>.None, // Version not typically in application registry data
                AssociatedSecurityDomain: associatedSecurityDomain));
    }

    /// <summary>
    /// Parses an executable load file from GP Registry Data TLV (0xE3).
    /// </summary>
    private static Result<ExecutableLoadFile, SmartCardError> ParseLoadFileFromRegistryData(TlvObject registryTlv)
    {
        var nestedTlvs = registryTlv.ParseNestedTlv();
        
        // Extract required fields
        var aidTlv = nestedTlvs.FirstOrDefault(t => t.TagNumber == TAG_AID);
        var lifecycleTlv = nestedTlvs.FirstOrDefault(t => t.TagNumber == TAG_LIFECYCLE_STATE);

        if (aidTlv is null)
        {
            return Result.Failure<ExecutableLoadFile, SmartCardError>(
                SmartCardError.InvalidData("Load file AID (tag 4F) not found in registry data"));
        }

        if (lifecycleTlv is null)
        {
            return Result.Failure<ExecutableLoadFile, SmartCardError>(
                SmartCardError.InvalidData("Lifecycle state (tag 9F70) not found in registry data"));
        }

        // Parse lifecycle state
        var lifecycleState = ParseLifecycleState(lifecycleTlv.Value);
        if (lifecycleState.IsFailure)
        {
            return Result.Failure<ExecutableLoadFile, SmartCardError>(lifecycleState.Error);
        }

        // Parse version if available
        var versionTlv = nestedTlvs.FirstOrDefault(t => t.TagNumber == TAG_LOAD_FILE_VERSION);
        var version = versionTlv != null 
            ? Maybe<string>.From(ParseVersionString(versionTlv.Value))
            : Maybe<string>.None;

        // Parse executable modules
        var moduleTlvs = nestedTlvs.Where(t => t.TagNumber == TAG_EXECUTABLE_MODULE_AID);
        var modules = ImmutableList.CreateBuilder<ExecutableModule>();
        
        foreach (var moduleTlv in moduleTlvs)
        {
            modules.Add(new ExecutableModule(
                Aid: (byte[])moduleTlv.Value.Clone()));
        }

        // Extract associated security domain
        var associatedSdTlv = nestedTlvs.FirstOrDefault(t => t.TagNumber == TAG_ASSOCIATED_SECURITY_DOMAIN);
        var associatedSecurityDomain = associatedSdTlv != null 
            ? Maybe<byte[]>.From((byte[])associatedSdTlv.Value.Clone())
            : Maybe<byte[]>.None;

        return Result.Success<ExecutableLoadFile, SmartCardError>(
            new ExecutableLoadFile(
                Aid: (byte[])aidTlv.Value.Clone(),
                LifecycleState: lifecycleState.Value,
                Version: version,
                ExecutableModules: modules.ToImmutable(),
                AssociatedSecurityDomainAid: associatedSecurityDomain));
    }

    /// <summary>
    /// Parses lifecycle state from TLV value bytes.
    /// </summary>
    private static Result<LifecycleState, SmartCardError> ParseLifecycleState(byte[] stateBytes)
    {
        if (stateBytes is null || stateBytes.Length == 0)
        {
            return Result.Failure<LifecycleState, SmartCardError>(
                SmartCardError.InvalidData("Lifecycle state value is empty"));
        }

        var stateValue = stateBytes[0];
        var lifecycleState = stateValue switch
        {
            0x01 => LifecycleState.Loaded,
            0x03 => LifecycleState.Installed,
            0x07 => LifecycleState.Selectable,
            0x0F => LifecycleState.Personalized,
            0x80 => LifecycleState.Terminated,
            0x83 => LifecycleState.Locked,
            0x87 => LifecycleState.Locked,
            _ => LifecycleState.Unknown
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

        var privileges = ImmutableList.CreateBuilder<Privilege>();

        // Parse first byte of privileges per GP specification (byte 0 = bits 7-0)
        if (privilegeBytes.Length >= 1)
        {
            var byte1 = privilegeBytes[0];
            
            if ((byte1 & 0x80) != 0) privileges.Add(Privilege.SecurityDomain);
            if ((byte1 & 0x40) != 0) privileges.Add(Privilege.DapVerification);
            if ((byte1 & 0x20) != 0) privileges.Add(Privilege.DelegatedManagement);
            if ((byte1 & 0x10) != 0) privileges.Add(Privilege.CardLock);
            if ((byte1 & 0x08) != 0) privileges.Add(Privilege.CardTerminate);
            if ((byte1 & 0x04) != 0) privileges.Add(Privilege.CardReset);
            if ((byte1 & 0x02) != 0) privileges.Add(Privilege.CvmManagement);
            if ((byte1 & 0x01) != 0) privileges.Add(Privilege.TrustedPath);
        }

        // Parse second byte if present (byte 1 = bits 15-8)
        if (privilegeBytes.Length >= 2)
        {
            var byte2 = privilegeBytes[1];
            if ((byte2 & 0x80) != 0) privileges.Add(Privilege.AuthorizedManagement);
            if ((byte2 & 0x40) != 0) privileges.Add(Privilege.TokenVerification);
            if ((byte2 & 0x20) != 0) privileges.Add(Privilege.GlobalDelete);
            if ((byte2 & 0x10) != 0) privileges.Add(Privilege.GlobalLock);
            if ((byte2 & 0x08) != 0) privileges.Add(Privilege.GlobalRegistry);
            if ((byte2 & 0x04) != 0) privileges.Add(Privilege.FinalApplication);
            if ((byte2 & 0x02) != 0) privileges.Add(Privilege.GlobalService);
            if ((byte2 & 0x01) != 0) privileges.Add(Privilege.ReceiptGeneration);
        }

        // Third byte (byte 2 = bits 23-16) reserved for application-specific privileges
        if (privilegeBytes.Length >= 3)
        {
            var byte3 = privilegeBytes[2];
            if ((byte3 & 0x01) != 0) privileges.Add(Privilege.MandatedDapVerification);
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

        // For Java Card CAP files, version is 2 bytes: major.minor
        if (versionBytes.Length >= 2)
        {
            return $"{versionBytes[0]}.{versionBytes[1]}";
        }

        // Single byte version
        if (versionBytes.Length == 1)
        {
            return versionBytes[0].ToString();
        }

        // Unknown format - return as hex
        return Convert.ToHexString(versionBytes);
    }
}