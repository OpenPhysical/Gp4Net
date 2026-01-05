using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Services;

public static partial class TlvService
{
    /// <summary>
    /// GlobalPlatform-specific TLV parsers for domain entities.
    /// Implements parsing according to GP Card Specification v2.3.1 Tables 11-36 and 11-37.
    /// </summary>
    [PublicAPI]
    public static class GlobalPlatformParsers
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
        public static Result<
            ImmutableList<ApplicationInfo>,
            SmartCardError
        > ParseApplicationsResponse(byte[] responseData)
        {
            if (responseData is null || responseData.Length == 0)
            {
                return Result.Success<ImmutableList<ApplicationInfo>, SmartCardError>(
                    ImmutableList<ApplicationInfo>.Empty
                );
            }

            return TlvParser
                .ParseMultiple([.. responseData])
                .Bind(parseResult =>
                {
                    var applicationList = parseResult
                        .Objects.Where(tlv =>
                            tlv.Tag.ToNumber()
                                .Match(success => success == TAG_GP_REGISTRY_DATA, failure => false)
                        )
                        .Select(ParseApplicationFromRegistryData)
                        .Where(result => result.IsSuccess)
                        .Select(result => result.Value)
                        .ToImmutableList();

                    return Result.Success<ImmutableList<ApplicationInfo>, SmartCardError>(
                        applicationList
                    );
                })
                .MapError(error =>
                    SmartCardError.InvalidData(
                        $"Failed to parse applications TLV response: {error}"
                    )
                );
        }

        /// <summary>
        /// Parses TLV-formatted GET STATUS response data for Executable Load Files.
        /// </summary>
        /// <param name="responseData">The TLV response data from GET STATUS command.</param>
        /// <returns>A Result containing the parsed load files or an error.</returns>
        public static Result<
            ImmutableList<ExecutableLoadFile>,
            SmartCardError
        > ParseLoadFilesResponse(byte[] responseData)
        {
            if (responseData is null || responseData.Length == 0)
            {
                return Result.Success<ImmutableList<ExecutableLoadFile>, SmartCardError>(
                    ImmutableList<ExecutableLoadFile>.Empty
                );
            }

            return TlvParser
                .ParseMultiple([.. responseData])
                .Bind(parseResult =>
                {
                    var loadFileList = parseResult
                        .Objects.Where(tlv =>
                            tlv.Tag.ToNumber()
                                .Match(success => success == TAG_GP_REGISTRY_DATA, failure => false)
                        )
                        .Select(ParseLoadFileFromRegistryData)
                        .Where(result => result.IsSuccess)
                        .Select(result => result.Value)
                        .ToImmutableList();

                    return Result.Success<ImmutableList<ExecutableLoadFile>, SmartCardError>(
                        loadFileList
                    );
                })
                .MapError(error =>
                    SmartCardError.InvalidData($"Failed to parse load files TLV response: {error}")
                );
        }

        /// <summary>
        /// Parses an application from GP Registry Data TLV (0xE3).
        /// </summary>
        private static Result<ApplicationInfo, SmartCardError> ParseApplicationFromRegistryData(
            TlvObject registryTlv
        )
        {
            return TlvParser
                .ParseMultiple(registryTlv.TlvData.Bytes)
                .Bind(nestedResult =>
                {
                    var nestedTlvs = nestedResult.Objects;

                    // Extract required fields using functional LINQ operations
                    var aidTlvs = nestedTlvs
                        .Where(tlv =>
                            tlv.Tag.ToNumber()
                                .Map(tagNum => tagNum == TAG_AID)
                                .GetValueOrDefault(false)
                        )
                        .ToImmutableArray();

                    var lifecycleTlvs = nestedTlvs
                        .Where(tlv =>
                            tlv.Tag.ToNumber()
                                .Map(tagNum => tagNum == TAG_LIFECYCLE_STATE)
                                .GetValueOrDefault(false)
                        )
                        .ToImmutableArray();

                    var privilegesTlvs = nestedTlvs
                        .Where(tlv =>
                            tlv.Tag.ToNumber()
                                .Map(tagNum => tagNum == TAG_PRIVILEGES)
                                .GetValueOrDefault(false)
                        )
                        .ToImmutableArray();

                    // Validate required fields exist
                    if (aidTlvs.Length == 0)
                    {
                        return Result.Failure<ApplicationInfo, SmartCardError>(
                            SmartCardError.InvalidData(
                                "Application AID (tag 4F) not found in registry data"
                            )
                        );
                    }

                    if (lifecycleTlvs.Length == 0)
                    {
                        return Result.Failure<ApplicationInfo, SmartCardError>(
                            SmartCardError.InvalidData(
                                "Lifecycle state (tag 9F70) not found in registry data"
                            )
                        );
                    }

                    var aidTlv = aidTlvs[0];
                    var lifecycleTlv = lifecycleTlvs[0];

                    // Parse lifecycle state
                    return ParseLifecycleState(lifecycleTlv.TlvData.Bytes.ToArray())
                        .Bind(lifecycleState =>
                        {
                            // Parse privileges - use empty array if not present
                            var privilegesData =
                                privilegesTlvs.Length > 0
                                    ? privilegesTlvs[0].TlvData.Bytes.ToArray()
                                    : [];
                            var privileges = ParsePrivileges(privilegesData);

                            // Determine application type from privileges
                            var appType = DetermineApplicationType(privileges);

                            // Extract optional associated security domain
                            var associatedSecurityDomainTlvs = nestedTlvs
                                .Where(tlv =>
                                    tlv.Tag.ToNumber()
                                        .Map(tagNum => tagNum == TAG_ASSOCIATED_SECURITY_DOMAIN)
                                        .GetValueOrDefault(false)
                                )
                                .ToImmutableArray();

                            var associatedSecurityDomain =
                                associatedSecurityDomainTlvs.Length > 0
                                    ? Maybe<byte[]>.From(
                                        associatedSecurityDomainTlvs[0].TlvData.Bytes.ToArray()
                                    )
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
            TlvObject registryTlv
        )
        {
            return TlvParser
                .ParseMultiple(registryTlv.TlvData.Bytes)
                .Bind(nestedResult =>
                {
                    var nestedTlvs = nestedResult.Objects;

                    // Extract required fields using functional LINQ operations
                    var aidTlvs = nestedTlvs
                        .Where(tlv =>
                            tlv.Tag.ToNumber()
                                .Map(tagNum => tagNum == TAG_AID)
                                .GetValueOrDefault(false)
                        )
                        .ToImmutableArray();

                    var lifecycleTlvs = nestedTlvs
                        .Where(tlv =>
                            tlv.Tag.ToNumber()
                                .Map(tagNum => tagNum == TAG_LIFECYCLE_STATE)
                                .GetValueOrDefault(false)
                        )
                        .ToImmutableArray();

                    // Validate required fields exist
                    if (aidTlvs.Length == 0)
                    {
                        return Result.Failure<ExecutableLoadFile, SmartCardError>(
                            SmartCardError.InvalidData(
                                "Load file AID (tag 4F) not found in registry data"
                            )
                        );
                    }

                    if (lifecycleTlvs.Length == 0)
                    {
                        return Result.Failure<ExecutableLoadFile, SmartCardError>(
                            SmartCardError.InvalidData(
                                "Lifecycle state (tag 9F70) not found in registry data"
                            )
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
                                .Where(tlv =>
                                    tlv.Tag.ToNumber()
                                        .Map(tagNum => tagNum == TAG_LOAD_FILE_VERSION)
                                        .GetValueOrDefault(false)
                                )
                                .ToImmutableArray();

                            var version =
                                versionTlvs.Length > 0
                                    ? Maybe<string>.From(
                                        ParseVersionString(versionTlvs[0].TlvData.Bytes.ToArray())
                                    )
                                    : Maybe<string>.None;

                            // Parse executable modules using LINQ
                            var modules = nestedTlvs
                                .Where(tlv =>
                                    tlv.Tag.ToNumber()
                                        .Map(tagNum => tagNum == TAG_EXECUTABLE_MODULE_AID)
                                        .GetValueOrDefault(false)
                                )
                                .Select(moduleTlv => new ExecutableModule(
                                    Aid: moduleTlv.TlvData.Bytes.ToArray()
                                ))
                                .ToImmutableList();

                            // Extract associated security domain
                            var associatedSdTlvs = nestedTlvs
                                .Where(tlv =>
                                    tlv.Tag.ToNumber()
                                        .Map(tagNum => tagNum == TAG_ASSOCIATED_SECURITY_DOMAIN)
                                        .GetValueOrDefault(false)
                                )
                                .ToImmutableArray();

                            var associatedSecurityDomain =
                                associatedSdTlvs.Length > 0
                                    ? Maybe<byte[]>.From(
                                        associatedSdTlvs[0].TlvData.Bytes.ToArray()
                                    )
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
            var lifecycleState = stateValue switch
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
        /// Parses application privileges from TLV value bytes using pure functional approach.
        /// </summary>
        private static ImmutableList<Privilege> ParsePrivileges(byte[] privilegeBytes)
        {
            if (privilegeBytes is null || privilegeBytes.Length == 0)
            {
                return ImmutableList<Privilege>.Empty;
            }

            // Use LINQ to generate all privileges based on bit flags
            var allPrivileges = new[]
            {
                // First byte (byte 0 = bits 7-0)
                (
                    privilegeBytes.Length >= 1 && (privilegeBytes[0] & 0x80) != 0,
                    Privilege.SecurityDomain
                ),
                (
                    privilegeBytes.Length >= 1 && (privilegeBytes[0] & 0x40) != 0,
                    Privilege.DapVerification
                ),
                (
                    privilegeBytes.Length >= 1 && (privilegeBytes[0] & 0x20) != 0,
                    Privilege.DelegatedManagement
                ),
                (privilegeBytes.Length >= 1 && (privilegeBytes[0] & 0x10) != 0, Privilege.CardLock),
                (
                    privilegeBytes.Length >= 1 && (privilegeBytes[0] & 0x08) != 0,
                    Privilege.CardTerminate
                ),
                (
                    privilegeBytes.Length >= 1 && (privilegeBytes[0] & 0x04) != 0,
                    Privilege.CardReset
                ),
                (
                    privilegeBytes.Length >= 1 && (privilegeBytes[0] & 0x02) != 0,
                    Privilege.CvmManagement
                ),
                (
                    privilegeBytes.Length >= 1 && (privilegeBytes[0] & 0x01) != 0,
                    Privilege.TrustedPath
                ),
                // Second byte (byte 1 = bits 15-8)
                (
                    privilegeBytes.Length >= 2 && (privilegeBytes[1] & 0x80) != 0,
                    Privilege.AuthorizedManagement
                ),
                (
                    privilegeBytes.Length >= 2 && (privilegeBytes[1] & 0x40) != 0,
                    Privilege.TokenVerification
                ),
                (
                    privilegeBytes.Length >= 2 && (privilegeBytes[1] & 0x20) != 0,
                    Privilege.GlobalDelete
                ),
                (
                    privilegeBytes.Length >= 2 && (privilegeBytes[1] & 0x10) != 0,
                    Privilege.GlobalLock
                ),
                (
                    privilegeBytes.Length >= 2 && (privilegeBytes[1] & 0x08) != 0,
                    Privilege.GlobalRegistry
                ),
                (
                    privilegeBytes.Length >= 2 && (privilegeBytes[1] & 0x04) != 0,
                    Privilege.FinalApplication
                ),
                (
                    privilegeBytes.Length >= 2 && (privilegeBytes[1] & 0x02) != 0,
                    Privilege.GlobalService
                ),
                (
                    privilegeBytes.Length >= 2 && (privilegeBytes[1] & 0x01) != 0,
                    Privilege.ReceiptGeneration
                ),
                // Third byte (byte 2 = bits 23-16)
                (
                    privilegeBytes.Length >= 3 && (privilegeBytes[2] & 0x01) != 0,
                    Privilege.MandatedDapVerification
                ),
            };

            return allPrivileges.Where(p => p.Item1).Select(p => p.Item2).ToImmutableList();
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

        /// <summary>
        /// Parses GET STATUS response for simple application status entries.
        /// This method handles the specific TLV format used by GetStatusCommand.
        /// </summary>
        /// <param name="response">The response data (excluding status word).</param>
        /// <returns>A Result containing either the parsed response entries or an error.</returns>
        public static Result<
            ImmutableList<ApplicationStatusEntry>,
            SmartCardError
        > ParseGetStatusResponse(byte[] response)
        {
            return Maybe<byte[]>
                .From(response)
                .ToResult(SmartCardError.InvalidArgument("Response data cannot be null"))
                .Bind(responseValue =>
                {
                    if (responseValue.Length == 0)
                    {
                        return Result.Success<
                            ImmutableList<ApplicationStatusEntry>,
                            SmartCardError
                        >(ImmutableList<ApplicationStatusEntry>.Empty);
                    }

                    var tlvParseResult = TlvParser.ParseMultiple([.. responseValue]);

                    if (tlvParseResult.IsFailure)
                    {
                        return Result.Success<
                            ImmutableList<ApplicationStatusEntry>,
                            SmartCardError
                        >(ImmutableList<ApplicationStatusEntry>.Empty);
                    }

                    return ParseApplicationStatusEntries(tlvParseResult.Value)
                        .Map(entries => entries.ToImmutableList());
                });
        }

        /// <summary>
        /// Parses multiple application status entries from TLV objects.
        /// Fails if any entry has validation errors (e.g., invalid lifecycle state).
        /// </summary>
        private static Result<
            IEnumerable<ApplicationStatusEntry>,
            SmartCardError
        > ParseApplicationStatusEntries(ParseResult parseResult)
        {
            var results = parseResult
                .Objects.Select(ParseSingleApplicationStatusEntry)
                .ToImmutableList();

            var failures = results.Where(r => r.IsFailure).ToImmutableList();

            if (failures.Any())
            {
                return Result.Failure<IEnumerable<ApplicationStatusEntry>, SmartCardError>(
                    failures.First().Error
                );
            }

            var validEntries = results
                .Where(result => result.IsSuccess)
                .Select(result => result.Value)
                .ToList();

            return Result.Success<IEnumerable<ApplicationStatusEntry>, SmartCardError>(
                validEntries
            );
        }

        /// <summary>
        /// Parses a single application status entry from a TLV container.
        /// </summary>
        private static Result<
            ApplicationStatusEntry,
            SmartCardError
        > ParseSingleApplicationStatusEntry(TlvObject container)
        {
            return container
                .Tag.ToNumber()
                .Bind(tagNumber =>
                    tagNumber == TAG_GP_REGISTRY_DATA
                        ? TlvParser.ParseMultiple(container.TlvData.Bytes)
                        : Result.Failure<ParseResult, SmartCardError>(
                            SmartCardError.InvalidResponse("Expected E3 container tag")
                        )
                )
                .Bind(childParseResult => ExtractRequiredApplicationTlvs(childParseResult.Objects))
                .Bind(tlvs =>
                    CreateApplicationStatusEntry(
                        tlvs.aid,
                        tlvs.lifecycle,
                        tlvs.privileges,
                        tlvs.executableLoadFile
                    )
                );
        }

        /// <summary>
        /// Extracts required TLV objects for application status entry.
        /// </summary>
        private static Result<
            (
                TlvObject aid,
                TlvObject lifecycle,
                Maybe<TlvObject> privileges,
                Maybe<TlvObject> executableLoadFile
            ),
            SmartCardError
        > ExtractRequiredApplicationTlvs(ImmutableArray<TlvObject> children)
        {
            var aidTlvs = children
                .Where(c => c.Tag.ToNumber().Match(tagNum => tagNum == TAG_AID, _ => false))
                .ToImmutableArray();

            var lifecycleTlvs = children
                .Where(c =>
                    c.Tag.ToNumber().Match(tagNum => tagNum == TAG_LIFECYCLE_STATE, _ => false)
                )
                .ToImmutableArray();

            var privilegesTlvs = children
                .Where(c => c.Tag.ToNumber().Match(tagNum => tagNum == TAG_PRIVILEGES, _ => false))
                .ToImmutableArray();

            var executableLoadFileTlvs = children
                .Where(c =>
                    c.Tag.ToNumber()
                        .Match(tagNum => tagNum == TAG_EXECUTABLE_LOAD_FILE_AID, _ => false)
                )
                .ToImmutableArray();

            if (aidTlvs.Length == 0)
            {
                return SmartCardError.InvalidResponse("Missing required AID (4F) TLV");
            }

            if (lifecycleTlvs.Length == 0)
            {
                return SmartCardError.InvalidResponse(
                    "Missing required lifecycle state (9F70) TLV"
                );
            }

            var aidTlv = aidTlvs[0];
            var lifecycleTlv = lifecycleTlvs[0];
            var privilegesTlv =
                privilegesTlvs.Length > 0
                    ? Maybe<TlvObject>.From(privilegesTlvs[0])
                    : Maybe<TlvObject>.None;
            var executableLoadFileTlv =
                executableLoadFileTlvs.Length > 0
                    ? Maybe<TlvObject>.From(executableLoadFileTlvs[0])
                    : Maybe<TlvObject>.None;

            return (aidTlv, lifecycleTlv, privilegesTlv, executableLoadFileTlv);
        }

        /// <summary>
        /// Creates an ApplicationStatusEntry from parsed TLV objects.
        /// </summary>
        private static Result<ApplicationStatusEntry, SmartCardError> CreateApplicationStatusEntry(
            TlvObject aidTlv,
            TlvObject lifecycleTlv,
            Maybe<TlvObject> privilegesTlv,
            Maybe<TlvObject> executableLoadFileTlv
        )
        {
            if (lifecycleTlv.TlvData.Bytes.Length == 0)
            {
                return SmartCardError.InvalidResponse("Lifecycle state TLV has no data");
            }

            byte lifecycleState = lifecycleTlv.TlvData.Bytes[0];
            if (!IsValidApplicationLifecycleState(lifecycleState))
            {
                return SmartCardError.InvalidResponse(
                    $"Invalid lifecycle state: 0x{lifecycleState:X2}"
                );
            }

            byte[] aid = aidTlv.TlvData.Bytes.ToArray();
            byte[] privileges = privilegesTlv.Match(
                Some: tlv => tlv.TlvData.Bytes.ToArray(),
                None: () => []
            );
            Maybe<byte[]> executableLoadFile = executableLoadFileTlv.Map(tlv =>
                tlv.TlvData.Bytes.ToArray()
            );

            return new ApplicationStatusEntry(
                aid,
                (ApplicationStatusEntry.LifecycleState)lifecycleState,
                privileges,
                executableLoadFile
            );
        }

        /// <summary>
        /// Validates if the provided lifecycle state value is valid for ApplicationStatusEntry.
        /// </summary>
        private static bool IsValidApplicationLifecycleState(byte state)
        {
            return state switch
            {
                0x01 => true, // Loaded
                0x03 => true, // Installed
                0x07 => true, // Selectable
                0x0F => true, // Personalized
                0x83 => true, // Blocked
                0x87 => true, // Locked
                _ => false,
            };
        }
    }
}
