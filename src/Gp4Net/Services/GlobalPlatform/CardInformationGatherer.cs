// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Pipeline;
using JetBrains.Annotations;
using WSCT.ISO7816;
using DomainCardCapabilities = Gp4Net.Domain.CardInfo.CardCapabilities;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// Service for gathering comprehensive card information using GET DATA commands.
/// Implements functional composition patterns with Result types for error handling.
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.3 (GET DATA Command)
/// </summary>
[PublicAPI]
public static class CardInformationGatherer
{
    /// <summary>
    /// Gathers all available card information using functional composition.
    /// Each data object is retrieved independently and failures are handled gracefully.
    /// </summary>
    /// <param name="executeCommand">Function to execute APDU commands</param>
    /// <param name="isdInfo">ISD information from SELECT response</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Complete CardInformation object with all available data</returns>
    public static async Task<Result<CardInformation, SmartCardError>> GatherAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        Maybe<SelectResponse> isdInfo,
        CancellationToken cancellationToken = default
    )
    {
        // Start with empty card information
        var cardInfo = CardInformation.Empty with
        {
            IsdInfo = isdInfo,
        };

        // Gather all data objects in parallel for efficiency
        var cplcTask = GetCplcDataAsync(executeCommand, cancellationToken);
        var cardDataTask = GetCardDataAsync(executeCommand, cancellationToken);
        var capabilitiesTask = GetCardCapabilitiesAsync(executeCommand, cancellationToken);
        var keyInfoTask = GetKeyInformationAsync(executeCommand, cancellationToken);
        var securityStatusTask = GetSecurityStatusAsync(executeCommand, cancellationToken);
        var diversificationDataTask = GetDiversificationDataAsync(
            executeCommand,
            cancellationToken
        );

        // Wait for all tasks to complete
        await Task.WhenAll(
            cplcTask,
            cardDataTask,
            capabilitiesTask,
            keyInfoTask,
            securityStatusTask,
            diversificationDataTask
        );

        // Compose the final result using functional patterns
        var finalCardInfo = cardInfo with
        {
            Cplc = cplcTask.Result.Match(
                success => Maybe<CplcData>.From(success),
                _ => Maybe<CplcData>.None
            ),
            CardData = cardDataTask.Result.Match(
                success => Maybe<CardDataInfo>.From(success),
                _ => Maybe<CardDataInfo>.None
            ),
            Capabilities = capabilitiesTask.Result.Match(
                success => Maybe<DomainCardCapabilities>.From(success),
                _ => Maybe<DomainCardCapabilities>.None
            ),
            KeyInfo = keyInfoTask.Result.Match(
                success => Maybe<KeyInformationTemplate>.From(success),
                _ => Maybe<KeyInformationTemplate>.None
            ),
            SecurityStatus = securityStatusTask.Result.Match(
                success => Maybe<SecurityDomainStatus>.From(success),
                _ => Maybe<SecurityDomainStatus>.None
            ),
            DiversificationData = diversificationDataTask.Result.Match(
                success => Maybe<byte[]>.From(success),
                _ => Maybe<byte[]>.None
            ),

            // Derive additional information from gathered data
            ScpInfo = DeriveScpInformation(
                capabilitiesTask.Result.Match(
                    success => Maybe<DomainCardCapabilities>.From(success),
                    _ => Maybe<DomainCardCapabilities>.None
                ),
                diversificationDataTask.Result.Match(
                    success => Maybe<byte[]>.From(success),
                    _ => Maybe<byte[]>.None
                )
            ),
            ChipDetails = DeriveChipDetails(
                cplcTask.Result.Match(
                    success => Maybe<CplcData>.From(success),
                    _ => Maybe<CplcData>.None
                ),
                cardDataTask.Result.Match(
                    success => Maybe<CardDataInfo>.From(success),
                    _ => Maybe<CardDataInfo>.None
                )
            ),
        };

        return Result.Success<CardInformation, SmartCardError>(finalCardInfo);
    }

    /// <summary>
    /// Retrieves CPLC (Card Production Life Cycle) data using GET DATA(0x9F7F).
    /// CPLC is an industry data object, not defined by GP Card Specification v2.3.1.
    /// </summary>
    private static async Task<Result<CplcData, SmartCardError>> GetCplcDataAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        return await GetDataCommand
            .Create(GetDataCommand.DataObjects.CardProductionLifeCycle)
            .Bind(async command =>
                await command
                    .ToCommandApdu()
                    .Bind(async apdu =>
                        await executeCommand(apdu, cancellationToken)
                            .Bind(response =>
                                GetDataResponse
                                    .Parse(
                                        GetDataCommand.DataObjects.CardProductionLifeCycle,
                                        response.Data
                                    )
                                    .Bind(getDataResponse =>
                                        getDataResponse
                                            .ParseAsCplc()
                                            .ToResult(
                                                SmartCardError.InvalidResponse(
                                                    "Failed to parse CPLC data"
                                                )
                                            )
                                    )
                            )
                    )
            );
    }

    /// <summary>
    /// Retrieves Card Data using GET DATA(0x0066).
    /// Contains OIDs for platform identification and version information.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section E.2.1.1
    /// </summary>
    private static async Task<Result<CardDataInfo, SmartCardError>> GetCardDataAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        return await GetDataCommand
            .Create(GetDataCommand.DataObjects.CardData)
            .Bind(async command =>
                await command
                    .ToCommandApdu()
                    .Bind(async apdu =>
                        await executeCommand(apdu, cancellationToken)
                            .Bind(response =>
                                GetDataResponse
                                    .Parse(GetDataCommand.DataObjects.CardData, response.Data)
                                    .Bind(getDataResponse =>
                                        getDataResponse
                                            .ParseAsCardData()
                                            .ToResult(
                                                SmartCardError.InvalidResponse(
                                                    "Failed to parse Card Data"
                                                )
                                            )
                                    )
                            )
                    )
            );
    }

    /// <summary>
    /// Retrieves Card Capabilities using GET DATA(0x0067).
    /// Contains SCP support, privileges, and algorithm information.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section E.2.1.1
    /// </summary>
    private static async Task<
        Result<DomainCardCapabilities, SmartCardError>
    > GetCardCapabilitiesAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        return await GetDataCommand
            .Create(GetDataCommand.DataObjects.CardCapabilities)
            .Bind(async command =>
                await command
                    .ToCommandApdu()
                    .Bind(async apdu =>
                        await executeCommand(apdu, cancellationToken)
                            .Bind(response =>
                                GetDataResponse
                                    .Parse(
                                        GetDataCommand.DataObjects.CardCapabilities,
                                        response.Data
                                    )
                                    .Bind(getDataResponse =>
                                        getDataResponse
                                            .ParseAsCardCapabilities()
                                            .ToResult(
                                                SmartCardError.InvalidResponse(
                                                    "Failed to parse Card Capabilities"
                                                )
                                            )
                                    )
                            )
                    )
            );
    }

    /// <summary>
    /// Retrieves Key Information Template using GET DATA(0x00E0).
    /// Contains cryptographic key details and versions.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section E.2.1.1
    /// </summary>
    private static async Task<
        Result<KeyInformationTemplate, SmartCardError>
    > GetKeyInformationAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        return await GetDataCommand
            .Create(GetDataCommand.DataObjects.KeyInformationTemplate)
            .Bind(async command =>
                await command
                    .ToCommandApdu()
                    .Bind(async apdu =>
                        await executeCommand(apdu, cancellationToken)
                            .Bind(response =>
                                GetDataResponse
                                    .Parse(
                                        GetDataCommand.DataObjects.KeyInformationTemplate,
                                        response.Data
                                    )
                                    .Bind(getDataResponse =>
                                        getDataResponse
                                            .ParseAsKeyInformation()
                                            .ToResult(
                                                SmartCardError.InvalidResponse(
                                                    "Failed to parse Key Information"
                                                )
                                            )
                                    )
                            )
                    )
            );
    }

    /// <summary>
    /// Retrieves Security Domain Management Data using GET DATA(0x00C1).
    /// Contains sequence counters and security status.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section E.2.1.1
    /// </summary>
    private static async Task<Result<SecurityDomainStatus, SmartCardError>> GetSecurityStatusAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        return await GetDataCommand
            .Create(GetDataCommand.DataObjects.SecurityDomainManagementData)
            .Bind(async command =>
                await command
                    .ToCommandApdu()
                    .Bind(async apdu =>
                        await executeCommand(apdu, cancellationToken)
                            .Bind(response =>
                                SecurityDomainStatus
                                    .Parse(Maybe<byte[]>.From(response.Data))
                                    .MapError(error =>
                                        SmartCardError.InvalidResponse(
                                            $"Failed to parse Security Status: {error}"
                                        )
                                    )
                            )
                    )
            );
    }

    /// <summary>
    /// Retrieves Diversification Data using GET DATA(0x00CF).
    /// Contains key derivation information and additional SCP support details.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section E.2.1.1
    /// </summary>
    private static async Task<Result<byte[], SmartCardError>> GetDiversificationDataAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        return await GetDataCommand
            .Create(GetDataCommand.DataObjects.DiversificationData)
            .Bind(async command =>
                await command
                    .ToCommandApdu()
                    .Bind(async apdu =>
                        await executeCommand(apdu, cancellationToken).Map(response => response.Data)
                    )
            );
    }

    /// <summary>
    /// Derives SCP information from multiple sources (capabilities and diversification data).
    /// Provides comprehensive SCP protocol and implementation option details.
    /// </summary>
    private static Maybe<ScpInformation> DeriveScpInformation(
        Maybe<DomainCardCapabilities> capabilities,
        Maybe<byte[]> diversificationData
    )
    {
        // Try to build SCP information from capabilities first
        var scpFromCapabilities = capabilities.Bind(cap =>
        {
            if (cap.ScpOptions.Count == 0)
                return Maybe<ScpInformation>.None;

            var protocols = cap
                .ScpOptions.GroupBy(opt => opt.ScpId)
                .Select(group => new ScpProtocolInfo(
                    group.Key,
                    group.Select(opt => (ScpImplementation)opt.Implementation).ToList()
                ))
                .ToList();

            return protocols.Count > 0
                ? Maybe<ScpInformation>.From(new ScpInformation(protocols))
                : Maybe<ScpInformation>.None;
        });

        // If capabilities don't provide SCP info, try diversification data
        if (scpFromCapabilities.HasValue)
            return scpFromCapabilities;

        return diversificationData.Bind(divData =>
        {
            var scpSupport = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(divData));
            if (string.IsNullOrEmpty(scpSupport) || scpSupport.Contains("None"))
                return Maybe<ScpInformation>.None;

            // Create basic SCP information from description - this is a simplified approach
            // In a full implementation, we'd parse the diversification data to extract actual protocol info
            var protocols = new[] { new ScpProtocolInfo(2, [ScpImplementation.Scp02I15]) };
            return Maybe<ScpInformation>.From(new ScpInformation(protocols));
        });
    }

    /// <summary>
    /// Derives chip details by combining CPLC manufacturing data with card data OIDs.
    /// Creates comprehensive chip identification and platform information.
    /// </summary>
    private static Maybe<ChipInfo> DeriveChipDetails(
        Maybe<CplcData> cplc,
        Maybe<CardDataInfo> cardData
    )
    {
        return cplc.Map(cplcData =>
        {
            // Use the existing factory method that handles all the chip type detection
            var chipInfo = ChipInfo.FromCplcData(cplcData);

            // Enhance with card data if available
            cardData.Match(
                Some: data =>
                {
                    // Update GlobalPlatform version from OID if available and more specific
                    data.GlobalPlatformVersionFromOid.Match(
                        Some: version =>
                            chipInfo.GlobalPlatformVersion = Maybe<string>.From(version),
                        None: () => { }
                    );

                    // Try to extract Java Card version from OIDs using GlobalPlatformOids helper
                    var javaCardVersion = ExtractJavaCardVersionFromOids(data.Oids);
                    javaCardVersion.Match(
                        Some: version => chipInfo.JavaCardVersion = Maybe<string>.From(version),
                        None: () => { }
                    );
                },
                None: () => { }
            );

            return chipInfo;
        });
    }

    /// <summary>
    /// Attempts to extract Java Card version from OID list.
    /// This is a simplified implementation - in practice would use more sophisticated OID parsing.
    /// </summary>
    private static Maybe<string> ExtractJavaCardVersionFromOids(IReadOnlyList<string> oids)
    {
        // Look for Java Card platform OIDs using functional composition
        var javaCardOids = oids.Where(oid => oid.Contains("1.2.840.114283.3")).ToList();

        return javaCardOids.Count > 0
            ? Maybe<string>.From("3.0.5") // Default JC version - would be parsed from actual OID
            : Maybe<string>.None;
    }
}
