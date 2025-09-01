// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Pipeline;
using JetBrains.Annotations;
using static Gp4Net.Services.TlvService;

namespace Gp4Net.Services;

public static partial class GlobalPlatformService
{
    /// <summary>
    /// GlobalPlatform response parsers and processors.
    /// Handles parsing of APDU responses into domain objects.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11
    /// </summary>
    [PublicAPI]
    public static class Responses
    {
        /// <summary>
        /// Parses a SELECT command response.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.9
        /// </summary>
        /// <param name="response">The command response to parse.</param>
        /// <returns>The parsed SelectResponse or an error.</returns>
        public static Result<SelectResponse, SmartCardError> ParseSelectResponse(
            CommandResponse response
        )
        {
            if (!response.IsSuccess)
            {
                return Result.Failure<SelectResponse, SmartCardError>(
                    SmartCardError.InvalidResponse($"SELECT failed with SW: {response.StatusWord:X4}")
                );
            }

            return SelectResponse.Parse(response.Data);
        }

        /// <summary>
        /// Parses an INITIALIZE UPDATE command response.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.10
        /// </summary>
        /// <param name="response">The command response to parse.</param>
        /// <returns>The parsed InitializeUpdateResponse or an error.</returns>
        public static Result<InitializeUpdateResponse, SmartCardError> ParseInitializeUpdateResponse(
            CommandResponse response
        )
        {
            if (!response.IsSuccess)
            {
                return Result.Failure<InitializeUpdateResponse, SmartCardError>(
                    SmartCardError.InvalidResponse(
                        $"INITIALIZE UPDATE failed with SW: {response.StatusWord:X4}"
                    )
                );
            }

            return InitializeUpdateResponse.Parse(response.Data);
        }

        /// <summary>
        /// Parses a GET STATUS command response into ApplicationInfo objects.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5
        /// </summary>
        /// <param name="response">The command response to parse.</param>
        /// <returns>The list of applications or an error.</returns>
        public static Result<ImmutableList<ApplicationInfo>, SmartCardError> ParseGetStatusResponse(
            CommandResponse response
        )
        {
            if (!response.IsSuccess)
            {
                return Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(
                    SmartCardError.InvalidResponse(
                        $"GET STATUS failed with SW: {response.StatusWord:X4}"
                    )
                );
            }

            return GetStatusResponse
                .Parse(response.Data)
                .Map(parsed => ConvertToApplicationInfos(parsed));
        }

        /// <summary>
        /// Parses a GET DATA command response for CPLC data.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.3
        /// </summary>
        /// <param name="response">The command response to parse.</param>
        /// <returns>The parsed CPLC data or an error.</returns>
        public static Result<CplcData, SmartCardError> ParseCplcResponse(CommandResponse response)
        {
            if (!response.IsSuccess)
            {
                return Result.Failure<CplcData, SmartCardError>(
                    SmartCardError.InvalidResponse(
                        $"GET DATA (CPLC) failed with SW: {response.StatusWord:X4}"
                    )
                );
            }

            // Extract CPLC data from TLV structure
            byte[] cplcBytes = ExtractTlvValue(
                response.Data,
                GetDataCommand.DataObjects.CardProductionLifeCycle
            );

            if (cplcBytes.Length == 0)
            {
                return Result.Failure<CplcData, SmartCardError>(
                    SmartCardError.InvalidResponse("No CPLC data found in response")
                );
            }

            return CplcData.Parse(cplcBytes);
        }

        /// <summary>
        /// Parses a generic GET DATA command response.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.3
        /// </summary>
        /// <param name="response">The command response to parse.</param>
        /// <returns>The raw data bytes or an error.</returns>
        public static Result<byte[], SmartCardError> ParseGetDataResponse(CommandResponse response)
        {
            if (!response.IsSuccess)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidResponse($"GET DATA failed with SW: {response.StatusWord:X4}")
                );
            }

            return Result.Success<byte[], SmartCardError>(response.Data ?? []);
        }

        /// <summary>
        /// Parses a PUT KEY command response.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.7
        /// </summary>
        /// <param name="response">The command response to parse.</param>
        /// <returns>The parsed PutKeyResponse or an error.</returns>
        public static Result<PutKeyResponse, SmartCardError> ParsePutKeyResponse(
            CommandResponse response
        )
        {
            if (!response.IsSuccess)
            {
                return Result.Failure<PutKeyResponse, SmartCardError>(
                    SmartCardError.InvalidResponse($"PUT KEY failed with SW: {response.StatusWord:X4}")
                );
            }

            return PutKeyResponse.Parse(response.Data);
        }

        /// <summary>
        /// Parses a DELETE command response.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.8
        /// </summary>
        /// <param name="response">The command response to parse.</param>
        /// <returns>Success if the deletion was successful, failure otherwise.</returns>
        public static Result<bool, SmartCardError> ParseDeleteResponse(CommandResponse response)
        {
            if (!response.IsSuccess)
            {
                return Result.Failure<bool, SmartCardError>(
                    SmartCardError.InvalidResponse($"DELETE failed with SW: {response.StatusWord:X4}")
                );
            }

            return Result.Success<bool, SmartCardError>(true);
        }

        #region Private Helper Methods

        /// <summary>
        /// Converts GetStatusResponse entries to domain ApplicationInfo objects.
        /// </summary>
        private static ImmutableList<ApplicationInfo> ConvertToApplicationInfos(
            GetStatusResponse response
        )
        {
            return [.. response
                .Applications.Select(entry =>
                {
                    // Map lifecycle state from GetStatusResponse to domain model
                    LifecycleState lcState = entry.State switch
                    {
                        ApplicationStatusEntry.LifecycleState.Loaded => LifecycleState.Loaded,
                        ApplicationStatusEntry.LifecycleState.Installed => LifecycleState.Installed,
                        ApplicationStatusEntry.LifecycleState.Selectable => LifecycleState.Selectable,
                        ApplicationStatusEntry.LifecycleState.Personalized =>
                            LifecycleState.Personalized,
                        ApplicationStatusEntry.LifecycleState.Blocked => LifecycleState.Locked,
                        ApplicationStatusEntry.LifecycleState.Locked => LifecycleState.Locked,
                        _ => LifecycleState.Unknown,
                    };

                    // Parse privileges from up to 3 bytes (C5: 3 bytes)
                    ImmutableList<Privilege> privilegesList =
                        entry.Privileges.Length > 0
                            ? ParsePrivileges(entry.Privileges)
                            : ImmutableList<Privilege>.Empty;

                    // Determine application type based on privileges
                    ApplicationType appType = privilegesList.Contains(Privilege.SecurityDomain)
                        ? ApplicationType.IssuerSecurityDomain
                        : ApplicationType.Application;

                    return new ApplicationInfo(
                        entry.Aid,
                        lcState,
                        privilegesList,
                        appType,
                        Version: Maybe<string>.None,
                        AssociatedSecurityDomain: Maybe<byte[]>.None,
                        ExecutableLoadFileAid: entry is { ExecutableLoadFileAid: { Length: > 0 } c4 }
                            ? Maybe<byte[]>.From(c4)
                            : Maybe<byte[]>.None
                    );
                })];
        }

        /// <summary>
        /// Parses privilege byte into individual privilege flags.
        /// </summary>
        private static ImmutableList<Privilege> ParsePrivileges(byte[] privBytes)
        {
            byte b1 = privBytes.Length > 0 ? privBytes[0] : (byte)0x00;
            byte b2 = privBytes.Length > 1 ? privBytes[1] : (byte)0x00;
            byte b3 = privBytes.Length > 2 ? privBytes[2] : (byte)0x00;

            ImmutableList<Privilege>.Builder list = ImmutableList.CreateBuilder<Privilege>();

            if ((b1 & 0x80) != 0)
                list.Add(Privilege.SecurityDomain);
            if ((b1 & 0x40) != 0)
                list.Add(Privilege.DapVerification);
            if ((b1 & 0x20) != 0)
                list.Add(Privilege.DelegatedManagement);
            if ((b1 & 0x10) != 0)
                list.Add(Privilege.CardLock);
            if ((b1 & 0x08) != 0)
                list.Add(Privilege.CardTerminate);
            if ((b1 & 0x04) != 0)
                list.Add(Privilege.CardReset);
            if ((b1 & 0x02) != 0)
                list.Add(Privilege.CvmManagement);
            if ((b1 & 0x01) != 0)
                list.Add(Privilege.TrustedPath);

            if ((b2 & 0x80) != 0)
                list.Add(Privilege.AuthorizedManagement);
            if ((b2 & 0x40) != 0)
                list.Add(Privilege.TokenVerification);
            if ((b2 & 0x20) != 0)
                list.Add(Privilege.GlobalDelete);
            if ((b2 & 0x10) != 0)
                list.Add(Privilege.GlobalLock);
            if ((b2 & 0x08) != 0)
                list.Add(Privilege.GlobalRegistry);
            if ((b2 & 0x04) != 0)
                list.Add(Privilege.FinalApplication);
            if ((b2 & 0x02) != 0)
                list.Add(Privilege.GlobalService);
            if ((b2 & 0x01) != 0)
                list.Add(Privilege.ReceiptGeneration);

            if ((b3 & 0x01) != 0)
                list.Add(Privilege.MandatedDapVerification);

            return list.ToImmutable();
        }

        /// <summary>
        /// Extracts a TLV value from a data buffer.
        /// </summary>
        private static byte[] ExtractTlvValue(byte[] data, ushort expectedTag)
        {
            if (data is not { Length: >= 2 })
            {
                return [];
            }

            // For two-byte tags like 9F7F, we need to handle them specially
            if (expectedTag > 0xFF && data.Length >= 3)
            {
                byte firstByte = (byte)(expectedTag >> 8);
                byte secondByte = (byte)(expectedTag & 0xFF);

                if (data[0] == firstByte && data[1] == secondByte)
                {
                    // This is a two-byte tag
                    int offset = 2;
                    int length = ParseLength(data, ref offset);

                    if (length >= 0 && offset + length <= data.Length)
                    {
                        return [.. data.Skip(offset).Take(length)];
                    }
                }
            }

            // Try parsing with TlvParser for more complex structures
            Result<TlvService.ParseResult, SmartCardError> parseResult = TlvParser.ParseMultiple(data.ToImmutableArray());
            if (parseResult.IsFailure)
            {
                return [];
            }
            ImmutableList<TlvObject> elements = [.. parseResult.Value.Objects];

            // For single-byte tags
            if (expectedTag <= 0xFF)
            {
                IEnumerable<TlvObject> candidates = elements.Where(e =>
                {
                    Result<uint, SmartCardError> tagNumber = e.Tag.ToNumber();
                    return tagNumber is { IsSuccess: true, Value: var tagVal } && tagVal == expectedTag;
                });
                
                if (candidates.Any())
                {
                    return candidates.First().TlvData.Bytes.ToArray();
                }
            }

            return [];
        }

        /// <summary>
        /// Parses the length field of a TLV structure.
        /// </summary>
        private static int ParseLength(byte[] data, ref int offset)
        {
            if (offset >= data.Length)
            {
                return -1;
            }

            byte lenByte = data[offset++];

            // Short form (bit 8 = 0)
            if ((lenByte & 0x80) == 0)
            {
                return lenByte;
            }

            // Long form (bit 8 = 1, bits 7-1 indicate number of subsequent octets)
            int lenLength = lenByte & 0x7F;
            if (lenLength == 0 || offset + lenLength > data.Length)
            {
                return -1;
            }

            // Use LINQ to calculate content length functionally
            // Capture offset value to avoid ref parameter in lambda
            int currentOffset = offset;
            int contentLength = Enumerable
                .Range(0, lenLength)
                .Aggregate(0, (acc, i) => (acc << 8) | data[currentOffset + i]);
            
            offset += lenLength;
            return contentLength;
        }

        #endregion
    }
}