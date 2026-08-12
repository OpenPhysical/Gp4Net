using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the GET STATUS command for querying card content status.
/// </summary>
[PublicAPI]
public class GetStatusCommand : IApduCommand
{
    /// <summary>
    /// Get status subset values for P1.
    /// </summary>
    public enum StatusSubset : byte
    {
        /// <summary>
        /// Issuer Security Domain only.
        /// </summary>
        IssuerSecurityDomain = 0x80,

        /// <summary>
        /// Applications and Supplementary Security Domains only.
        /// </summary>
        ApplicationsAndSupplementaryDomains = 0x40,

        /// <summary>
        /// Executable Load Files only.
        /// </summary>
        ExecutableLoadFiles = 0x20,

        /// <summary>
        /// Executable Load Files and their Executable Modules.
        /// </summary>
        ExecutableLoadFilesAndModules = 0x10,
    }

    /// <summary>
    /// Response format values for P2.
    /// </summary>
    public enum ResponseFormat : byte
    {
        /// <summary>
        /// Deprecated response format.
        /// </summary>
        Deprecated = 0x00,

        /// <summary>
        /// Deprecated response format.
        /// </summary>
        None = Deprecated,

        /// <summary>
        /// Return data in TLV format.
        /// </summary>
        Tlv = 0x02,
    }

    /// <summary>
    /// Occurrence selection values for P2.b1.
    /// </summary>
    public enum OccurrenceMode : byte
    {
        /// <summary>Gets the first or all occurrences.</summary>
        FirstOrAll = 0x00,

        /// <summary>Gets the next occurrences.</summary>
        Next = 0x01,
    }

    /// <summary>
    /// Gets the status subset to query.
    /// </summary>
    public StatusSubset Subset { get; }

    /// <summary>
    /// Gets the response format.
    /// </summary>
    public ResponseFormat Format { get; }

    /// <summary>
    /// Gets the occurrence selection.
    /// </summary>
    public OccurrenceMode Occurrence { get; }

    /// <summary>
    /// Gets the search criteria (optional AID).
    /// </summary>
    public Maybe<byte[]> SearchCriteria { get; }

    /// <inheritdoc />
    public byte Cla => GlobalPlatform.Cla.GP_STANDARD;

    /// <inheritdoc />
    public byte Ins => GlobalPlatform.Ins.GET_STATUS;

    /// <summary>
    /// Gets the P1 parameter (status subset).
    /// </summary>
    public byte P1 => (byte)Subset;

    /// <summary>
    /// Gets the P2 parameter (response format).
    /// </summary>
    public byte P2 => (byte)((byte)Format | (byte)Occurrence);

    /// <summary>
    /// Gets the command data (search criteria).
    /// </summary>
    public byte[] Data => SearchCriteria.GetValueOrDefault([]);

    /// <summary>
    /// Gets the expected response length.
    /// </summary>
    public int ExpectedResponseLength => 256;

    /// <summary>
    /// Gets whether this command uses extended length encoding.
    /// </summary>
    public bool IsExtendedLength => false;

    /// <summary>
    /// Creates a WSCT CommandAPDU for this GET STATUS command.
    /// </summary>
    /// <returns>A Result containing the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        return ApduBuilder.CreateCommand(
            GlobalPlatform.Cla.GP_STANDARD,
            GlobalPlatform.Ins.GET_STATUS,
            (byte)Subset,
            P2,
            SearchCriteria,
            Maybe<int>.From(256)
        );
    }

    /// <summary>
    /// Initializes a new instance of the GetStatusCommand class.
    /// </summary>
    /// <param name="subset">The status subset to query.</param>
    /// <param name="format">The response format.</param>
    /// <param name="occurrence">The occurrence selection.</param>
    /// <param name="searchCriteria">Optional search criteria (AID).</param>
    private GetStatusCommand(
        StatusSubset subset,
        ResponseFormat format,
        OccurrenceMode occurrence,
        byte[] searchCriteria
    )
    {
        Subset = subset;
        Format = format;
        Occurrence = occurrence;
        SearchCriteria = Maybe<byte[]>.From((byte[])searchCriteria.Clone());
    }

    /// <summary>
    /// Creates a GET STATUS command with the specified parameters.
    /// </summary>
    /// <param name="subset">The status subset to query.</param>
    /// <param name="format">The response format.</param>
    /// <param name="searchCriteria">Optional search criteria (AID).</param>
    /// <param name="occurrence">The occurrence selection.</param>
    /// <param name="tagList">Optional response tag list.</param>
    /// <returns>A Result containing either a new GetStatusCommand or an error.</returns>
    public static Result<GetStatusCommand, SmartCardError> Create(
        StatusSubset subset,
        ResponseFormat format = ResponseFormat.Tlv,
        Maybe<byte[]> searchCriteria = default,
        OccurrenceMode occurrence = OccurrenceMode.FirstOrAll,
        Maybe<byte[]> tagList = default
    )
    {
        if (!IsValidStatusSubset(subset))
        {
            return SmartCardError.InvalidArgument($"Invalid status subset: {subset}");
        }

        if (!IsValidResponseFormat(format))
        {
            return SmartCardError.InvalidArgument($"Invalid response format: {format}");
        }

        if (!IsValidOccurrenceMode(occurrence))
        {
            return SmartCardError.InvalidArgument($"Invalid occurrence mode: {occurrence}");
        }

        if (subset == StatusSubset.IssuerSecurityDomain && occurrence == OccurrenceMode.Next)
        {
            return SmartCardError.InvalidArgument(
                "GET STATUS next occurrence is not valid for the Issuer Security Domain."
            );
        }

        var dataResult = BuildCommandData(searchCriteria, tagList);
        return dataResult.Map(data => new GetStatusCommand(subset, format, occurrence, data));
    }

    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    /// <returns>The command name.</returns>
    public override string ToString()
    {
        return "GET STATUS";
    }

    /// <summary>
    /// Validates if the provided StatusSubset value is valid.
    /// </summary>
    private static bool IsValidStatusSubset(StatusSubset subset)
    {
        return subset switch
        {
            StatusSubset.IssuerSecurityDomain => true,
            StatusSubset.ApplicationsAndSupplementaryDomains => true,
            StatusSubset.ExecutableLoadFiles => true,
            StatusSubset.ExecutableLoadFilesAndModules => true,
            _ => false,
        };
    }

    /// <summary>
    /// Validates if the provided ResponseFormat value is valid.
    /// </summary>
    private static bool IsValidResponseFormat(ResponseFormat format)
    {
        return format switch
        {
            ResponseFormat.None => true,
            ResponseFormat.Tlv => true,
            _ => false,
        };
    }

    private static bool IsValidOccurrenceMode(OccurrenceMode occurrence) =>
        occurrence is OccurrenceMode.FirstOrAll or OccurrenceMode.Next;

    private static Result<byte[], SmartCardError> BuildCommandData(
        Maybe<byte[]> searchCriteria,
        Maybe<byte[]> tagList
    )
    {
        byte[] criteria = searchCriteria.GetValueOrDefault([]);
        byte[] aidSearch;

        if (criteria.Length == 0)
        {
            aidSearch = [0x4F, 0x00];
        }
        else if (criteria[0] == 0x4F)
        {
            if (criteria.Length < 2 || criteria[1] > 16 || criteria.Length < criteria[1] + 2)
            {
                return SmartCardError.InvalidArgument("Invalid GET STATUS AID search TLV.");
            }

            aidSearch = (byte[])criteria.Clone();
        }
        else
        {
            if (criteria.Length is < 5 or > 16)
            {
                return SmartCardError.InvalidArgument(
                    "Search criteria AID must be between 5 and 16 bytes."
                );
            }

            aidSearch = [0x4F, (byte)criteria.Length, .. criteria];
        }

        return tagList.Match(
            tags =>
            {
                if (tags.Length is < 1 or > 127)
                {
                    return SmartCardError.InvalidArgument(
                        "GET STATUS tag list must contain between 1 and 127 bytes."
                    );
                }

                // GP Card Specification v2.3.1, Table 11-35.
                return Result.Success<byte[], SmartCardError>(
                    [.. aidSearch, 0x5C, (byte)tags.Length, .. tags]
                );
            },
            () => Result.Success<byte[], SmartCardError>(aidSearch)
        );
    }

    /// <inheritdoc />
    public CommandAPDU ToApdu()
    {
        return ToCommandApdu()
            .GetValueOrDefault(
                new CommandAPDU(
                    GlobalPlatform.Cla.GP_STANDARD,
                    GlobalPlatform.Ins.GET_STATUS,
                    0x00,
                    0x00
                )
            );
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        return ApduBuilder
            .BuildApduBytes(
                GlobalPlatform.Cla.GP_STANDARD,
                GlobalPlatform.Ins.GET_STATUS,
                (byte)Subset,
                P2,
                SearchCriteria,
                Maybe<int>.From(256)
            )
            .GetValueOrDefault([]);
    }
}

/// <summary>
/// Represents an application status entry from GET STATUS response.
/// </summary>
[PublicAPI]
public class ApplicationStatusEntry
{
    /// <summary>
    /// Gets the application AID.
    /// </summary>
    public byte[] Aid { get; }

    /// <summary>Lifecycle byte returned by GET STATUS.</summary>
    public byte RawLifecycleState { get; }

    /// <summary>
    /// Gets the application privileges.
    /// </summary>
    public byte[] Privileges { get; }

    /// <summary>
    /// Gets the optional Executable Load File AID associated with this application (TLV C4).
    /// </summary>
    public Maybe<byte[]> ExecutableLoadFileAid { get; }

    /// <summary>
    /// Preserves the lifecycle byte returned by GET STATUS.
    /// GP Card Specification v2.3.1, Tables 11-3 through 11-6.
    /// </summary>
    public ApplicationStatusEntry(
        byte[] aid,
        byte rawLifecycleState,
        byte[] privileges,
        Maybe<byte[]> executableLoadFileAid = default
    )
    {
        ArgumentNullException.ThrowIfNull(aid);
        ArgumentNullException.ThrowIfNull(privileges);

        Aid = aid.Length == 0 ? Array.Empty<byte>() : (byte[])aid.Clone();
        RawLifecycleState = rawLifecycleState;
        Privileges = privileges.Length == 0 ? Array.Empty<byte>() : (byte[])privileges.Clone();
        ExecutableLoadFileAid = executableLoadFileAid.Map(value =>
            value.Length == 0 ? Array.Empty<byte>() : (byte[])value.Clone()
        );
    }
}

/// <summary>
/// Represents the response to a GET STATUS command.
/// </summary>
[PublicAPI]
public class GetStatusResponse
{
    /// <summary>
    /// Gets the list of application status entries.
    /// </summary>
    public IReadOnlyList<ApplicationStatusEntry> Applications { get; }

    /// <summary>
    /// Initializes a new instance of the GetStatusResponse class.
    /// </summary>
    /// <param name="applications">The list of applications.</param>
    public GetStatusResponse(IList<ApplicationStatusEntry> applications)
    {
        Applications = new List<ApplicationStatusEntry>(applications);
    }

    /// <summary>
    /// Parses a GET STATUS response using TlvCodec.GlobalPlatformParsers.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <returns>A Result containing either the parsed response or an error.</returns>
    public static Result<GetStatusResponse, SmartCardError> Parse(byte[] response)
    {
        return TlvCodec
            .GlobalPlatformParsers.ParseGetStatusResponse(response)
            .Map(entries => new GetStatusResponse(entries.ToList()));
    }
}
