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
        /// No format specified.
        /// </summary>
        None = 0x00,

        /// <summary>
        /// Return data in TLV format.
        /// </summary>
        Tlv = 0x02,
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
    /// Gets the search criteria (optional AID).
    /// </summary>
    public byte[] SearchCriteria { get; }

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
    public byte P2 => (byte)Format;

    /// <summary>
    /// Gets the command data (search criteria).
    /// </summary>
    public byte[] Data => SearchCriteria;

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
            (byte)Format,
            Maybe<byte[]>.From(SearchCriteria),
            Maybe<int>.From(256)
        );
    }

    /// <summary>
    /// Initializes a new instance of the GetStatusCommand class.
    /// </summary>
    /// <param name="subset">The status subset to query.</param>
    /// <param name="format">The response format.</param>
    /// <param name="searchCriteria">Optional search criteria (AID).</param>
    private GetStatusCommand(
        StatusSubset subset,
        ResponseFormat format = ResponseFormat.None,
        byte[] searchCriteria = null
    )
    {
        Subset = subset;
        Format = format;
        SearchCriteria = searchCriteria != null ? (byte[])searchCriteria.Clone() : [];
    }

    /// <summary>
    /// Creates a GET STATUS command with the specified parameters.
    /// </summary>
    /// <param name="subset">The status subset to query.</param>
    /// <param name="format">The response format.</param>
    /// <param name="searchCriteria">Optional search criteria (AID).</param>
    /// <returns>A Result containing either a new GetStatusCommand or an error.</returns>
    public static Result<GetStatusCommand, SmartCardError> Create(
        StatusSubset subset,
        ResponseFormat format = ResponseFormat.None,
        byte[] searchCriteria = null
    )
    {
        // Validate StatusSubset enum
        if (!IsValidStatusSubset(subset))
        {
            return SmartCardError.InvalidArgument($"Invalid status subset: {subset}");
        }

        // Validate ResponseFormat enum
        if (!IsValidResponseFormat(format))
        {
            return SmartCardError.InvalidArgument($"Invalid response format: {format}");
        }

        // Validate search criteria if provided
        // Note: Search criteria can be a TLV structure (e.g., 4F00 for empty search)
        // or an AID (5-16 bytes). We allow both.
        if (searchCriteria is { Length: > 0 })
        {
            // If it looks like a raw AID (not TLV), validate length
            if (searchCriteria[0] != 0x4F && searchCriteria.Length is < 5 or > 16)
            {
                return SmartCardError.InvalidArgument(
                    "Search criteria AID must be between 5 and 16 bytes."
                );
            }
        }

        return new GetStatusCommand(subset, format, searchCriteria);
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

    /// <summary>
    /// Validates search criteria for AID format and length.
    /// </summary>
    /// <param name="searchCriteria">The search criteria to validate.</param>
    /// <returns>Maybe containing SmartCardError if validation fails, or None if valid.</returns>
    private static Maybe<SmartCardError> ValidateSearchCriteria(byte[] searchCriteria)
    {
        // If it looks like a raw AID (not TLV), validate length
        if (searchCriteria[0] != 0x4F && searchCriteria.Length is < 5 or > 16)
        {
            return Maybe<SmartCardError>.From(
                SmartCardError.InvalidArgument(
                    "Search criteria AID must be between 5 and 16 bytes."
                )
            );
        }
        return Maybe<SmartCardError>.None;
    }

    /// <inheritdoc />
    public CommandAPDU ToApdu()
    {
        return ToCommandApdu().GetValueOrDefault(new CommandAPDU([]));
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        return ToCommandApdu().Map(cmd => cmd.ToBytes()).GetValueOrDefault([]);
    }
}

/// <summary>
/// Represents an application status entry from GET STATUS response.
/// </summary>
[PublicAPI]
public class ApplicationStatusEntry
{
    /// <summary>
    /// Application lifecycle states.
    /// </summary>
    public enum LifecycleState : byte
    {
        /// <summary>
        /// Application is loaded (for load files and apps reporting 0x01).
        /// </summary>
        Loaded = 0x01,

        /// <summary>
        /// Application is installed.
        /// </summary>
        Installed = 0x03,

        /// <summary>
        /// Application is selectable.
        /// </summary>
        Selectable = 0x07,

        /// <summary>
        /// Application is personalized.
        /// </summary>
        Personalized = 0x0F,

        /// <summary>
        /// Application is blocked.
        /// </summary>
        Blocked = 0x83,

        /// <summary>
        /// Application is locked.
        /// </summary>
        Locked = 0x87,
    }

    /// <summary>
    /// Gets the application AID.
    /// </summary>
    public byte[] Aid { get; }

    /// <summary>
    /// Gets the application lifecycle state.
    /// </summary>
    public LifecycleState State { get; }

    /// <summary>
    /// Gets the application privileges.
    /// </summary>
    public byte[] Privileges { get; }

    /// <summary>
    /// Gets the Executable Load File AID associated with this application (TLV C4), if provided.
    /// </summary>
    public byte[] ExecutableLoadFileAid { get; }

    /// <summary>
    /// Initializes a new instance of the ApplicationStatusEntry class.
    /// </summary>
    /// <param name="aid">The application AID.</param>
    /// <param name="state">The lifecycle state.</param>
    /// <param name="privileges">The application privileges.</param>
    /// <param name="executableLoadFileAid">The executable load file AID (optional).</param>
    public ApplicationStatusEntry(
        byte[] aid,
        LifecycleState state,
        byte[] privileges,
        byte[] executableLoadFileAid = null
    )
    {
        Aid = (byte[])aid.Clone();
        State = state;
        Privileges = (byte[])privileges.Clone();
        ExecutableLoadFileAid =
            executableLoadFileAid != null ? (byte[])executableLoadFileAid.Clone() : [];
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
    /// Parses a GET STATUS response using TlvService.GlobalPlatformParsers.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <returns>A Result containing either the parsed response or an error.</returns>
    public static Result<GetStatusResponse, SmartCardError> Parse(byte[] response)
    {
        return TlvService
            .GlobalPlatformParsers.ParseGetStatusResponse(response)
            .Map(entries => new GetStatusResponse(entries.ToList()));
    }
}
