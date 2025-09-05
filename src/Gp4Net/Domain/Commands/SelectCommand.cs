using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Services;
using static Gp4Net.Services.TlvService;
using Gp4Net.Transport;
using WSCT.Core;
using WSCT.ISO7816;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the SELECT command for selecting applications or security domains.
/// </summary>
[PublicAPI]
public class SelectCommand : IApduCommand
{
    /// <summary>
    /// The command class byte.
    /// </summary>
    public const byte ClassByte = Apdu.Classes.Standard;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte InstructionByte = Apdu.Instructions.Select;

    /// <summary>
    /// Selection control values for P1.
    /// </summary>
    public enum SelectionControl : byte
    {
        /// <summary>
        /// Select by name (AID).
        /// </summary>
        SelectByName = Apdu.SelectP1.SelectByName,
    }

    /// <summary>
    /// File control information values for P2.
    /// </summary>
    public enum FileControlInfo : byte
    {
        /// <summary>
        /// Return FCI template.
        /// </summary>
        ReturnFci = Apdu.SelectP2.ReturnFci,

        /// <summary>
        /// Return FCP template.
        /// </summary>
        ReturnFcp = Apdu.SelectP2.ReturnFcp,

        /// <summary>
        /// Return FMD template.
        /// </summary>
        ReturnFmd = Apdu.SelectP2.ReturnFmd,

        /// <summary>
        /// No response data.
        /// </summary>
        NoResponseData = Apdu.SelectP2.NoResponseData,
    }

    /// <summary>
    /// Gets the selection control.
    /// </summary>
    public SelectionControl Control { get; }

    /// <summary>
    /// Gets the file control information.
    /// </summary>
    public FileControlInfo ControlInfo { get; }

    /// <summary>
    /// Gets the application identifier (AID).
    /// </summary>
    public byte[] Aid { get; }

    /// <summary>
    /// Initializes a new instance of the SelectCommand class.
    /// </summary>
    /// <param name="aid">The application identifier to select (0-16 bytes, empty for auto-detection).</param>
    /// <param name="control">The selection control method.</param>
    /// <param name="controlInfo">The file control information.</param>
    private SelectCommand(
        byte[] aid,
        SelectionControl control = SelectionControl.SelectByName,
        FileControlInfo controlInfo = FileControlInfo.ReturnFci
    )
    {
        Aid = (byte[])aid.Clone();
        Control = control;
        ControlInfo = controlInfo;
    }

    /// <summary>
    /// Select mode for the SELECT command.
    /// </summary>
    public enum SelectMode : byte
    {
        /// <summary>
        /// Select the first or only occurrence.
        /// </summary>
        First = 0x00,

        /// <summary>
        /// Select the next occurrence.
        /// </summary>
        Next = 0x02,
    }

    /// <summary>
    /// Creates a SELECT command with the specified AID.
    /// </summary>
    /// <param name="aid">The application identifier to select (0-16 bytes).</param>
    /// <param name="mode">The select mode.</param>
    /// <returns>A Result containing the SelectCommand or an error.</returns>
    public static Result<SelectCommand, SmartCardError> Create(
        byte[] aid,
        SelectMode mode = SelectMode.First
    )
    {
        return Maybe<byte[]>
            .From(aid)
            .Match(
                Some: aidValue => ValidateAndCreateSelect(aidValue, mode),
                None: () => new InvalidDataError("AID", "cannot be null")
            );
    }

    private static Result<SelectCommand, SmartCardError> ValidateAndCreateSelect(
        byte[] aid,
        SelectMode mode
    )
    {
        if (aid.Length > 16)
        {
            return new InvalidLengthError("AID", 16, aid.Length);
        }

        // GP Card Specification v2.3.1 Table 11-80: P1 is always SelectByName (0x04) for AID selection
        SelectionControl control = SelectionControl.SelectByName;

        // GP Card Specification v2.3.1 Table 11-81: P2 parameter for SELECT command
        // 0x00 = First or only occurrence
        // 0x02 = Next occurrence
        FileControlInfo controlInfo =
            mode == SelectMode.First
                ? FileControlInfo.ReturnFci // 0x00 = First occurrence
                : (FileControlInfo)SelectMode.Next; // 0x02 = Next occurrence

        return Result.Success<SelectCommand, SmartCardError>(
            new SelectCommand(aid, control, controlInfo)
        );
    }

    /// <summary>
    /// Creates a SELECT command for the Issuer Security Domain.
    /// </summary>
    /// <returns>A Result containing the SelectCommand or an error.</returns>
    public static Result<SelectCommand, SmartCardError> CreateForIssuerSecurityDomain()
    {
        return Create([]);
    }

    /// <summary>
    /// Internal factory to construct a SELECT command with explicit mode and control info.
    /// </summary>
    internal static Result<SelectCommand, SmartCardError> CreateWith(
        byte[] aid,
        SelectMode mode,
        FileControlInfo controlInfo
    )
    {
        return Maybe<byte[]>
            .From(aid)
            .Match(
                Some: aidValue => ValidateAndCreateSelectWith(aidValue, mode, controlInfo),
                None: () => new InvalidDataError("AID", "cannot be null")
            );
    }

    private static Result<SelectCommand, SmartCardError> ValidateAndCreateSelectWith(
        byte[] aid,
        SelectMode mode,
        FileControlInfo controlInfo
    )
    {
        if (aid.Length > 16)
        {
            return new InvalidLengthError("AID", 16, aid.Length);
        }

        SelectionControl control = SelectionControl.SelectByName;

        return Result.Success<SelectCommand, SmartCardError>(
            new SelectCommand((byte[])aid.Clone(), control, controlInfo)
        );
    }

    /// <summary>
    /// Converts this command to a CommandAPDU.
    /// </summary>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        return ControlInfo == FileControlInfo.NoResponseData
            ? Result.Success<CommandAPDU, SmartCardError>(
                new CommandAPDU(ClassByte, InstructionByte, (byte)Control, (byte)ControlInfo, (uint)Aid.Length, Aid))
            : Result.Success<CommandAPDU, SmartCardError>(
                new CommandAPDU(ClassByte, InstructionByte, (byte)Control, (byte)ControlInfo, (uint)Aid.Length, Aid, 256));
    }

    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    /// <returns>The string "SELECT".</returns>
    public override string ToString()
    {
        return "SELECT";
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
/// Represents the File Control Information (FCI) from a SELECT response.
/// </summary>
[PublicAPI]
public class FileControlInformation
{
    /// <summary>
    /// Gets the application AID.
    /// </summary>
    public byte[] ApplicationAid { get; }

    /// <summary>
    /// Gets the application label.
    /// </summary>
    public Maybe<string> ApplicationLabel { get; }

    /// <summary>
    /// Gets the application priority indicator.
    /// </summary>
    public Maybe<byte> ApplicationPriorityIndicator { get; }

    /// <summary>
    /// Gets the maximum length of data field in command message.
    /// </summary>
    public Maybe<ushort> MaxCommandDataLength { get; }

    /// <summary>
    /// Gets the maximum length of data field in response message.
    /// </summary>
    public Maybe<ushort> MaxResponseDataLength { get; }

    /// <summary>
    /// Gets the issuer identification number.
    /// </summary>
    public byte[] IssuerIdentificationNumber { get; }

    /// <summary>
    /// Gets the card image number.
    /// </summary>
    public byte[] CardImageNumber { get; }

    /// <summary>
    /// Gets the card data.
    /// </summary>
    public byte[] CardData { get; }

    /// <summary>
    /// Gets the discretionary data.
    /// </summary>
    public byte[] DiscretionaryData { get; }

    /// <summary>
    /// Initializes a new instance of the FileControlInformation class.
    /// </summary>
    /// <param name="applicationAid">The application AID.</param>
    /// <param name="applicationLabel">The application label.</param>
    /// <param name="applicationPriorityIndicator">The application priority indicator.</param>
    /// <param name="maxCommandDataLength">The maximum command data length.</param>
    /// <param name="maxResponseDataLength">The maximum response data length.</param>
    /// <param name="issuerIdentificationNumber">The issuer identification number.</param>
    /// <param name="cardImageNumber">The card image number.</param>
    /// <param name="cardData">The card data.</param>
    /// <param name="discretionaryData">The discretionary data.</param>
    public FileControlInformation(
        byte[] applicationAid,
        Maybe<string> applicationLabel,
        Maybe<byte> applicationPriorityIndicator,
        Maybe<ushort> maxCommandDataLength,
        Maybe<ushort> maxResponseDataLength,
        byte[] issuerIdentificationNumber,
        byte[] cardImageNumber,
        byte[] cardData,
        byte[] discretionaryData
    )
    {
        ApplicationAid = (byte[])applicationAid.Clone();
        ApplicationLabel = applicationLabel;
        ApplicationPriorityIndicator = applicationPriorityIndicator;
        MaxCommandDataLength = maxCommandDataLength;
        MaxResponseDataLength = maxResponseDataLength;
        IssuerIdentificationNumber = (byte[])issuerIdentificationNumber.Clone();
        CardImageNumber = (byte[])cardImageNumber.Clone();
        CardData = (byte[])cardData.Clone();
        DiscretionaryData = (byte[])discretionaryData.Clone();
    }
}

/// <summary>
/// Represents the response to a SELECT command.
/// </summary>
[PublicAPI]
public class SelectResponse
{
    /// <summary>
    /// Gets the File Control Information.
    /// </summary>
    public Maybe<FileControlInformation> Fci { get; }

    /// <summary>
    /// Gets the raw response data.
    /// </summary>
    public byte[] RawData { get; }

    /// <summary>
    /// Initializes a new instance of the SelectResponse class.
    /// </summary>
    /// <param name="rawData">The raw response data.</param>
    /// <param name="fci">The parsed FCI (optional).</param>
    public SelectResponse(byte[] rawData, Maybe<FileControlInformation> fci = default)
    {
        RawData = (byte[])rawData.Clone();
        Fci = fci;
    }

    /// <summary>
    /// Parses a SELECT response.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <returns>A Result containing the parsed response or an error.</returns>
    public static Result<SelectResponse, SmartCardError> Parse(byte[] response)
    {
        if (response is null)
        {
            return Result.Failure<SelectResponse, SmartCardError>(
                new InvalidDataError("Response", "cannot be null")
            );
        }

        // Try to parse FCI data
        Result<Maybe<FileControlInformation>, SmartCardError> fciResult = ParseFciData(response);
        return fciResult.IsSuccess
            ? Result.Success<SelectResponse, SmartCardError>(
                new SelectResponse(response, fciResult.Value)
            )
            : Result.Failure<SelectResponse, SmartCardError>(fciResult.Error);
    }

    /// <summary>
    /// Parses a SELECT response with detailed FCI parsing.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <returns>A Result containing the parsed response with FCI details or an error.</returns>
    public static Result<SelectResponse, SmartCardError> ParseWithFci(byte[] response)
    {
        return Parse(response);
    }

    /// <summary>
    /// Parses FCI data from response.
    /// </summary>
    /// <param name="data">The FCI data.</param>
    /// <returns>The parsed FCI or None if unparseable.</returns>
    private static Result<Maybe<FileControlInformation>, SmartCardError> ParseFciData(byte[] data)
    {
        if (data.Length == 0)
        {
            return Result.Success<Maybe<FileControlInformation>, SmartCardError>(
                Maybe<FileControlInformation>.None
            );
        }

        var parseResult = TlvService.TlvParser.ParseMultiple(data.ToImmutableArray());
        if (parseResult.IsFailure)
        {
            return Result.Success<Maybe<FileControlInformation>, SmartCardError>(
                Maybe<FileControlInformation>.None
            );
        }
        var tlvObjects = parseResult.Value.Objects;

        // Find FCI template (0x6F) using functional composition
        TlvObject[] fciTemplate = [.. tlvObjects
            .Select(tlv =>
                tlv.Tag.ToNumber()
                    .Match(
                        tag => tag == 0x6F ? Maybe<TlvObject>.From(tlv) : Maybe<TlvObject>.None,
                        error => Maybe<TlvObject>.None
                    )
            )
            .Where(maybeTlv => maybeTlv.HasValue)
            .SelectMany(maybeTlv => maybeTlv.Match(tlv => [tlv], () => Array.Empty<TlvObject>()))
            .Take(1)];

        if (fciTemplate.Length > 0)
        {
            return ParseFciTemplate(fciTemplate[0])
                .Map(fci => Maybe<FileControlInformation>.From(fci));
        }

        return Result.Success<Maybe<FileControlInformation>, SmartCardError>(
            Maybe<FileControlInformation>.None
        );
    }

    private static Result<FileControlInformation, SmartCardError> ParseFciTemplate(
        TlvObject fciTemplate
    )
    {
        byte[] applicationAid = [];
        Maybe<string> applicationLabel = Maybe<string>.None;
        Maybe<byte> applicationPriorityIndicator = Maybe<byte>.None;
        Maybe<ushort> maxCommandDataLength = Maybe<ushort>.None;
        Maybe<ushort> maxResponseDataLength = Maybe<ushort>.None;
        byte[] issuerIdentificationNumber = [];
        byte[] cardImageNumber = [];
        byte[] cardData = [];
        byte[] discretionaryData = [];

        // Parse direct children of FCI template
        var childrenResult = TlvService.TlvParser.ParseMultiple(fciTemplate.TlvData.Bytes);
        if (childrenResult.IsFailure)
        {
            return Result.Failure<FileControlInformation, SmartCardError>(
                SmartCardError.InvalidData("Failed to parse FCI template children")
            );
        }
        var children = childrenResult.Value.Objects;
        foreach (TlvObject tlv in children)
        {
            var tagResult = tlv.Tag.ToNumber();
            if (tagResult.IsFailure)
                return Result.Failure<FileControlInformation, SmartCardError>(
                    SmartCardError.InvalidData("Failed to parse nested TLV tag")
                );

            switch (tagResult.Value)
            {
                case 0x84: // DF Name (AID)
                    applicationAid = tlv.TlvData.Bytes.ToArray();
                    break;
                case 0x50: // Application Label
                    // Per ISO 7816-4 and GP specifications, application labels must be ASCII
                    try
                    {
                        string labelText = Encoding.ASCII.GetString(tlv.TlvData.Bytes.ToArray());
                        applicationLabel = Maybe<string>.From(labelText);
                    }
                    catch
                    {
                        return Result.Failure<FileControlInformation, SmartCardError>(
                            SmartCardError.InvalidData(
                                "Invalid ASCII encoding in application label"
                            )
                        );
                    }
                    break;
                case 0x87: // Application Priority Indicator
                    if (tlv.TlvData.Bytes.Length > 0)
                    {
                        applicationPriorityIndicator = Maybe<byte>.From(tlv.TlvData.Bytes[0]);
                    }

                    break;
                case 0x9F38: // PDOL (Processing Options Data Object List)
                    // Not currently used but could be parsed
                    break;
                case 0xA5: // FCI Proprietary Template
                    Result<ProprietaryTemplateData, SmartCardError> proprietaryResult =
                        ParseProprietaryTemplate(tlv);
                    if (proprietaryResult.IsFailure)
                        return Result.Failure<FileControlInformation, SmartCardError>(
                            proprietaryResult.Error
                        );

                    maxCommandDataLength = proprietaryResult.Value.MaxCommandDataLength;
                    maxResponseDataLength = proprietaryResult.Value.MaxResponseDataLength;
                    issuerIdentificationNumber = proprietaryResult.Value.IssuerIdentificationNumber;
                    cardImageNumber = proprietaryResult.Value.CardImageNumber;
                    cardData = proprietaryResult.Value.CardData;
                    break;
                case 0xBF0C: // FCI Issuer Discretionary Data
                    discretionaryData = tlv.TlvData.Bytes.ToArray();
                    break;
            }
        }

        return Result.Success<FileControlInformation, SmartCardError>(
            new FileControlInformation(
                applicationAid: applicationAid,
                applicationLabel: applicationLabel,
                applicationPriorityIndicator: applicationPriorityIndicator,
                maxCommandDataLength: maxCommandDataLength,
                maxResponseDataLength: maxResponseDataLength,
                issuerIdentificationNumber: issuerIdentificationNumber,
                cardImageNumber: cardImageNumber,
                cardData: cardData,
                discretionaryData: discretionaryData
            )
        );
    }

    /// <summary>
    /// Result of parsing FCI proprietary template data.
    /// </summary>
    private record ProprietaryTemplateData(
        Maybe<ushort> MaxCommandDataLength,
        Maybe<ushort> MaxResponseDataLength,
        byte[] IssuerIdentificationNumber,
        byte[] CardImageNumber,
        byte[] CardData
    );

    /// <summary>
    /// Parses the proprietary template within FCI.
    /// </summary>
    private static Result<ProprietaryTemplateData, SmartCardError> ParseProprietaryTemplate(
        TlvObject proprietaryTemplate
    )
    {
        Maybe<ushort> maxCommandDataLength = Maybe<ushort>.None;
        Maybe<ushort> maxResponseDataLength = Maybe<ushort>.None;
        byte[] issuerIdentificationNumber = [];
        byte[] cardImageNumber = [];
        byte[] cardData = [];

        var childrenResult = TlvService.TlvParser.ParseMultiple(proprietaryTemplate.TlvData.Bytes);
        if (childrenResult.IsFailure)
        {
            return Result.Failure<ProprietaryTemplateData, SmartCardError>(
                SmartCardError.InvalidData("Failed to parse proprietary template children")
            );
        }
        var children = childrenResult.Value.Objects;
        foreach (TlvObject tlv in children)
        {
            var tagNumber = tlv.Tag.ToNumber();
            if (tagNumber.IsFailure)
                return Result.Failure<ProprietaryTemplateData, SmartCardError>(
                    SmartCardError.InvalidData("Failed to parse proprietary template tag")
                );

            switch (tagNumber.Value)
            {
                case 0x9F65: // Maximum length of data field in command message
                    switch (tlv.TlvData.Bytes.Length)
                    {
                        case 1:
                            maxCommandDataLength = Maybe<ushort>.From(tlv.TlvData.Bytes[0]);
                            break;
                        case 2:
                            maxCommandDataLength = Maybe<ushort>.From(
                                (ushort)(tlv.TlvData.Bytes[0] << 8 | tlv.TlvData.Bytes[1])
                            );
                            break;
                    }
                    break;
                case 0x9F66: // Maximum length of data field in response message
                    switch (tlv.TlvData.Bytes.Length)
                    {
                        case 1:
                            maxResponseDataLength = Maybe<ushort>.From(tlv.TlvData.Bytes[0]);
                            break;
                        case 2:
                            maxResponseDataLength = Maybe<ushort>.From(
                                (ushort)(tlv.TlvData.Bytes[0] << 8 | tlv.TlvData.Bytes[1])
                            );
                            break;
                    }
                    break;
                case 0x42: // Issuer Identification Number
                    issuerIdentificationNumber = tlv.TlvData.Bytes.ToArray();
                    break;
                case 0x45: // Card Image Number
                    cardImageNumber = tlv.TlvData.Bytes.ToArray();
                    break;
                case 0x66: // Card Data
                    cardData = tlv.TlvData.Bytes.ToArray();
                    break;
            }
        }

        return Result.Success<ProprietaryTemplateData, SmartCardError>(
            new ProprietaryTemplateData(
                maxCommandDataLength,
                maxResponseDataLength,
                issuerIdentificationNumber,
                cardImageNumber,
                cardData
            )
        );
    }
}
