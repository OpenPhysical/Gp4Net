using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the SELECT command for selecting applications or security domains.
/// </summary>
[PublicAPI]
public class SelectCommand : BaseApduCommand
{
    /// <summary>
    /// The command class byte.
    /// </summary>
    public const byte ClassByte = 0x00;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte InstructionByte = 0xA4;

    /// <summary>
    /// Selection control values for P1.
    /// </summary>
    public enum SelectionControl : byte
    {
        /// <summary>
        /// Select by name (AID).
        /// </summary>
        SelectByName = 0x04,
    }

    /// <summary>
    /// File control information values for P2.
    /// </summary>
    public enum FileControlInfo : byte
    {
        /// <summary>
        /// Return FCI template.
        /// </summary>
        ReturnFci = 0x00,

        /// <summary>
        /// Return FCP template.
        /// </summary>
        ReturnFcp = 0x04,

        /// <summary>
        /// Return FMD template.
        /// </summary>
        ReturnFmd = 0x08,

        /// <summary>
        /// No response data.
        /// </summary>
        NoResponseData = 0x0C,
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
        if (aid == null)
        {
            return Result.Failure<SelectCommand, SmartCardError>(
                new InvalidDataError("AID", "cannot be null")
            );
        }

        if (aid.Length > 16)
        {
            return Result.Failure<SelectCommand, SmartCardError>(
                new InvalidLengthError("AID", 16, aid.Length)
            );
        }

        // GP Card Specification v2.3.1 Table 11-80: P1 is always SelectByName (0x04) for AID selection
        var control = SelectionControl.SelectByName;
        
        // GP Card Specification v2.3.1 Table 11-81: P2 parameter for SELECT command
        // 0x00 = First or only occurrence
        // 0x02 = Next occurrence
        var controlInfo = mode == SelectMode.First
            ? FileControlInfo.ReturnFci      // 0x00 = First occurrence
            : (FileControlInfo)SelectMode.Next;  // 0x02 = Next occurrence

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
        return Create([], SelectMode.First);
    }

    /// <summary>
    /// Internal factory to construct a SELECT command with explicit mode and control info.
    /// </summary>
    internal static Result<SelectCommand, SmartCardError> CreateWith(
        byte[] aid,
        SelectMode mode,
        FileControlInfo controlInfo)
    {
        if (aid == null)
        {
            return Result.Failure<SelectCommand, SmartCardError>(
                new InvalidDataError("AID", "cannot be null")
            );
        }

        if (aid.Length > 16)
        {
            return Result.Failure<SelectCommand, SmartCardError>(
                new InvalidLengthError("AID", 16, aid.Length)
            );
        }

        var control = SelectionControl.SelectByName;

        return Result.Success<SelectCommand, SmartCardError>(
            new SelectCommand((byte[])aid.Clone(), control, controlInfo)
        );
    }


    /// <inheritdoc />
    public override byte Cla
    {
        get
        {
            return ClassByte;
        }
    }

    /// <inheritdoc />
    public override byte Ins
    {
        get
        {
            return InstructionByte;
        }
    }

    /// <inheritdoc />
    public override byte P1
    {
        get
        {
            return (byte)Control;
        }
    }

    /// <inheritdoc />
    public override byte P2
    {
        get
        {
            return (byte)ControlInfo;
        }
    }

    /// <inheritdoc />
    public override byte[] Data
    {
        get
        {
            return Aid;
        }
    }

    /// <inheritdoc />
    public override Maybe<int> ExpectedResponseLength
    {
        get
        {
            return ControlInfo == FileControlInfo.NoResponseData ? Maybe<int>.None : Maybe<int>.From(256);
        }
    }


    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    /// <returns>The string "SELECT".</returns>
    public override string ToString()
    {
        return "SELECT";
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
                new InvalidDataError("Response", "cannot be null"));
        }
        
        // Try to parse FCI data
        var fciResult = ParseFciData(response);
        return fciResult.IsSuccess 
            ? Result.Success<SelectResponse, SmartCardError>(new SelectResponse(response, fciResult.Value))
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
                Maybe<FileControlInformation>.None);
        }

        var tlvObjects = TlvParser.ParseAll(data);
        
        // Find FCI template (0x6F) using functional composition
        var fciTemplate = tlvObjects
            .Select(tlv => tlv.GetTagNumber()
                .Match(
                    tag => tag == 0x6F ? Maybe<TlvObject>.From(tlv) : Maybe<TlvObject>.None,
                    error => Maybe<TlvObject>.None))
            .Where(maybeTlv => maybeTlv.HasValue)
            .SelectMany(maybeTlv => maybeTlv.Match(
                tlv => new[] { tlv },
                () => Array.Empty<TlvObject>()))
            .Take(1)
            .ToArray();
        
        if (fciTemplate.Length > 0)
        {
            return ParseFciTemplate(fciTemplate[0])
                .Map(fci => Maybe<FileControlInformation>.From(fci));
        }

        return Result.Success<Maybe<FileControlInformation>, SmartCardError>(
            Maybe<FileControlInformation>.None);
    }
    
    private static Result<FileControlInformation, SmartCardError> ParseFciTemplate(TlvObject fciTemplate)
    {
        byte[] applicationAid = [];
        var applicationLabel = Maybe<string>.None;
        var applicationPriorityIndicator = Maybe<byte>.None;
        var maxCommandDataLength = Maybe<ushort>.None;
        var maxResponseDataLength = Maybe<ushort>.None;
        byte[] issuerIdentificationNumber = [];
        byte[] cardImageNumber = [];
        byte[] cardData = [];
        byte[] discretionaryData = [];

        // Parse direct children of FCI template
        var children = fciTemplate.ParseNestedTlv();
        foreach (var tlv in children)
        {
            var tagResult = tlv.GetTagNumber();
            if (tagResult.IsFailure) 
                return Result.Failure<FileControlInformation, SmartCardError>(
                    SmartCardError.InvalidData("Failed to parse nested TLV tag"));
            
            switch (tagResult.Value)
                {
                    case 0x84: // DF Name (AID)
                        applicationAid = tlv.Value;
                        break;
                    case 0x50: // Application Label
                        // Per ISO 7816-4 and GP specifications, application labels must be ASCII
                        var labelResult = EncodingUtils.SafeAsciiDecode(tlv.Value);
                        if (labelResult.IsFailure)
                        {
                            return Result.Failure<FileControlInformation, SmartCardError>(
                                SmartCardError.InvalidData("Invalid ASCII encoding in application label"));
                        }
                        applicationLabel = labelResult.IsSuccess ? Maybe<string>.From(labelResult.Value) : Maybe<string>.None;
                        break;
                    case 0x87: // Application Priority Indicator
                        if (tlv.Value.Length > 0)
                        {
                            applicationPriorityIndicator = Maybe<byte>.From(tlv.Value[0]);
                        }

                        break;
                    case 0x9F38: // PDOL (Processing Options Data Object List)
                        // Not currently used but could be parsed
                        break;
                    case 0xA5: // FCI Proprietary Template
                        var proprietaryResult = ParseProprietaryTemplate(tlv);
                        if (proprietaryResult.IsFailure) 
                            return Result.Failure<FileControlInformation, SmartCardError>(proprietaryResult.Error);
                        
                        maxCommandDataLength = proprietaryResult.Value.MaxCommandDataLength;
                        maxResponseDataLength = proprietaryResult.Value.MaxResponseDataLength;
                        issuerIdentificationNumber = proprietaryResult.Value.IssuerIdentificationNumber;
                        cardImageNumber = proprietaryResult.Value.CardImageNumber;
                        cardData = proprietaryResult.Value.CardData;
                        break;
                    case 0xBF0C: // FCI Issuer Discretionary Data
                        discretionaryData = tlv.Value;
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
                ));
    }

    /// <summary>
    /// Result of parsing FCI proprietary template data.
    /// </summary>
    private record ProprietaryTemplateData(
        Maybe<ushort> MaxCommandDataLength,
        Maybe<ushort> MaxResponseDataLength,
        byte[] IssuerIdentificationNumber,
        byte[] CardImageNumber,
        byte[] CardData);

    /// <summary>
    /// Parses the proprietary template within FCI.
    /// </summary>
    private static Result<ProprietaryTemplateData, SmartCardError> ParseProprietaryTemplate(
        TlvObject proprietaryTemplate)
    {
        var maxCommandDataLength = Maybe<ushort>.None;
        var maxResponseDataLength = Maybe<ushort>.None;
        byte[] issuerIdentificationNumber = [];
        byte[] cardImageNumber = [];
        byte[] cardData = [];

        var children = proprietaryTemplate.ParseNestedTlv();
        foreach (var tlv in children)
        {
            var tagNumber = tlv.GetTagNumber();
            if (tagNumber.IsFailure)
                return Result.Failure<ProprietaryTemplateData, SmartCardError>(
                    SmartCardError.InvalidData("Failed to parse proprietary template tag"));
            
            switch (tagNumber.Value)
            {
                case 0x9F65: // Maximum length of data field in command message
                    switch (tlv.Value.Length)
                    {
                        case 1:
                            maxCommandDataLength = Maybe<ushort>.From(tlv.Value[0]);
                            break;
                        case 2:
                            maxCommandDataLength = Maybe<ushort>.From((ushort)((tlv.Value[0] << 8) | tlv.Value[1]));
                            break;
                    }
                    break;
                case 0x9F66: // Maximum length of data field in response message
                    switch (tlv.Value.Length)
                    {
                        case 1:
                            maxResponseDataLength = Maybe<ushort>.From(tlv.Value[0]);
                            break;
                        case 2:
                            maxResponseDataLength = Maybe<ushort>.From((ushort)((tlv.Value[0] << 8) | tlv.Value[1]));
                            break;
                    }
                    break;
                case 0x42: // Issuer Identification Number
                    issuerIdentificationNumber = tlv.Value;
                    break;
                case 0x45: // Card Image Number
                    cardImageNumber = tlv.Value;
                    break;
                case 0x66: // Card Data
                    cardData = tlv.Value;
                    break;
            }
        }

        return Result.Success<ProprietaryTemplateData, SmartCardError>(
            new ProprietaryTemplateData(
                maxCommandDataLength,
                maxResponseDataLength,
                issuerIdentificationNumber,
                cardImageNumber,
                cardData));
    }
}
