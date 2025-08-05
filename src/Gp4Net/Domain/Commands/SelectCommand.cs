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
                SmartCardError.InvalidData("AID cannot be null")
            );
        }

        if (aid.Length > 16)
        {
            return Result.Failure<SelectCommand, SmartCardError>(
                SmartCardError.InvalidData("AID must be 16 bytes or less")
            );
        }

        var control = mode == SelectMode.First
            ? SelectionControl.SelectByName
            : SelectionControl.SelectByName; // Note: mode affects P2, not P1
        var controlInfo = mode == SelectMode.First
            ? FileControlInfo.ReturnFci
            : (FileControlInfo)((byte)FileControlInfo.ReturnFci | (byte)mode);

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
    /// Creates a SELECT command with empty AID for auto-detection.
    /// </summary>
    /// <param name="controlInfo">The file control information.</param>
    /// <returns>A new SelectCommand instance with empty AID.</returns>
    [Obsolete("Use CreateForIssuerSecurityDomain() instead")]
    public static SelectCommand CreateEmptySelect(
        FileControlInfo controlInfo = FileControlInfo.ReturnFci
    )
    {
        return new SelectCommand(
            [],
            SelectionControl.SelectByName,
            controlInfo
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
    public override string ToString() => "SELECT";
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
    public string ApplicationLabel { get; }

    /// <summary>
    /// Gets the application priority indicator.
    /// </summary>
    public byte? ApplicationPriorityIndicator { get; }

    /// <summary>
    /// Gets the maximum length of data field in command message.
    /// </summary>
    public ushort? MaxCommandDataLength { get; }

    /// <summary>
    /// Gets the maximum length of data field in response message.
    /// </summary>
    public ushort? MaxResponseDataLength { get; }

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
        byte[] applicationAid = null,
        string applicationLabel = null,
        byte? applicationPriorityIndicator = null,
        ushort? maxCommandDataLength = null,
        ushort? maxResponseDataLength = null,
        byte[] issuerIdentificationNumber = null,
        byte[] cardImageNumber = null,
        byte[] cardData = null,
        byte[] discretionaryData = null
    )
    {
        ApplicationAid = applicationAid != null ? (byte[])applicationAid.Clone() : [];
        ApplicationLabel = applicationLabel;
        ApplicationPriorityIndicator = applicationPriorityIndicator;
        MaxCommandDataLength = maxCommandDataLength;
        MaxResponseDataLength = maxResponseDataLength;
        IssuerIdentificationNumber =
            issuerIdentificationNumber != null
                ? (byte[])issuerIdentificationNumber.Clone()
                : [];
        CardImageNumber = cardImageNumber != null ? (byte[])cardImageNumber.Clone() : [];
        CardData = cardData != null ? (byte[])cardData.Clone() : [];
        DiscretionaryData =
            discretionaryData != null ? (byte[])discretionaryData.Clone() : [];
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
    public FileControlInformation Fci { get; }

    /// <summary>
    /// Gets the raw response data.
    /// </summary>
    public byte[] RawData { get; }

    /// <summary>
    /// Initializes a new instance of the SelectResponse class.
    /// </summary>
    /// <param name="rawData">The raw response data.</param>
    /// <param name="fci">The parsed FCI (optional).</param>
    public SelectResponse(byte[] rawData, FileControlInformation fci = null)
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
        if (response == null)
        {
            return Result.Failure<SelectResponse, SmartCardError>(
                SmartCardError.InvalidData("Response data cannot be null")
            );
        }

        try
        {
            // Try to parse FCI data
            var fci = ParseFciData(response);
            return Result.Success<SelectResponse, SmartCardError>(
                new SelectResponse(response, fci)
            );
        }
        catch (Exception ex)
        {
            return Result.Failure<SelectResponse, SmartCardError>(
                SmartCardError.InvalidResponse($"Failed to parse SELECT response: {ex.Message}")
            );
        }
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
    /// <returns>The parsed FCI.</returns>
    private static FileControlInformation ParseFciData(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return null;
        }

        try
        {
            var tlvObjects = TlvParser.ParseAll(data);
            var fciTemplate = tlvObjects.FirstOrDefault(t => t.TagNumber == 0x6F);

            if (fciTemplate == null)
            {
                return null;
            }

            byte[] applicationAid = [];
            string applicationLabel = null;
            byte? applicationPriorityIndicator = null;
            ushort? maxCommandDataLength = null;
            ushort? maxResponseDataLength = null;
            byte[] issuerIdentificationNumber = [];
            byte[] cardImageNumber = [];
            byte[] cardData = [];
            byte[] discretionaryData = [];

            // Parse direct children of FCI template
            var children = fciTemplate.ParseNestedTlv();
            foreach (var tlv in children)
            {
                switch (tlv.TagNumber)
                {
                    case 0x84: // DF Name (AID)
                        applicationAid = tlv.Value;
                        break;
                    case 0x50: // Application Label
                        applicationLabel = System.Text.Encoding.UTF8.GetString(tlv.Value);
                        break;
                    case 0x87: // Application Priority Indicator
                        if (tlv.Value.Length > 0)
                        {
                            applicationPriorityIndicator = tlv.Value[0];
                        }

                        break;
                    case 0x9F38: // PDOL (Processing Options Data Object List)
                        // Not currently used but could be parsed
                        break;
                    case 0xA5: // FCI Proprietary Template
                        ParseProprietaryTemplate(
                            tlv,
                            ref maxCommandDataLength,
                            ref maxResponseDataLength,
                            ref issuerIdentificationNumber,
                            ref cardImageNumber,
                            ref cardData
                        );
                        break;
                    case 0xBF0C: // FCI Issuer Discretionary Data
                        discretionaryData = tlv.Value;
                        break;
                }
            }

            return new FileControlInformation(
                applicationAid: applicationAid,
                applicationLabel: applicationLabel,
                applicationPriorityIndicator: applicationPriorityIndicator,
                maxCommandDataLength: maxCommandDataLength,
                maxResponseDataLength: maxResponseDataLength,
                issuerIdentificationNumber: issuerIdentificationNumber,
                cardImageNumber: cardImageNumber,
                cardData: cardData,
                discretionaryData: discretionaryData
            );
        }
        catch
        {
            // If parsing fails, return null
            return null;
        }
    }

    /// <summary>
    /// Parses the proprietary template within FCI.
    /// </summary>
    private static void ParseProprietaryTemplate(
        TlvObject proprietaryTemplate,
        ref ushort? maxCommandDataLength,
        ref ushort? maxResponseDataLength,
        ref byte[] issuerIdentificationNumber,
        ref byte[] cardImageNumber,
        ref byte[] cardData
    )
    {
        var children = proprietaryTemplate.ParseNestedTlv();
        foreach (var tlv in children)
        {
            switch (tlv.TagNumber)
            {
                case 0x9F65: // Maximum length of data field in command message
                    if (tlv.Value.Length == 1)
                    {
                        maxCommandDataLength = tlv.Value[0];
                    }
                    else if (tlv.Value.Length == 2)
                    {
                        maxCommandDataLength = (ushort)((tlv.Value[0] << 8) | tlv.Value[1]);
                    }

                    break;
                case 0x9F66: // Maximum length of data field in response message
                    if (tlv.Value.Length == 1)
                    {
                        maxResponseDataLength = tlv.Value[0];
                    }
                    else if (tlv.Value.Length == 2)
                    {
                        maxResponseDataLength = (ushort)((tlv.Value[0] << 8) | tlv.Value[1]);
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
    }
}