using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Transport;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;
using static Gp4Net.Services.TlvCodec;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the GET DATA command for retrieving data objects from the card.
/// </summary>
[PublicAPI]
public class GetDataCommand : IApduCommand
{
    /// <summary>
    /// Common data object identifiers.
    /// </summary>
    public static class DataObjects
    {
        /// <summary>
        /// Issuer Identification Number (tag 0x0042).
        /// </summary>
        public static readonly ushort IssuerIdentificationNumber = 0x0042;

        /// <summary>
        /// Card Image Number (tag 0x0045).
        /// </summary>
        public static readonly ushort CardImageNumber = 0x0045;

        /// <summary>
        /// Card Data (tag 0x0066).
        /// </summary>
        public static readonly ushort CardData = 0x0066;

        /// <summary>
        /// Key Information Template (tag 0x00E0).
        /// </summary>
        public static readonly ushort KeyInformationTemplate = 0x00E0;

        /// <summary>
        /// Card Capabilities (tag 0x0067).
        /// </summary>
        public static readonly ushort CardCapabilities = 0x0067;

        /// <summary>
        /// Security Domain Manager AID (tag 0x004F).
        /// </summary>
        public static readonly ushort SecurityDomainManagerAid = 0x004F;

        /// <summary>
        /// Card Production Life Cycle (tag 0x9F7F).
        /// </summary>
        public static readonly ushort CardProductionLifeCycle = 0x9F7F;

        /// <summary>
        /// Sequence Counter of the default Key Version Number (tag 0x00C1).
        /// Also known as Security Domain Management Data.
        /// </summary>
        public static readonly ushort SequenceCounterDefaultKeyVersion = 0x00C1;

        /// <summary>
        /// Security Domain Management Data (tag 0x00C1).
        /// Same as SequenceCounterDefaultKeyVersion.
        /// </summary>
        public static readonly ushort SecurityDomainManagementData = 0x00C1;

        /// <summary>
        /// Confirmation Counter (tag 0x00C2).
        /// </summary>
        public static readonly ushort ConfirmationCounter = 0x00C2;

        /// <summary>
        /// Free EEPROM Memory Space (tag 0x00C6).
        /// </summary>
        public static readonly ushort FreeEepromMemorySpace = 0x00C6;

        /// <summary>
        /// Free COR RAM (tag 0x00C7).
        /// </summary>
        public static readonly ushort FreeCorRam = 0x00C7;

        /// <summary>
        /// Diversification Data (tag 0x00CF).
        /// </summary>
        public static readonly ushort DiversificationData = 0x00CF;

        /// <summary>
        /// Key Derivation Data (tag 0x00D0).
        /// </summary>
        public static readonly ushort KeyDerivationData = 0x00D0;

        /// <summary>
        /// Security Domain Manager URL (tag 0x5F50).
        /// </summary>
        public static readonly ushort SecurityDomainManagerUrl = 0x5F50;

        /// <summary>
        /// Application Production Life Cycle Data (tag 0x9F70).
        /// </summary>
        public static readonly ushort ApplicationProductionLifeCycleData = 0x9F70;

        /// <summary>
        /// Maximum number of APDU bytes (tag 0x9F65).
        /// </summary>
        public static readonly ushort MaximumApduBytes = 0x9F65;

        /// <summary>
        /// Extended Card Resources Information (tag 0xFF21).
        /// </summary>
        public static readonly ushort ExtendedCardResourcesInformation = 0xFF21;

        /// <summary>List of Applications (tag 0x2F00).</summary>
        public static readonly ushort ApplicationList = 0x2F00;
    }

    private readonly byte[] _data;

    /// <summary>
    /// Gets the data object identifier.
    /// </summary>
    public ushort DataObjectIdentifier { get; }

    /// <summary>
    /// Gets the P1 parameter (high byte of data object identifier).
    /// </summary>
    public byte P1
    {
        get { return (byte)(DataObjectIdentifier >> 8); }
    }

    /// <summary>
    /// Gets the P2 parameter (low byte of data object identifier).
    /// </summary>
    public byte P2
    {
        get { return (byte)(DataObjectIdentifier & 0xFF); }
    }

    /// <summary>
    /// Initializes a new instance of the GetDataCommand class.
    /// </summary>
    /// <param name="dataObjectIdentifier">The data object identifier (2 bytes).</param>
    /// <param name="data">The command data.</param>
    private GetDataCommand(ushort dataObjectIdentifier, byte[] data)
    {
        DataObjectIdentifier = dataObjectIdentifier;
        _data = (byte[])data.Clone();
    }

    /// <summary>
    /// Creates a GET DATA command for a 2-byte data object identifier.
    /// </summary>
    /// <param name="dataObject">The data object identifier (2 bytes).</param>
    /// <returns>A Result containing the command or an error.</returns>
    public static Result<GetDataCommand, SmartCardError> Create(ushort dataObject)
    {
        return Result.Success<GetDataCommand, SmartCardError>(new GetDataCommand(dataObject, []));
    }

    /// <summary>
    /// Creates GET DATA for the List of Applications.
    /// GP Card Specification v2.3.1, §11.3.2.2.
    /// </summary>
    public static Result<GetDataCommand, SmartCardError> CreateApplicationList() =>
        Result.Success<GetDataCommand, SmartCardError>(
            new GetDataCommand(DataObjects.ApplicationList, [0x5C, 0x00])
        );

    /// <summary>
    /// Gets the class byte.
    /// </summary>
    public byte Cla => GlobalPlatform.Cla.GP_STANDARD;

    /// <summary>
    /// Gets the instruction byte.
    /// </summary>
    public byte Ins => Apdu.Instructions.GET_DATA;

    /// <summary>
    /// Gets the command data.
    /// </summary>
    public byte[] Data => (byte[])_data.Clone();

    /// <summary>
    /// Gets the expected response length.
    /// </summary>
    public Maybe<int> ExpectedResponseLength => Maybe<int>.From(0); // 0 means 256 in short APDU format

    /// <summary>
    /// Gets whether this command uses extended length.
    /// </summary>
    public bool IsExtendedLength => false;

    /// <summary>
    /// Creates a WSCT CommandAPDU from this GET DATA command.
    /// </summary>
    /// <returns>A Result containing the CommandAPDU.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        return Result.Success<CommandAPDU, SmartCardError>(new CommandAPDU(ToBytes()));
    }

    /// <inheritdoc/>
    public CommandAPDU ToApdu()
    {
        return new CommandAPDU(ToBytes());
    }

    /// <inheritdoc/>
    public byte[] ToBytes()
    {
        return _data.Length == 0
            ? [Cla, Ins, P1, P2, 0x00]
            : [Cla, Ins, P1, P2, (byte)_data.Length, .. _data, 0x00];
    }

    /// <summary>
    /// Returns a string representation of the command.
    /// </summary>
    /// <returns>"GET DATA"</returns>
    public override string ToString()
    {
        return "GET DATA";
    }
}

/// <summary>
/// Represents the response to a GET DATA command.
/// </summary>
[PublicAPI]
public class GetDataResponse
{
    /// <summary>
    /// Gets the data object identifier that was requested.
    /// </summary>
    public ushort DataObjectIdentifier { get; }

    /// <summary>
    /// Gets the retrieved data.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the parsed TLV object if the response is in TLV format.
    /// </summary>
    public Maybe<TlvObject> TlvObject { get; }

    /// <summary>
    /// Gets a value indicating whether the response is in TLV format.
    /// </summary>
    public bool IsTlvFormat
    {
        get { return TlvObject.HasValue; }
    }

    /// <summary>
    /// Initializes a new instance of the GetDataResponse class.
    /// </summary>
    /// <param name="dataObjectIdentifier">The data object identifier.</param>
    /// <param name="data">The retrieved data.</param>
    /// <param name="tlvObject">The parsed TLV object (optional).</param>
    public GetDataResponse(
        ushort dataObjectIdentifier,
        byte[] data,
        Maybe<TlvObject> tlvObject = default
    )
    {
        DataObjectIdentifier = dataObjectIdentifier;
        Data = (byte[])data.Clone();
        TlvObject = tlvObject;
    }

    /// <summary>
    /// Parses a GET DATA response.
    /// </summary>
    /// <param name="dataObjectIdentifier">The data object identifier that was requested.</param>
    /// <param name="response">The response data (excluding status word).</param>
    /// <returns>A Result containing the parsed response or an error.</returns>
    public static Result<GetDataResponse, SmartCardError> Parse(
        ushort dataObjectIdentifier,
        byte[] response
    )
    {
        return Maybe<byte[]>
            .From(response)
            .Match(
                Some: responseValue => ParseValidResponse(dataObjectIdentifier, responseValue),
                None: () =>
                    Result.Failure<GetDataResponse, SmartCardError>(
                        SmartCardError.InvalidArgument("Response data cannot be null")
                    )
            );
    }

    /// <summary>
    /// Parses a valid response into a GetDataResponse.
    /// </summary>
    /// <param name="dataObjectIdentifier">The data object identifier.</param>
    /// <param name="response">The validated response data.</param>
    /// <returns>A Result containing the parsed response or an error.</returns>
    private static Result<GetDataResponse, SmartCardError> ParseValidResponse(
        ushort dataObjectIdentifier,
        byte[] response
    )
    {
        return TlvParser
            .Parse([.. response])
            .Match(
                tlvObject =>
                    Result.Success<GetDataResponse, SmartCardError>(
                        new GetDataResponse(
                            dataObjectIdentifier,
                            response,
                            Maybe<TlvObject>.From(tlvObject)
                        )
                    ),
                error =>
                    Result.Failure<GetDataResponse, SmartCardError>(
                        SmartCardError.InvalidResponse("Failed to parse GET DATA response as TLV")
                    )
            );
    }

    /// <summary>
    /// Parses the response as CPLC data.
    /// </summary>
    /// <returns>Parsed CPLC data or None if not applicable.</returns>
    public Maybe<CplcData> ParseAsCplc()
    {
        if (DataObjectIdentifier != GetDataCommand.DataObjects.CardProductionLifeCycle)
        {
            return Maybe<CplcData>.None;
        }

        // CPLC data can be in raw format or TLV format
        byte[] dataToparse =
            IsTlvFormat && TlvObject.HasValue
                ? TlvObject.Match(tlv => tlv.TlvData.Bytes.ToArray(), () => Data)
                : Data;

        if (dataToparse.Length < 42)
        {
            return Maybe<CplcData>.None;
        }

        return CplcData
            .Parse(dataToparse)
            .Match(success => Maybe<CplcData>.From(success), failure => Maybe<CplcData>.None);
    }

    /// <summary>
    /// Parses the response as Card Data.
    /// </summary>
    /// <returns>Parsed card data or None if not applicable.</returns>
    public Maybe<CardDataInfo> ParseAsCardData()
    {
        if (DataObjectIdentifier != GetDataCommand.DataObjects.CardData)
        {
            return Maybe<CardDataInfo>.None;
        }

        byte[] dataToparse =
            IsTlvFormat && TlvObject.HasValue
                ? TlvObject.Match(tlv => tlv.TlvData.Bytes.ToArray(), () => Data)
                : Data;

        return Maybe<byte[]>
            .From(dataToparse)
            .Where(data => data.Length > 0)
            .Match(
                Some: validData =>
                    CardDataInfo
                        .Parse(validData)
                        .Match(
                            success => Maybe<CardDataInfo>.From(success),
                            failure => Maybe<CardDataInfo>.None
                        ),
                None: () => Maybe<CardDataInfo>.None
            );
    }

    /// <summary>
    /// Parses the response as Card Capabilities (tag 0x67 format).
    /// </summary>
    /// <returns>Parsed card capabilities or null if not applicable.</returns>
    public Maybe<CardCapabilities> ParseAsCardCapabilities()
    {
        if (DataObjectIdentifier != GetDataCommand.DataObjects.CardCapabilities)
        {
            return Maybe<CardCapabilities>.None;
        }

        byte[] dataToparse =
            IsTlvFormat && TlvObject.HasValue
                ? TlvObject.Match(tlv => tlv.TlvData.Bytes.ToArray(), () => Data)
                : Data;

        return Maybe<byte[]>
            .From(dataToparse)
            .Where(data => data.Length > 0)
            .Bind(validData =>
                CardCapabilities
                    .TryParse(Maybe<byte[]>.From(validData))
                    .Match(
                        onSuccess: caps => Maybe<CardCapabilities>.From(caps),
                        onFailure: error => Maybe<CardCapabilities>.None
                    )
            );
    }

    /// <summary>
    /// Gets the value as a hex string.
    /// </summary>
    /// <returns>The value formatted as a hex string.</returns>
    public string GetValueAsHexString()
    {
        byte[] dataToUse =
            IsTlvFormat && TlvObject.HasValue
                ? TlvObject.Match(tlv => tlv.TlvData.Bytes.ToArray(), () => Data)
                : Data;
        return Maybe<byte[]>
            .From(dataToUse)
            .Match(Some: data => Convert.ToHexString(data), None: () => string.Empty);
    }

    /// <summary>
    /// Gets the value as a numeric value (for counters, etc).
    /// </summary>
    /// <returns>The numeric value or None if not applicable.</returns>
    public Maybe<uint> GetValueAsNumber()
    {
        byte[] dataToUse =
            IsTlvFormat && TlvObject.HasValue
                ? TlvObject.Match(tlv => tlv.TlvData.Bytes.ToArray(), () => Data)
                : Data;

        return Maybe<byte[]>
            .From(dataToUse)
            .Where(data => data.Length is > 0 and <= 4)
            .Map(ConvertToNumber);
    }

    /// <summary>
    /// Converts byte array to numeric value.
    /// </summary>
    /// <param name="data">The byte array to convert.</param>
    /// <returns>The numeric value.</returns>
    private static uint ConvertToNumber(byte[] data)
    {
        return data.Aggregate(0u, (acc, b) => acc << 8 | b);
    }

    /// <summary>
    /// Parses the response as Key Information Template.
    /// </summary>
    /// <returns>Parsed key information or None if not applicable.</returns>
    public Maybe<KeyInformationTemplate> ParseAsKeyInformation()
    {
        if (DataObjectIdentifier != GetDataCommand.DataObjects.KeyInformationTemplate)
        {
            return Maybe<KeyInformationTemplate>.None;
        }

        byte[] dataToparse =
            IsTlvFormat && TlvObject.HasValue
                ? TlvObject.Match(tlv => tlv.TlvData.Bytes.ToArray(), () => Data)
                : Data;

        return Maybe<byte[]>
            .From(dataToparse)
            .Where(data => data.Length > 0)
            .Bind(validData =>
                KeyInformationTemplate
                    .Parse(validData)
                    .Match(
                        success => Maybe<KeyInformationTemplate>.From(success),
                        failure => Maybe<KeyInformationTemplate>.None
                    )
            );
    }
}
