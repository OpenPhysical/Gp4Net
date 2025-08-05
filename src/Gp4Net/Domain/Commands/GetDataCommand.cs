using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the GET DATA command for retrieving data objects from the card.
/// </summary>
[PublicAPI]
public class GetDataCommand : IApduCommand
{
    /// <summary>
    /// The command class byte.
    /// </summary>
    public const byte Cla = 0x80;

    /// <summary>
    /// The command instruction byte.
    /// </summary>
    public const byte Ins = 0xCA;

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
        /// </summary>
        public static readonly ushort SequenceCounterDefaultKeyVersion = 0x00C1;

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
        /// Application Production Life Cycle Data (tag 0x009F70).
        /// </summary>
        public static readonly uint ApplicationProductionLifeCycleData = 0x009F70;

        /// <summary>
        /// Maximum number of APDU bytes (tag 0x009F65).
        /// </summary>
        public static readonly uint MaximumApduBytes = 0x009F65;

        /// <summary>
        /// Extended Card Resources Information (tag 0x00FF21).
        /// </summary>
        public static readonly uint ExtendedCardResourcesInformation = 0x00FF21;
    }

    /// <summary>
    /// Gets the data object identifier.
    /// </summary>
    public ushort DataObjectIdentifier { get; }

    /// <summary>
    /// Gets the P1 parameter (high byte of data object identifier).
    /// </summary>
    public byte P1 => (byte)(DataObjectIdentifier >> 8);

    /// <summary>
    /// Gets the P2 parameter (low byte of data object identifier).
    /// </summary>
    public byte P2 => (byte)(DataObjectIdentifier & 0xFF);

    /// <summary>
    /// Initializes a new instance of the GetDataCommand class.
    /// </summary>
    /// <param name="dataObjectIdentifier">The data object identifier (2 bytes).</param>
    private GetDataCommand(ushort dataObjectIdentifier)
    {
        DataObjectIdentifier = dataObjectIdentifier;
    }

    /// <summary>
    /// Creates a GET DATA command for a 2-byte data object identifier.
    /// </summary>
    /// <param name="dataObject">The data object identifier (2 bytes).</param>
    /// <returns>A Result containing the command or an error.</returns>
    public static Result<GetDataCommand, SmartCardError> Create(ushort dataObject)
    {
        return Result.Success<GetDataCommand, SmartCardError>(new GetDataCommand(dataObject));
    }

    /// <summary>
    /// Creates a GET DATA command for a 3-byte data object identifier.
    /// </summary>
    /// <param name="identifier">The 3-byte data object identifier.</param>
    /// <returns>A Result containing the command or an error.</returns>
    public static Result<GetDataCommand, SmartCardError> CreateFor3ByteIdentifier(byte[] identifier)
    {
        if (identifier == null)
        {
            return Result.Failure<GetDataCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Identifier cannot be null")
            );
        }

        if (identifier.Length != 3)
        {
            return Result.Failure<GetDataCommand, SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Identifier must be exactly 3 bytes, but was {identifier.Length} bytes"
                )
            );
        }

        // For 3-byte identifiers, we use the first two bytes as the identifier
        // This is a simplified approach - full implementation would handle 3-byte tags properly
        var twoByteIdentifier = (ushort)((identifier[0] << 8) | identifier[1]);
        return Result.Success<GetDataCommand, SmartCardError>(new GetDataCommand(twoByteIdentifier));
    }

    /// <summary>
    /// Converts this command to an APDU byte array.
    /// </summary>
    /// <returns>The APDU command bytes.</returns>
    public byte[] ToApdu()
    {
        return new byte[]
        {
            Cla,
            Ins,
            P1,
            P2,
            0x00, // Le (expecting response)
        };
    }

    // IApduCommand implementation
    byte IApduCommand.Cla => Cla;
    byte IApduCommand.Ins => Ins;
    byte IApduCommand.P1 => P1;
    byte IApduCommand.P2 => P2;
    byte[]? IApduCommand.Data => null;
    int? IApduCommand.ExpectedResponseLength => 256;
    bool IApduCommand.IsExtendedLength => false;

    /// <summary>
    /// Returns a string representation of the command.
    /// </summary>
    /// <returns>"GET DATA"</returns>
    public override string ToString() => "GET DATA";
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
    public bool IsTlvFormat => TlvObject.HasValue;

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
    public static Result<GetDataResponse, SmartCardError> Parse(ushort dataObjectIdentifier, byte[] response)
    {
        if (response == null)
        {
            return Result.Failure<GetDataResponse, SmartCardError>(
                SmartCardError.InvalidArgument("Response data cannot be null")
            );
        }

        try
        {
            // Try to parse as TLV
            var tlvObject = TlvParser.ParseSingle(response);
            var parsedResponse = new GetDataResponse(dataObjectIdentifier, response, tlvObject);
            return Result.Success<GetDataResponse, SmartCardError>(parsedResponse);
        }
        catch (Exception ex)
        {
            return Result.Failure<GetDataResponse, SmartCardError>(
                SmartCardError.InvalidResponse($"Failed to parse GET DATA response: {ex.Message}")
            );
        }
    }

    /// <summary>
    /// Parses the response as CPLC data.
    /// </summary>
    /// <returns>Parsed CPLC data or null if not applicable.</returns>
    public CplcData? ParseAsCplc()
    {
        if (DataObjectIdentifier != GetDataCommand.DataObjects.CardProductionLifeCycle)
        {
            return null;
        }

        // CPLC data can be in raw format or TLV format
        var dataToparse = IsTlvFormat && TlvObject.HasValue ? TlvObject.Value.Value : Data;

        if (dataToparse.Length < 42)
        {
            return null;
        }

        try
        {
            return CplcData.Parse(dataToparse);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parses the response as Card Data.
    /// </summary>
    /// <returns>Parsed card data or null if not applicable.</returns>
    public CardDataInfo? ParseAsCardData()
    {
        if (DataObjectIdentifier != GetDataCommand.DataObjects.CardData)
        {
            return null;
        }

        var dataToparse = IsTlvFormat && TlvObject.HasValue ? TlvObject.Value.Value : Data;

        if (dataToparse == null || dataToparse.Length == 0)
        {
            return null;
        }

        try
        {
            return CardDataInfo.Parse(dataToparse);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parses the response as Card Capabilities (tag 0x67 format).
    /// </summary>
    /// <returns>Parsed card capabilities or null if not applicable.</returns>
    public CardCapabilities? ParseAsCardCapabilities()
    {
        if (DataObjectIdentifier != GetDataCommand.DataObjects.CardCapabilities)
        {
            return null;
        }

        var dataToparse = IsTlvFormat && TlvObject.HasValue ? TlvObject.Value.Value : Data;

        if (dataToparse == null || dataToparse.Length == 0)
        {
            return null;
        }

        try
        {
            return CardCapabilities.Parse(dataToparse);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Gets the value as a hex string.
    /// </summary>
    /// <returns>The value formatted as a hex string.</returns>
    public string GetValueAsHexString()
    {
        var dataToUse = IsTlvFormat && TlvObject.HasValue ? TlvObject.Value.Value : Data;
        return dataToUse != null
            ? Convert.ToHexString(dataToUse)
            : string.Empty;
    }

    /// <summary>
    /// Gets the value as a numeric value (for counters, etc).
    /// </summary>
    /// <returns>The numeric value or null if not applicable.</returns>
    public uint? GetValueAsNumber()
    {
        var dataToUse = IsTlvFormat && TlvObject.HasValue ? TlvObject.Value.Value : Data;

        if (dataToUse == null || dataToUse.Length == 0 || dataToUse.Length > 4)
        {
            return null;
        }

        uint result = 0;
        for (var i = 0; i < dataToUse.Length; i++)
        {
            result = (result << 8) | dataToUse[i];
        }

        return result;
    }

    /// <summary>
    /// Parses the response as Key Information Template.
    /// </summary>
    /// <returns>Parsed key information or null if not applicable.</returns>
    public KeyInformationTemplate? ParseAsKeyInformation()
    {
        if (DataObjectIdentifier != GetDataCommand.DataObjects.KeyInformationTemplate)
        {
            return null;
        }

        var dataToparse = IsTlvFormat && TlvObject.HasValue ? TlvObject.Value.Value : Data;

        if (dataToparse == null || dataToparse.Length == 0)
        {
            return null;
        }

        try
        {
            return KeyInformationTemplate.Parse(dataToparse);
        }
        catch
        {
            return null;
        }
    }
}