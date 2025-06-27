using System;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the GET DATA command for retrieving data objects from the card.
    /// </summary>
    [PublicAPI]
    public class GetDataCommand
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
            /// Security Domain Manager AID (tag 0x004F).
            /// </summary>
            public static readonly ushort SecurityDomainManagerAid = 0x004F;

            /// <summary>
            /// Card Production Life Cycle (tag 0x009F7F).
            /// </summary>
            public static readonly uint CardProductionLifeCycle = 0x009F7F;

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
        public GetDataCommand(ushort dataObjectIdentifier)
        {
            DataObjectIdentifier = dataObjectIdentifier;
        }

        /// <summary>
        /// Creates a GET DATA command for a 3-byte data object identifier.
        /// </summary>
        /// <param name="dataObjectIdentifier">The 3-byte data object identifier.</param>
        /// <returns>A new GetDataCommand instance.</returns>
        public static GetDataCommand CreateFor3ByteIdentifier(uint dataObjectIdentifier)
        {
            if (dataObjectIdentifier > 0xFFFFFF)
                throw new ArgumentException("Data object identifier must be 3 bytes or less.", nameof(dataObjectIdentifier));

            // For 3-byte identifiers, we use the first two bytes as the identifier
            // This is a simplified approach - full implementation would handle 3-byte tags properly
            return new GetDataCommand((ushort)(dataObjectIdentifier >> 8));
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
                0x00 // Le (expecting response)
            };
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
        /// Gets the TLV tag if the response is in TLV format.
        /// </summary>
        public byte[]? Tag { get; }

        /// <summary>
        /// Gets the TLV value if the response is in TLV format.
        /// </summary>
        public byte[]? Value { get; }

        /// <summary>
        /// Gets a value indicating whether the response is in TLV format.
        /// </summary>
        public bool IsTlvFormat => Tag != null && Value != null;

        /// <summary>
        /// Initializes a new instance of the GetDataResponse class.
        /// </summary>
        /// <param name="dataObjectIdentifier">The data object identifier.</param>
        /// <param name="data">The retrieved data.</param>
        /// <param name="tag">The TLV tag (optional).</param>
        /// <param name="value">The TLV value (optional).</param>
        public GetDataResponse(ushort dataObjectIdentifier, byte[] data, byte[]? tag = null, byte[]? value = null)
        {
            DataObjectIdentifier = dataObjectIdentifier;
            Data = (byte[])data.Clone();
            Tag = tag != null ? (byte[])tag.Clone() : null;
            Value = value != null ? (byte[])value.Clone() : null;
        }

        /// <summary>
        /// Parses a GET DATA response.
        /// </summary>
        /// <param name="dataObjectIdentifier">The data object identifier that was requested.</param>
        /// <param name="response">The response data (excluding status word).</param>
        /// <returns>The parsed response.</returns>
        public static GetDataResponse Parse(ushort dataObjectIdentifier, byte[] response)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response));

            // Try to parse as TLV if the response starts with a valid tag
            var tlvResult = TryParseTlv(response);
            if (tlvResult.HasValue)
            {
                return new GetDataResponse(
                    dataObjectIdentifier,
                    response,
                    tlvResult.Value.Tag,
                    tlvResult.Value.Value);
            }

            // Return as raw data if not TLV format
            return new GetDataResponse(dataObjectIdentifier, response);
        }

        /// <summary>
        /// Attempts to parse TLV data.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <returns>The parsed TLV or null if not valid TLV.</returns>
        private static (byte[] Tag, byte[] Value)? TryParseTlv(byte[] data)
        {
            if (data == null || data.Length < 2)
                return null;

            try
            {
                int offset = 0;

                // Parse tag
                byte[] tag;
                if ((data[0] & 0x1F) == 0x1F)
                {
                    // Multi-byte tag
                    int tagLength = 1;
                    while (offset + tagLength < data.Length && (data[offset + tagLength - 1] & 0x80) != 0)
                        tagLength++;
                    
                    if (offset + tagLength >= data.Length)
                        return null;
                    
                    tag = new byte[tagLength];
                    Array.Copy(data, offset, tag, 0, tagLength);
                    offset += tagLength;
                }
                else
                {
                    // Single-byte tag
                    tag = new byte[] { data[0] };
                    offset = 1;
                }

                if (offset >= data.Length)
                    return null;

                // Parse length
                int valueLength;
                if ((data[offset] & 0x80) == 0)
                {
                    // Short form
                    valueLength = data[offset];
                    offset++;
                }
                else
                {
                    // Long form
                    int lengthBytes = data[offset] & 0x7F;
                    if (lengthBytes == 0 || offset + lengthBytes >= data.Length)
                        return null;

                    offset++;
                    valueLength = 0;
                    for (int i = 0; i < lengthBytes; i++)
                    {
                        valueLength = (valueLength << 8) | data[offset + i];
                    }
                    offset += lengthBytes;
                }

                if (offset + valueLength != data.Length)
                    return null;

                // Parse value
                var value = new byte[valueLength];
                Array.Copy(data, offset, value, 0, valueLength);

                return (tag, value);
            }
            catch
            {
                return null;
            }
        }
    }
}