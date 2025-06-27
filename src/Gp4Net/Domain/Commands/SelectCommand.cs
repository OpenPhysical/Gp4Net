using System;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the SELECT command for selecting applications or security domains.
    /// </summary>
    [PublicAPI]
    public class SelectCommand
    {
        /// <summary>
        /// The command class byte.
        /// </summary>
        public const byte Cla = 0x00;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte Ins = 0xA4;

        /// <summary>
        /// Selection control values for P1.
        /// </summary>
        public enum SelectionControl : byte
        {
            /// <summary>
            /// Select by name (AID).
            /// </summary>
            SelectByName = 0x04
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
            NoResponseData = 0x0C
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
        /// <param name="aid">The application identifier to select (5-16 bytes).</param>
        /// <param name="control">The selection control method.</param>
        /// <param name="controlInfo">The file control information.</param>
        public SelectCommand(byte[] aid, SelectionControl control = SelectionControl.SelectByName, FileControlInfo controlInfo = FileControlInfo.ReturnFci)
        {
            if (aid == null)
                throw new ArgumentNullException(nameof(aid));
            if (aid.Length < 5 || aid.Length > 16)
                throw new ArgumentException("AID must be between 5 and 16 bytes.", nameof(aid));

            Aid = (byte[])aid.Clone();
            Control = control;
            ControlInfo = controlInfo;
        }

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            var apdu = new byte[5 + Aid.Length];

            apdu[0] = Cla;
            apdu[1] = Ins;
            apdu[2] = (byte)Control;
            apdu[3] = (byte)ControlInfo;
            apdu[4] = (byte)Aid.Length;

            Array.Copy(Aid, 0, apdu, 5, Aid.Length);

            return apdu;
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
        public byte[]? ApplicationAid { get; }

        /// <summary>
        /// Gets the application label.
        /// </summary>
        public string? ApplicationLabel { get; }

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
        public byte[]? IssuerIdentificationNumber { get; }

        /// <summary>
        /// Gets the card image number.
        /// </summary>
        public byte[]? CardImageNumber { get; }

        /// <summary>
        /// Gets the card data.
        /// </summary>
        public byte[]? CardData { get; }

        /// <summary>
        /// Gets the discretionary data.
        /// </summary>
        public byte[]? DiscretionaryData { get; }

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
            byte[]? applicationAid = null,
            string? applicationLabel = null,
            byte? applicationPriorityIndicator = null,
            ushort? maxCommandDataLength = null,
            ushort? maxResponseDataLength = null,
            byte[]? issuerIdentificationNumber = null,
            byte[]? cardImageNumber = null,
            byte[]? cardData = null,
            byte[]? discretionaryData = null)
        {
            ApplicationAid = applicationAid != null ? (byte[])applicationAid.Clone() : null;
            ApplicationLabel = applicationLabel;
            ApplicationPriorityIndicator = applicationPriorityIndicator;
            MaxCommandDataLength = maxCommandDataLength;
            MaxResponseDataLength = maxResponseDataLength;
            IssuerIdentificationNumber = issuerIdentificationNumber != null ? (byte[])issuerIdentificationNumber.Clone() : null;
            CardImageNumber = cardImageNumber != null ? (byte[])cardImageNumber.Clone() : null;
            CardData = cardData != null ? (byte[])cardData.Clone() : null;
            DiscretionaryData = discretionaryData != null ? (byte[])discretionaryData.Clone() : null;
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
        public FileControlInformation? Fci { get; }

        /// <summary>
        /// Gets the raw response data.
        /// </summary>
        public byte[] RawData { get; }

        /// <summary>
        /// Initializes a new instance of the SelectResponse class.
        /// </summary>
        /// <param name="rawData">The raw response data.</param>
        /// <param name="fci">The parsed FCI (optional).</param>
        public SelectResponse(byte[] rawData, FileControlInformation? fci = null)
        {
            RawData = (byte[])rawData.Clone();
            Fci = fci;
        }

        /// <summary>
        /// Parses a SELECT response.
        /// </summary>
        /// <param name="response">The response data (excluding status word).</param>
        /// <returns>The parsed response.</returns>
        public static SelectResponse Parse(byte[] response)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response));

            // For now, return basic response without detailed FCI parsing
            // Full TLV parsing would be more complex and requires additional TLV utilities
            return new SelectResponse(response);
        }

        /// <summary>
        /// Parses a SELECT response with detailed FCI parsing.
        /// </summary>
        /// <param name="response">The response data (excluding status word).</param>
        /// <returns>The parsed response with FCI details.</returns>
        public static SelectResponse ParseWithFci(byte[] response)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response));

            var fci = ParseFciData(response);
            return new SelectResponse(response, fci);
        }

        /// <summary>
        /// Parses FCI data from response.
        /// This is a simplified parser that handles basic TLV structure.
        /// </summary>
        /// <param name="data">The FCI data.</param>
        /// <returns>The parsed FCI.</returns>
        private static FileControlInformation? ParseFciData(byte[] data)
        {
            if (data == null || data.Length == 0)
                return null;

            // This is a simplified FCI parser
            // A full implementation would need complete TLV parsing
            try
            {
                // Basic parsing for demonstration
                // Real implementation would handle all TLV tags properly
                
                byte[]? applicationAid = null;
                string? applicationLabel = null;
                
                // Look for common tags (simplified approach)
                for (int i = 0; i < data.Length - 1; i++)
                {
                    byte tag = data[i];
                    byte length = data[i + 1];
                    
                    if (i + 2 + length > data.Length)
                        break;
                    
                    switch (tag)
                    {
                        case 0x4F: // Application AID
                            applicationAid = new byte[length];
                            Array.Copy(data, i + 2, applicationAid, 0, length);
                            break;
                        case 0x50: // Application Label
                            applicationLabel = System.Text.Encoding.UTF8.GetString(data, i + 2, length);
                            break;
                    }
                    
                    i += 1 + length;
                }
                
                return new FileControlInformation(
                    applicationAid: applicationAid,
                    applicationLabel: applicationLabel);
            }
            catch
            {
                // If parsing fails, return null
                return null;
            }
        }
    }
}