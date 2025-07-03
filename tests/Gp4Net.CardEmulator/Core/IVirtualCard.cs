using System;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Core
{
    /// <summary>
    /// Interface for a virtual smart card that can process APDU commands.
    /// </summary>
    [PublicAPI]
    public interface IVirtualCard
    {
        /// <summary>
        /// Gets the Answer to Reset (ATR) of the virtual card.
        /// </summary>
        byte[] GetAtr();

        /// <summary>
        /// Processes an APDU command and returns the response.
        /// </summary>
        /// <param name="command">The APDU command bytes.</param>
        /// <returns>The APDU response including status word.</returns>
        ApduResponse ProcessCommand(byte[] command);

        /// <summary>
        /// Resets the virtual card to its initial state.
        /// </summary>
        void Reset();

        /// <summary>
        /// Gets a value indicating whether the card is currently selected.
        /// </summary>
        bool IsSelected { get; }

        /// <summary>
        /// Gets a value indicating whether a secure channel is established.
        /// </summary>
        bool IsSecureChannelEstablished { get; }
    }

    /// <summary>
    /// Represents an APDU response with data and status word.
    /// </summary>
    [PublicAPI]
    public class ApduResponse
    {
        /// <summary>
        /// Gets the response data.
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Gets the status word.
        /// </summary>
        public ushort StatusWord { get; }

        /// <summary>
        /// Gets a value indicating whether the command was successful.
        /// </summary>
        public bool IsSuccessful => StatusWord == 0x9000;

        /// <summary>
        /// Initializes a new instance of the ApduResponse class.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="statusWord">The status word.</param>
        public ApduResponse(byte[] data, ushort statusWord)
        {
            Data = data ?? throw new ArgumentNullException(nameof(data));
            StatusWord = statusWord;
        }

        /// <summary>
        /// Creates a successful response with data.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <returns>A successful APDU response.</returns>
        public static ApduResponse Success(byte[] data = null)
        {
            return new ApduResponse(data ?? Array.Empty<byte>(), 0x9000);
        }

        /// <summary>
        /// Creates an error response with the specified status word.
        /// </summary>
        /// <param name="statusWord">The error status word.</param>
        /// <returns>An error APDU response.</returns>
        public static ApduResponse Error(ushort statusWord)
        {
            return new ApduResponse(Array.Empty<byte>(), statusWord);
        }

        /// <summary>
        /// Converts the response to a byte array suitable for transmission.
        /// </summary>
        /// <returns>The response bytes including status word.</returns>
        public byte[] ToBytes()
        {
            var result = new byte[Data.Length + 2];
            Array.Copy(Data, 0, result, 0, Data.Length);
            result[Data.Length] = (byte)(StatusWord >> 8);
            result[Data.Length + 1] = (byte)(StatusWord & 0xFF);
            return result;
        }
    }
}
