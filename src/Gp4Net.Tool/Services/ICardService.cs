using System;
using System.Collections.Generic;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Interface for smart card communication services.
    /// </summary>
    [PublicAPI]
    public interface ICardService : IDisposable
    {
        /// <summary>
        /// Gets the available card readers.
        /// </summary>
        IReadOnlyList<string> GetReaders();

        /// <summary>
        /// Connects to a card in the specified reader.
        /// </summary>
        /// <param name="readerName">The reader name.</param>
        /// <returns>True if connection was successful.</returns>
        bool Connect(string readerName);

        /// <summary>
        /// Disconnects from the current card.
        /// </summary>
        void Disconnect();

        /// <summary>
        /// Gets a value indicating whether a card is connected.
        /// </summary>
        bool IsConnected { get; }

        /// <summary>
        /// Gets the ATR of the connected card.
        /// </summary>
        byte[]? GetAtr();

        /// <summary>
        /// Sends an APDU command to the card.
        /// </summary>
        /// <param name="command">The APDU command bytes.</param>
        /// <returns>The response from the card.</returns>
        CardResponse SendCommand(byte[] command);

        /// <summary>
        /// Establishes a secure channel with the card.
        /// </summary>
        /// <param name="keySet">The key set to use for authentication.</param>
        /// <param name="securityLevel">The security level to establish.</param>
        /// <returns>True if secure channel was established successfully.</returns>
        bool EstablishSecureChannel(byte[] keySet, byte securityLevel);

        /// <summary>
        /// Gets a value indicating whether a secure channel is established.
        /// </summary>
        bool IsSecureChannelEstablished { get; }
    }

    /// <summary>
    /// Represents a response from a smart card.
    /// </summary>
    [PublicAPI]
    public class CardResponse
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
        /// Initializes a new instance of the CardResponse class.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="statusWord">The status word.</param>
        public CardResponse(byte[] data, ushort statusWord)
        {
            Data = data ?? throw new ArgumentNullException(nameof(data));
            StatusWord = statusWord;
        }
    }
}